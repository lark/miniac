//! Firmware upgrade orchestration (RFC 5415 section 9.1).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Provides image element codecs, the AC-side fragmentation session that splits
//! an image into sequential Image Data elements, and the download/apply state
//! machine. The image hash is supplied by the caller (MD5 per RFC 5415); no
//! digest dependency is pulled in here.

#![allow(dead_code)] // firmware session; wired into image/report handling

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use md5::{Digest, Md5};
use rusqlite::{params, OptionalExtension};
use tokio::sync::mpsc::Sender;

use crate::db::Db;
use crate::device::Mac;

const MAX_BLOCK_CAP: usize = 1024;

/// Image Data "Data Type" octet (RFC 5415 4.6.26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageDataType {
    Include = 1,
    Eof = 2,
    Abort = 5,
}

/// A single Image Data element (tag 24): a data type octet plus up to 1024
/// image bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDataBlock {
    pub data_type: ImageDataType,
    pub data: Vec<u8>,
}

impl ImageDataBlock {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + self.data.len());
        v.push(self.data_type as u8);
        v.extend_from_slice(&self.data);
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.is_empty() {
            return Err(anyhow!("Image Data element empty"));
        }
        let data_type = match body[0] {
            1 => ImageDataType::Include,
            2 => ImageDataType::Eof,
            5 => ImageDataType::Abort,
            other => return Err(anyhow!("unknown Image Data type {}", other)),
        };
        Ok(ImageDataBlock {
            data_type,
            data: body[1..].to_vec(),
        })
    }
}

/// Image Identifier element (tag 25): IANA enterprise vendor id + image name.
///
/// The payload after the vendor id is vendor-defined: RFC uses a UTF-8 name,
/// while TP-Link AC100 sends a 14-byte binary version (see
/// [`crate::vendor::tplink::image_version`]), so it is kept as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageIdentifier {
    pub vendor_id: u32,
    pub name: Vec<u8>,
}

impl ImageIdentifier {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.name.len());
        v.extend_from_slice(&self.vendor_id.to_be_bytes());
        v.extend_from_slice(&self.name);
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(anyhow!("Image Identifier too short"));
        }
        let vendor_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        Ok(ImageIdentifier {
            vendor_id,
            name: body[4..].to_vec(),
        })
    }
}

/// Image Information element (tag 26): file size (4) + 16-byte MD5 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub file_size: u32,
    pub hash: [u8; 16],
}

impl ImageInfo {
    /// Size and MD5 of the whole image, as advertised to the WTP in an
    /// Image Data Response (RFC 5415 9.1).
    pub fn of(image: &[u8]) -> Self {
        ImageInfo {
            file_size: image.len() as u32,
            hash: md5_of(image),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.extend_from_slice(&self.file_size.to_be_bytes());
        v.extend_from_slice(&self.hash);
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() != 20 {
            return Err(anyhow!("Image Info must be 20 bytes"));
        }
        let file_size = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&body[4..20]);
        Ok(ImageInfo { file_size, hash })
    }
}

/// AC-side fragmenter over a firmware image. Yields sequential Image Data
/// blocks; the last block is flagged EOF so the WTP knows transfer completed.
#[derive(Debug, Clone)]
pub struct ImageSession {
    pub image: Vec<u8>,
    pub block_size: usize,
    offset: usize,
}

impl ImageSession {
    pub fn new(image: Vec<u8>, block_size: usize) -> Self {
        let block_size = block_size.clamp(1, MAX_BLOCK_CAP);
        ImageSession {
            image,
            block_size,
            offset: 0,
        }
    }

    /// Produce the next block, or `None` once the image is fully consumed.
    pub fn next_block(&mut self) -> Option<ImageDataBlock> {
        if self.offset >= self.image.len() {
            return None;
        }
        let end = (self.offset + self.block_size).min(self.image.len());
        let data = self.image[self.offset..end].to_vec();
        self.offset = end;
        let data_type = if end == self.image.len() {
            ImageDataType::Eof
        } else {
            ImageDataType::Include
        };
        Some(ImageDataBlock { data_type, data })
    }

    pub fn is_complete(&self) -> bool {
        self.offset >= self.image.len()
    }

    /// Progress percentage (0..100) for reporting / UI.
    pub fn progress(&self) -> u8 {
        if self.image.is_empty() {
            return 100;
        }
        ((self.offset * 100) / self.image.len()).min(100) as u8
    }
}

/// Firmware download/apply state for a WTP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeState {
    Idle,
    /// Image Identifier announced to the WTP (Run-state flow); waiting for its
    /// Image Data Request / Initiate Download before sending any data.
    Announced,
    Downloading,
    AwaitReset,
    Done,
}

/// Drive the AC side of an image download against one WTP. `inflight` holds
/// the Image Data block currently being (re)transmitted; it is replaced on an
/// ACK from the WTP's Image Data Response.
#[derive(Debug, Clone)]
pub struct FirmwareUpgrade {
    pub state: UpgradeState,
    pub session: Option<ImageSession>,
    pub inflight: Option<ImageDataBlock>,
    /// Image Identifier signalled to the WTP (Configuration Update Request and,
    /// on the Run-state flow, the closing Reset Request).
    pub image_id: Option<ImageIdentifier>,
    /// Size and MD5 of the whole image, sent in the Image Data Response that
    /// answers the WTP's Initiate Download.
    pub info: Option<ImageInfo>,
    /// Sequence number of the Image Data Request currently awaiting its
    /// Response; `None` when no block is in flight.
    pub pending_seq: Option<u32>,
}

impl FirmwareUpgrade {
    pub fn new() -> Self {
        FirmwareUpgrade {
            state: UpgradeState::Idle,
            session: None,
            inflight: None,
            image_id: None,
            info: None,
            pending_seq: None,
        }
    }

    /// Announce an image without sending data yet (RFC 5415 9.1, Run state):
    /// the WTP is told the identifier in a Configuration Update Request and
    /// must answer with its own Image Data Request / Initiate Download.
    pub fn announce(&mut self, image: Vec<u8>, block_size: usize, image_id: ImageIdentifier) {
        self.info = Some(ImageInfo::of(&image));
        self.image_id = Some(image_id);
        self.session = Some(ImageSession::new(image, block_size));
        self.inflight = None;
        self.state = UpgradeState::Announced;
    }

    /// Start the transfer once the WTP initiated the download.
    pub fn start_download(&mut self) {
        if self.session.is_none() {
            return;
        }
        self.inflight = self.session.as_mut().and_then(|s| s.next_block());
        self.state = UpgradeState::Downloading;
    }

    /// Announce and immediately start (boot-time Image Data state, where the
    /// WTP has already sent Image Identifier / Initiate Download).
    pub fn begin(&mut self, image: Vec<u8>, block_size: usize, image_id: ImageIdentifier) {
        self.announce(image, block_size, image_id);
        self.start_download();
    }

    /// The block to transmit now (or `None` when nothing is pending).
    pub fn current(&self) -> Option<&ImageDataBlock> {
        self.inflight.as_ref()
    }

    /// Advance after the WTP acknowledged the in-flight block. Passing the EOF
    /// block moves the upgrade to `AwaitReset` in preparation for the reset.
    pub fn complete_block(&mut self) {
        let last = self.inflight.take();
        let was_eof = matches!(last.as_ref().map(|b| b.data_type), Some(ImageDataType::Eof));
        if was_eof {
            self.state = UpgradeState::AwaitReset;
            return;
        }
        self.inflight = self.session.as_mut().and_then(|s| s.next_block());
    }

    pub fn reset_sent(&mut self) {
        self.state = UpgradeState::Done;
    }

    /// Close a completed transfer the AC does not reset itself: in the
    /// boot-time Image Data state the WTP enters Reset on its own.
    pub fn finish(&mut self) {
        self.inflight = None;
        self.pending_seq = None;
        self.state = UpgradeState::Done;
    }

    pub(crate) fn abort(&mut self) {
        self.session = None;
        self.inflight = None;
        self.pending_seq = None;
        self.image_id = None;
        self.info = None;
        self.state = UpgradeState::Idle;
    }
}

/// A catalogued firmware image, stored on disk under the AC's firmware root
/// as `{vendor}/{model}/{hw_version}/{file_name}`. `hw_version` is empty when
/// the image format carries no hardware revision (H3C); such an image applies
/// to every hardware revision of its model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareImage {
    pub id: i64,
    pub vendor: String,
    pub model: String,
    pub hw_version: String,
    /// Software version recovered from the image (e.g. `SWBA1B0V100R010`).
    pub version: String,
    pub file_name: String,
    pub size: u64,
    pub hash: [u8; 16],
    pub stored_path: String,
    pub uploaded_at: u64,
}

/// Firmware container formats miniac recognizes on upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareFormat {
    /// H3C WTP image: the 8-byte `H3C_+k+f` magic followed by a fixed header
    /// whose software version string reads like `SWBA1B0V100R010` (product code,
    /// then `V` + version). The product code is the device model the WTP
    /// reports in its Join Request. A flash script and the payload follow.
    H3c,
    /// TP-Link AP images. Two containers are recognized by content, not name:
    /// the legacy one carries the software version string at 0x618
    /// (`1.0.6 Build 20200311 Rel.13347`), the cloud one a JSON header at
    /// 0x1014 with `soft-version` and `support-list` (`model:major.minor`).
    /// Legacy images name no model, so the file name
    /// `..._V<major>.<minor>_<x.y.z>_Build_<date>_Rel.<rel>.bin` remains the
    /// only source for model / hardware revision.
    TpLink,
    /// Ruijie RGOS images are RPM packages (`ed ab ee db` lead). The main RPM
    /// header carries the build manifest as plain text: `sup_list` (hardware
    /// product id), `target` (model), and `[softver] ver` (software version).
    Ruijie,
}

impl FirmwareFormat {
    /// Vendor tag used in the catalogue and on disk.
    pub fn vendor(self) -> &'static str {
        match self {
            FirmwareFormat::H3c => "h3c",
            FirmwareFormat::TpLink => "tplink",
            FirmwareFormat::Ruijie => "ruijie",
        }
    }
}

/// Metadata recovered from an uploaded image before operator overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageMeta {
    pub format: FirmwareFormat,
    pub vendor: String,
    pub model: String,
    /// Empty when the format does not encode one (H3C): applies to any
    /// hardware revision of the model.
    pub hw_version: String,
    /// Human-readable software version.
    pub version: String,
}

/// H3C image magic at offset 0.
const H3C_MAGIC: &[u8] = b"H3C_+k+f";
/// H3C header: the version string sits between 0x40 and 0x90, surrounded by
/// binary fields; the first printable run of at least 8 characters there is the
/// software version (e.g. `SWBA1B0V100R010`).
const H3C_HEADER_LEN: usize = 0x90;
const H3C_VERSION_START: usize = 0x40;

/// Ruijie RGOS RPM lead magic.
const RUIJIE_RPM_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
/// The RGOS build manifest lives inside the RPM main header, within the first
/// few KiB. Scanning that window avoids decompressing the payload.
const RUIJIE_MANIFEST_SCAN: usize = 0x1000;

/// Identify an image's format and pull vendor / model / hardware / version out
/// of it. Returns `None` when neither supported format matches (the caller can
/// still store the image with explicit metadata).
pub fn detect_image(file_name: &str, data: &[u8]) -> Option<ImageMeta> {
    if data.starts_with(&RUIJIE_RPM_MAGIC) {
        if let Some(meta) = ruijie_meta(data) {
            return Some(meta);
        }
    }
    if data.starts_with(H3C_MAGIC) {
        let version = h3c_version(data)
            .or_else(|| file_name.strip_suffix(".bin"))
            .filter(|v| v.contains('V'))?;
        let model = version.split_once('V').map(|(m, _)| m)?;
        if model.is_empty() {
            return None;
        }
        return Some(ImageMeta {
            format: FirmwareFormat::H3c,
            vendor: FirmwareFormat::H3c.vendor().to_string(),
            model: model.to_string(),
            hw_version: String::new(),
            version: version.to_string(),
        });
    }
    tplink_meta(file_name, data)
}

/// Software version string in an H3C header (see [`H3C_HEADER_LEN`]). The run
/// must contain a `V` so binary header fields are never mistaken for it.
fn h3c_version(data: &[u8]) -> Option<&str> {
    let header = data.get(..H3C_HEADER_LEN)?;
    let printable = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_');
    let mut start: Option<usize> = None;
    for (i, &b) in header.iter().enumerate().skip(H3C_VERSION_START) {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                let run = &header[s..i];
                if run.len() >= 8 && run.contains(&b'V') {
                    return std::str::from_utf8(run).ok();
                }
                start = None;
            }
            _ => {}
        }
    }
    None
}

/// Read the RGOS manifest out of an RPM main header. `target` names the model
/// (`ap120-a`), `sup_list` the hardware product id (`0x30020122`, also the
/// `rg_cfg/<id>/` directory) and `[softver] ver` the software version.
fn ruijie_meta(data: &[u8]) -> Option<ImageMeta> {
    let head = data.get(..RUIJIE_MANIFEST_SCAN.min(data.len()))?;
    let target = manifest_value(head, b"target=")?;
    Some(ImageMeta {
        format: FirmwareFormat::Ruijie,
        vendor: FirmwareFormat::Ruijie.vendor().to_string(),
        model: ruijie_model(&target),
        // RGOS `sup_list` is the hardware product id (also the `rg_cfg/<id>/`
        // directory), not a revision the WTP reports, so leaving it empty keeps
        // firmware selection working (`select_for_wtp` only compares a
        // non-empty hardware version on both sides).
        hw_version: String::new(),
        version: manifest_section_value(head, b"[softver]", b"ver=").unwrap_or_default(),
    })
}

/// First `key=value` in the manifest window, terminated by end of line, `;` or
/// NUL (the manifest shares the header with binary tag data).
fn manifest_value(head: &[u8], key: &[u8]) -> Option<String> {
    let at = head.windows(key.len()).position(|w| w == key)? + key.len();
    let rest = &head[at..];
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'\n' | b'\r' | 0 | b';'))
        .unwrap_or(rest.len());
    let value = String::from_utf8_lossy(&rest[..end]).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// `key=value` in the manifest section that follows a `[section]` marker.
fn manifest_section_value(head: &[u8], section: &[u8], key: &[u8]) -> Option<String> {
    let at = head.windows(section.len()).position(|w| w == section)? + section.len();
    manifest_value(&head[at..], key)
}

/// Map an RGOS `target` (`ap120-a`) to the model string the WTP reports in its
/// Board Data (`RG-AP120-A`).
fn ruijie_model(target: &str) -> String {
    let upper = target.trim().to_ascii_uppercase();
    if upper.starts_with("AP") {
        format!("RG-{upper}")
    } else {
        upper
    }
}

/// Legacy TP-Link container head: `00 00 01 00` + magic `55 AA 4C 5E`.
const TPLINK_HEAD_MAGIC: [u8; 8] = [0x00, 0x00, 0x01, 0x00, 0x55, 0xAA, 0x4C, 0x5E];
/// Fixed offset of the NUL-terminated software version in the legacy head,
/// e.g. `1.0.6 Build 20200311 Rel.13347`.
const TPLINK_VERSION_OFF: usize = 0x618;
/// Version runs are short; the rest of the head is a partition table.
const TPLINK_VERSION_MAX: usize = 0x40;
/// Cloud images keep a 2048-byte JSON header here; uac's
/// `apupd_image_soft_ver_get` refuses images shorter than `0x1014 + 2048`.
const TPLINK_JSON_OFF: usize = 0x1014;
const TPLINK_JSON_LEN: usize = 2048;

/// TP-Link metadata: the image contents carry the software version (and, for
/// cloud images, the supported models and their hardware revisions); the file
/// name is only a fallback and a model hint for legacy images.
fn tplink_meta(file_name: &str, data: &[u8]) -> Option<ImageMeta> {
    let named = tplink_name_meta(file_name);
    let content = tplink_content(data);
    if named.is_none() && content.is_none() {
        return None;
    }
    let mut meta = named.unwrap_or(ImageMeta {
        format: FirmwareFormat::TpLink,
        vendor: FirmwareFormat::TpLink.vendor().to_string(),
        model: String::new(),
        hw_version: String::new(),
        version: String::new(),
    });
    if let Some(content) = content {
        meta.version = content.version;
        if !content.models.is_empty() {
            // Prefer the model the file is named after; a single-entry list
            // applies to whatever the file is called.
            let chosen = content
                .models
                .iter()
                .find(|(m, _)| m.eq_ignore_ascii_case(&meta.model))
                .or_else(|| {
                    (meta.model.is_empty() || content.models.len() == 1).then(|| &content.models[0])
                });
            if let Some((model, hw_version)) = chosen {
                meta.model = model.clone();
                meta.hw_version = hw_version.clone();
            }
        }
    }
    Some(meta)
}

/// Metadata encoded in the image itself.
struct TpLinkContent {
    version: String,
    /// `(model, hardware revision)` pairs from a cloud `support-list`.
    models: Vec<(String, String)>,
}

fn tplink_content(data: &[u8]) -> Option<TpLinkContent> {
    if data.get(..TPLINK_HEAD_MAGIC.len()) == Some(TPLINK_HEAD_MAGIC.as_slice()) {
        return Some(TpLinkContent {
            version: tplink_head_version(data).unwrap_or_default(),
            models: Vec::new(),
        });
    }
    tplink_cloud_content(data)
}

/// Software version at [`TPLINK_VERSION_OFF`] in the legacy head (see
/// [`TPLINK_HEAD_MAGIC`]). The string is the image's own marker: the AP reads
/// it from the file, not from the name it arrived under.
fn tplink_head_version(data: &[u8]) -> Option<String> {
    let raw = data.get(TPLINK_VERSION_OFF..TPLINK_VERSION_OFF + TPLINK_VERSION_MAX)?;
    let end = raw.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&raw[..end]).ok()?.trim();
    let software = s.split_whitespace().next()?;
    if !version_token(software) || !s.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return None;
    }
    Some(s.to_string())
}

/// Cloud image header (see [`TPLINK_JSON_OFF`]): `soft-version` and the
/// CRLF-separated `support-list` lines `model:major.minor`.
fn tplink_cloud_content(data: &[u8]) -> Option<TpLinkContent> {
    let raw = data.get(TPLINK_JSON_OFF..TPLINK_JSON_OFF + TPLINK_JSON_LEN)?;
    let text = std::str::from_utf8(raw).ok()?;
    let start = text.find('{')?;
    let end = json_object_end(&text[start..])?;
    let json: serde_json::Value = serde_json::from_str(&text[start..start + end]).ok()?;
    let version = json.get("soft-version")?.as_str()?.trim();
    if version.is_empty() {
        return None;
    }
    let models = json
        .get("support-list")
        .and_then(|v| v.as_str())
        .map(support_list)
        .unwrap_or_default();
    Some(TpLinkContent {
        version: version.to_string(),
        models,
    })
}

/// `TL-AP1300GI-PoE:1.0\r\nTL-AP300C-PoE:2.0` → `(model, hardware revision)`
/// pairs, dropping malformed lines.
fn support_list(text: &str) -> Vec<(String, String)> {
    text.split(['\r', '\n'])
        .filter_map(|line| {
            let (model, hw) = line.split_once(':')?;
            let (model, hw) = (model.trim(), hw.trim());
            if model.is_empty() || !version_token(hw) {
                return None;
            }
            Some((model.to_string(), hw.to_string()))
        })
        .collect()
}

/// End (exclusive) of the JSON object starting at `s[0] == '{'`, skipping
/// string contents so a `}` inside a quoted value cannot truncate it.
fn json_object_end(s: &str) -> Option<usize> {
    let mut depth = 0u32;
    let mut in_string = false;
    let mut escaped = false;
    for (i, b) in s.bytes().enumerate() {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// TP-Link metadata from the file name (legacy images name no model, so this
/// is the only model source for them).
fn tplink_name_meta(file_name: &str) -> Option<ImageMeta> {
    let stem = file_name
        .strip_suffix(".bin")
        .or_else(|| file_name.strip_suffix(".BIN"))?;
    let parts: Vec<&str> = stem.split('_').collect();
    let hw_pos = parts
        .iter()
        .position(|p| p.strip_prefix('V').is_some_and(version_token))?;
    if hw_pos == 0 {
        return None;
    }
    let sw_pos = parts
        .iter()
        .enumerate()
        .skip(hw_pos + 1)
        .find(|(_, p)| version_token(p))?
        .0;
    let mut version = parts[sw_pos].to_string();
    if let Some(build) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("Build"))
        .and_then(|i| parts.get(i + 1))
    {
        version.push_str(" Build ");
        version.push_str(build);
    }
    if let Some(rel) = parts.iter().find_map(|p| p.strip_prefix("Rel.")) {
        version.push_str(" Rel ");
        version.push_str(rel);
    }
    Some(ImageMeta {
        format: FirmwareFormat::TpLink,
        vendor: FirmwareFormat::TpLink.vendor().to_string(),
        model: parts[..hw_pos].join("_"),
        hw_version: parts[hw_pos][1..].to_string(),
        version,
    })
}

/// A dotted numeric token (`2.0`, `1.0.6`, `10.0.0.1`).
fn version_token(s: &str) -> bool {
    let count = s.split('.').count();
    (2..=4).contains(&count)
        && s.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// A persisted record of a firmware upgrade run (AC audit trail).
pub struct FirmwareStore {
    db: Arc<Db>,
    root: PathBuf,
}

const DEFAULT_FW_ROOT: &str = "firmware";

impl FirmwareStore {
    pub fn new(db: Arc<Db>) -> Self {
        FirmwareStore::with_root(db, DEFAULT_FW_ROOT)
    }

    /// Configure the on-disk root directory for uploaded images.
    pub fn with_root(db: Arc<Db>, root: impl AsRef<Path>) -> Self {
        FirmwareStore {
            db,
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Absolute path to a stored image from its relative `stored_path`.
    pub fn abs_path(&self, stored_path: &str) -> PathBuf {
        self.root.join(stored_path)
    }

    pub fn record_start(&self, wmac: &[u8], image: &str, size: u32, hash: &[u8]) -> Result<i64> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO firmware_upgrades (wmac,image,size,hash,state,started_at)
             VALUES (?1,?2,?3,?4,'downloading',strftime('%s','now'))",
            params![wmac, image, size as i64, hash],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn mark_done(&self, id: i64) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "UPDATE firmware_upgrades SET state='done', finished_at=strftime('%s','now') WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<u64> {
        let conn = self.db.lock();
        let n = conn.query_row("SELECT COUNT(*) FROM firmware_upgrades", [], |r| {
            r.get::<_, i64>(0)
        })?;
        Ok(n as u64)
    }

    /// Store an upload with the metadata the caller supplies. The software
    /// version is still recovered from the image when its format is recognized.
    pub fn save_image(
        &self,
        vendor: &str,
        model: &str,
        hw_version: &str,
        file_name: &str,
        data: &[u8],
    ) -> Result<FirmwareImage> {
        let version = detect_image(file_name, data)
            .map(|m| m.version)
            .unwrap_or_default();
        self.store(vendor, model, hw_version, &version, file_name, data)
    }

    /// Store an upload, filling vendor / model / hardware from the detected
    /// format. The optional arguments are operator overrides: a non-empty value
    /// wins over detection, so an unrecognized image can still be catalogued.
    /// An image whose format is recognized but whose model cannot be derived is
    /// rejected with the supported-format list.
    pub fn save_upload(
        &self,
        file_name: &str,
        data: &[u8],
        vendor: Option<&str>,
        model: Option<&str>,
        hw_version: Option<&str>,
    ) -> Result<FirmwareImage> {
        let detected = detect_image(file_name, data);
        let pick = |given: Option<&str>, found: Option<&str>| -> String {
            match given.map(str::trim).filter(|s| !s.is_empty()) {
                Some(v) => v.to_string(),
                None => found.unwrap_or_default().to_string(),
            }
        };
        let vendor = pick(vendor, detected.as_ref().map(|m| m.vendor.as_str()));
        let model = pick(model, detected.as_ref().map(|m| m.model.as_str()));
        let hw_version = pick(hw_version, detected.as_ref().map(|m| m.hw_version.as_str()));
        if vendor.trim().is_empty() || model.trim().is_empty() {
            return Err(anyhow!(
                "unrecognized firmware '{file_name}': supported formats are h3c and tplink; \
                 fill vendor/model to store it explicitly"
            ));
        }
        let version = detected.map(|m| m.version).unwrap_or_default();
        self.store(&vendor, &model, &hw_version, &version, file_name, data)
    }

    fn store(
        &self,
        vendor: &str,
        model: &str,
        hw_version: &str,
        version: &str,
        file_name: &str,
        data: &[u8],
    ) -> Result<FirmwareImage> {
        for (label, value) in [
            ("vendor", vendor),
            ("model", model),
            ("hw_version", hw_version),
            ("file name", file_name),
        ] {
            if value.contains(['/', '\\']) || value == ".." {
                return Err(anyhow!("invalid {label} '{value}'"));
            }
        }
        let hash = md5_of(data);
        // H3C images name no hardware revision; `any` keeps the on-disk layout
        // uniform while the catalog row stays empty so the model matches every
        // revision.
        let hw_dir = if hw_version.is_empty() { "any" } else { hw_version };
        let stored_path = format!("{vendor}/{model}/{hw_dir}/{file_name}");
        let abs = self.abs_path(&stored_path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).context("create firmware dirs")?;
        }
        fs::write(&abs, data).context("write firmware image")?;

        let now = now_unix() as i64;
        let conn = self.db.lock();
        let existing = conn
            .query_row(
                "SELECT id FROM firmware_images WHERE vendor=?1 AND model=?2 AND hw_version=?3 AND file_name=?4",
                params![vendor, model, hw_version, file_name],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        let id = match existing {
            Some(rid) => {
                conn.execute(
                    "UPDATE firmware_images SET size=?2, hash=?3, stored_path=?4, uploaded_at=?5, version=?6
                     WHERE id=?1",
                    params![rid, data.len() as i64, &hash[..], stored_path, now, version],
                )?;
                rid
            }
            None => {
                conn.execute(
                    "INSERT INTO firmware_images (vendor,model,hw_version,file_name,size,hash,stored_path,uploaded_at,version)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![vendor, model, hw_version, file_name, data.len() as i64, &hash[..], stored_path, now, version],
                )?;
                conn.last_insert_rowid()
            }
        };
        drop(conn);
        Ok(self.get_image(id)?.expect("just-inserted image"))
    }

    /// All catalogued images.
    pub fn list_images(&self) -> Result<Vec<FirmwareImage>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT id,vendor,model,hw_version,version,file_name,size,hash,stored_path,uploaded_at
             FROM firmware_images ORDER BY vendor, model, hw_version",
        )?;
        let rows = stmt.query_map([], row_to_image)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Look up a single catalogued image.
    pub fn get_image(&self, id: i64) -> Result<Option<FirmwareImage>> {
        let conn = self.db.lock();
        let img = conn
            .query_row(
                "SELECT id,vendor,model,hw_version,version,file_name,size,hash,stored_path,uploaded_at
                 FROM firmware_images WHERE id=?1",
                params![id],
                row_to_image,
            )
            .optional()?;
        Ok(img)
    }

    /// Read a catalogued image's bytes from disk for delivery.
    pub fn load_image_bytes(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let img = match self.get_image(id)? {
            Some(i) => i,
            None => return Ok(None),
        };
        let abs = self.abs_path(&img.stored_path);
        Ok(Some(fs::read(&abs).with_context(|| {
            format!("read image file {}", abs.display())
        })?))
    }

    /// Select the image to serve to a WTP that asked for `requested` (the name
    /// from its Image Identifier). An exact file-name / stored-path match wins;
    /// otherwise the newest image catalogued for the device's vendor and model
    /// (and hardware version, when both sides know it) is used.
    pub fn select_for_wtp(
        &self,
        requested: &str,
        vendor: &str,
        model: &str,
        hw_version: &str,
    ) -> Result<Option<FirmwareImage>> {
        let images = self.list_images()?;
        if let Some(img) = images
            .iter()
            .find(|i| i.file_name == requested || i.stored_path == requested)
        {
            return Ok(Some(img.clone()));
        }
        if vendor.is_empty() || model.is_empty() {
            return Ok(None);
        }
        Ok(images
            .into_iter()
            .filter(|i| {
                i.vendor.eq_ignore_ascii_case(vendor)
                    && i.model.eq_ignore_ascii_case(model)
                    // An image that names no hardware revision applies to every
                    // one of its model's revisions; otherwise both sides must
                    // agree (when the device's revision is known).
                    && (i.hw_version.is_empty()
                        || hw_version.is_empty()
                        || i.hw_version.eq_ignore_ascii_case(hw_version))
            })
            .max_by_key(|i| i.uploaded_at))
    }
}

fn md5_of(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut h = [0u8; 16];
    h.copy_from_slice(&out);
    h
}

fn row_to_image(r: &rusqlite::Row) -> rusqlite::Result<FirmwareImage> {
    let hash: Vec<u8> = r.get(7)?;
    let mut h = [0u8; 16];
    if hash.len() == 16 {
        h.copy_from_slice(&hash);
    }
    Ok(FirmwareImage {
        id: r.get(0)?,
        vendor: r.get(1)?,
        model: r.get(2)?,
        hw_version: r.get(3)?,
        version: r.get(4)?,
        file_name: r.get(5)?,
        size: r.get::<_, i64>(6)? as u64,
        hash: h,
        stored_path: r.get(8)?,
        uploaded_at: r.get::<_, i64>(9)? as u64,
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Command delivered from the management plane to a live WTP session to begin
/// a firmware image download.
pub enum UpgradeCmd {
    /// Deliver `image` to the WTP under the Image Identifier `name`.
    Start {
        image: Vec<u8>,
        name: String,
        /// Catalogue software version; Ruijie announces it in the Image
        /// Identifier (type 1) so the WTP can compare it with its running one.
        version: String,
    },
}

/// Registry mapping a WTP MAC to its live session's command channel, letting
/// the web/API layer trigger a firmware download into the running CAPWAP flow.
pub struct UpgradeRegistry {
    inner: std::sync::Mutex<std::collections::HashMap<Mac, Sender<UpgradeCmd>>>,
    /// Images queued while the WTP had no live session, keyed by MAC. An H3C
    /// WTP picks one up at its next Join and is told about it in the Join
    /// Response (the M60's join-time entry for an out-of-date WTP).
    pending: std::sync::Mutex<std::collections::HashMap<Mac, i64>>,
}

impl UpgradeRegistry {
    pub fn new() -> Self {
        UpgradeRegistry {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Associate a WTP MAC with the channel its session listens on.
    pub fn register(&self, mac: Mac, tx: Sender<UpgradeCmd>) {
        self.inner.lock().unwrap().insert(mac, tx);
    }

    /// Whether a live session for this WTP is currently registered.
    pub fn is_active(&self, mac: Mac) -> bool {
        self.inner.lock().unwrap().contains_key(&mac)
    }

    /// Deliver a command to the WTP's session. Returns false when the session
    /// is absent or its channel closed (e.g. the WTP just went offline).
    pub fn trigger(&self, mac: Mac, cmd: UpgradeCmd) -> bool {
        match self.inner.lock().unwrap().get(&mac).cloned() {
            Some(tx) => tx.try_send(cmd).is_ok(),
            None => false,
        }
    }

    /// Queue an image for a WTP that is offline: its session is gone, so the
    /// upgrade is announced to it on the next Join instead.
    pub fn queue_pending(&self, mac: Mac, image_id: i64) {
        self.pending.lock().unwrap().insert(mac, image_id);
    }

    /// Take the image queued for this WTP, if any (consumed once).
    pub fn take_pending(&self, mac: Mac) -> Option<i64> {
        self.pending.lock().unwrap().remove(&mac)
    }
}

/// Persisted key for the join-time upgrade switch.
const UPDATE_ON_JOIN_KEY: &str = "firmware.update_on_join";

/// AC-wide firmware policy, editable from the system settings page.
///
/// `update_on_join` defaults to false: an AP that restarts (for example after a
/// site-wide power outage) must not be told to download an image in its Join
/// Response, otherwise every AP starts upgrading at once. With the switch off,
/// firmware is only delivered to a WTP that is already in a live session, i.e.
/// on an explicit admin action.
pub struct FirmwarePolicy {
    db: Arc<Db>,
    update_on_join: AtomicBool,
}

impl FirmwarePolicy {
    pub fn new(db: Arc<Db>) -> Result<Self> {
        let stored: Option<String> = {
            let conn = db.lock();
            conn.query_row(
                "SELECT value FROM sys_setting WHERE key=?1",
                params![UPDATE_ON_JOIN_KEY],
                |r| r.get(0),
            )
            .optional()?
        };
        Ok(FirmwarePolicy {
            db,
            update_on_join: AtomicBool::new(stored.as_deref() == Some("1")),
        })
    }

    pub fn update_on_join(&self) -> bool {
        self.update_on_join.load(Ordering::Relaxed)
    }

    pub fn set_update_on_join(&self, on: bool) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO sys_setting (key,value) VALUES (?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![UPDATE_ON_JOIN_KEY, if on { "1" } else { "0" }],
        )?;
        self.update_on_join.store(on, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_hash() -> [u8; 16] {
        [7u8; 16]
    }

    #[test]
    fn image_elements_roundtrip() {
        let blk = ImageDataBlock {
            data_type: ImageDataType::Eof,
            data: b"tail".to_vec(),
        };
        assert_eq!(ImageDataBlock::decode(&blk.encode()).unwrap(), blk);

        let id = ImageIdentifier {
            vendor_id: 1916,
            name: b"ac-fw-2.1".to_vec(),
        };
        assert_eq!(ImageIdentifier::decode(&id.encode()).unwrap(), id);

        let info = ImageInfo {
            file_size: 4096,
            hash: fixed_hash(),
        };
        assert_eq!(ImageInfo::decode(&info.encode()).unwrap(), info);
    }

    #[test]
    fn fragment_with_eof() {
        let image: Vec<u8> = (0..(3 * 1024 + 10)).map(|i| (i % 251) as u8).collect();
        let mut sess = ImageSession::new(image.clone(), 1024);
        let mut reassembled = Vec::new();
        let mut eofs = 0;
        while let Some(blk) = sess.next_block() {
            reassembled.extend_from_slice(&blk.data);
            if blk.data_type == ImageDataType::Eof {
                eofs += 1;
            }
        }
        assert_eq!(eofs, 1);
        assert_eq!(reassembled, image);
        assert!(sess.is_complete());
        assert_eq!(sess.progress(), 100);
    }

    #[test]
    fn upgrade_state_flow() {
        let mut u = FirmwareUpgrade::new();
        assert_eq!(u.state, UpgradeState::Idle);
        let id = ImageIdentifier {
            vendor_id: 0x1234_5678,
            name: b"fw.bin".to_vec(),
        };
        u.begin((0..4u8).collect(), 2, id.clone()); // two blocks of 2 bytes
        assert_eq!(u.state, UpgradeState::Downloading);
        assert_eq!(u.image_id, Some(id));
        assert_eq!(u.info.as_ref().unwrap().file_size, 4);

        let a = u.current().unwrap().clone();
        assert_eq!(a.data_type, ImageDataType::Include);
        assert_eq!(a.data.len(), 2);
        u.complete_block();

        let b = u.current().unwrap().clone();
        assert_eq!(b.data_type, ImageDataType::Eof);
        assert!((&u.state) != &UpgradeState::AwaitReset); // EOF not yet acked
        u.complete_block();

        assert!(u.current().is_none());
        assert_eq!(u.state, UpgradeState::AwaitReset);
        u.reset_sent();
        assert_eq!(u.state, UpgradeState::Done);

        // Run-state flow: announced image waits for the WTP's Initiate Download.
        let mut r = FirmwareUpgrade::new();
        r.announce(vec![1, 2, 3], 512, u.image_id.clone().unwrap());
        assert_eq!(r.state, UpgradeState::Announced);
        assert!(r.current().is_none());
        r.start_download();
        assert_eq!(r.state, UpgradeState::Downloading);
        assert!(r.current().is_some());
    }

    #[test]
    fn store_records() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let s = FirmwareStore::new(db);
        let id = s
            .record_start(&[1, 2, 3, 4, 5, 6], "ac-fw-2.1", 4096, &fixed_hash())
            .unwrap();
        assert_eq!(s.count().unwrap(), 1);
        s.mark_done(id).unwrap();
        assert_eq!(s.count().unwrap(), 1);
    }

    #[test]
    fn image_catalog_roundtrip() {
        let dir = std::env::temp_dir().join(format!("miniac-fw-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let db = Arc::new(Db::open_in_memory().unwrap());
        let s = FirmwareStore::with_root(db, &dir);

        let img = s
            .save_image("tplink", "ac100", "v3", "ac100v3-1.3.bin", b"hello world")
            .unwrap();
        assert_eq!(img.size, 11);
        assert_eq!(img.stored_path, "tplink/ac100/v3/ac100v3-1.3.bin");
        assert_eq!(s.list_images().unwrap().len(), 1);
        assert_eq!(s.load_image_bytes(img.id).unwrap().unwrap(), b"hello world");

        // Re-upload same triplet overwrites rather than duplicating.
        let again = s
            .save_image("tplink", "ac100", "v3", "ac100v3-1.3.bin", b"goodbye")
            .unwrap();
        assert_eq!(again.id, img.id);
        assert_eq!(s.list_images().unwrap().len(), 1);
        assert_eq!(s.load_image_bytes(img.id).unwrap().unwrap(), b"goodbye");

        // WTP-initiated downloads select by Image Identifier name first, then
        // fall back to the device's vendor / model / hardware version.
        let by_name = s
            .select_for_wtp("ac100v3-1.3.bin", "", "", "")
            .unwrap()
            .unwrap();
        assert_eq!(by_name.id, img.id);
        let by_device = s
            .select_for_wtp("unknown-name", "TPLink", "AC100", "v3")
            .unwrap()
            .unwrap();
        assert_eq!(by_device.id, img.id);
        assert!(s
            .select_for_wtp("unknown-name", "tplink", "other", "v3")
            .unwrap()
            .is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_h3c_image() {
        let mut data = vec![0u8; 0x200];
        data[..8].copy_from_slice(b"H3C_+k+f");
        data[0x63..0x72].copy_from_slice(b"SWBA1B0V100R010");
        let meta = detect_image("SWBA1B0V100R010.bin", &data).unwrap();
        assert_eq!(meta.format, FirmwareFormat::H3c);
        assert_eq!(meta.vendor, "h3c");
        assert_eq!(meta.model, "SWBA1B0");
        assert_eq!(meta.version, "SWBA1B0V100R010");
        assert!(meta.hw_version.is_empty()); // H3C names no hardware revision
    }

    #[test]
    fn detect_ruijie_rgos_image() {
        let mut data = vec![0xED, 0xAB, 0xEE, 0xDB];
        data.extend_from_slice(&[0u8; 0x3fc]);
        data.extend_from_slice(
            b"sup_list=0x30020122;\n\
              [rootfs]\n\
              name=rootfs.ubi\n\
              ver=1.0.0.2e5482c0\n\
              target=ap120-a\n\
              buildtime=2020/03/17 12:38:21\n\
              [softver]\n\
              ver=AP_RGOS 11.1(9)B1P25, Release(07151712)\n",
        );
        let meta = detect_image("RGOS11.1_B1P25_S1C2_install.bin", &data).unwrap();
        assert_eq!(meta.format, FirmwareFormat::Ruijie);
        assert_eq!(meta.vendor, "ruijie");
        assert_eq!(meta.model, "RG-AP120-A");
        assert!(meta.hw_version.is_empty());
        assert_eq!(meta.version, "AP_RGOS 11.1(9)B1P25, Release(07151712)");
    }

    #[test]
    fn detect_tplink_image() {
        let meta = detect_image(
            "TL-AP1300GI-PoE_V2.0_1.0.6_Build_20200311_Rel.13347.bin",
            b"x",
        )
        .unwrap();
        assert_eq!(meta.format, FirmwareFormat::TpLink);
        assert_eq!(meta.vendor, "tplink");
        assert_eq!(meta.model, "TL-AP1300GI-PoE");
        assert_eq!(meta.hw_version, "2.0");
        assert_eq!(meta.version, "1.0.6 Build 20200311 Rel 13347");
        assert!(detect_image("random-image.bin", b"x").is_none());
    }

    /// Legacy head as found in TL-AP1300GI-PoE images: magic at 0 and the
    /// software version at 0x618, no model anywhere.
    fn tplink_legacy_image() -> Vec<u8> {
        let mut data = vec![0u8; 0x800];
        data[..8].copy_from_slice(&TPLINK_HEAD_MAGIC);
        let version = b"1.0.6 Build 20200311 Rel.13347";
        data[TPLINK_VERSION_OFF..TPLINK_VERSION_OFF + version.len()].copy_from_slice(version);
        data
    }

    #[test]
    fn tplink_version_comes_from_image_not_name() {
        // A renamed image still reports the version its own header carries;
        // the model is unavailable, so the catalogue needs it from the operator.
        let meta = detect_image("renamed.bin", &tplink_legacy_image()).unwrap();
        assert_eq!(meta.format, FirmwareFormat::TpLink);
        assert_eq!(meta.version, "1.0.6 Build 20200311 Rel.13347");
        assert_eq!(meta.model, "");
        assert_eq!(meta.hw_version, "");

        // With the conventional name the model / hardware revision come from
        // it, the version still wins over the name's copy.
        let mut image = tplink_legacy_image();
        image[TPLINK_VERSION_OFF..TPLINK_VERSION_OFF + 5].copy_from_slice(b"1.0.7");
        let meta = detect_image(
            "TL-AP1300GI-PoE_V2.0_1.0.6_Build_20200311_Rel.13347.bin",
            &image,
        )
        .unwrap();
        assert_eq!(meta.model, "TL-AP1300GI-PoE");
        assert_eq!(meta.hw_version, "2.0");
        assert_eq!(meta.version, "1.0.7 Build 20200311 Rel.13347");

        // The magic alone is not enough: a printable run without a dotted
        // version prefix is not treated as a version.
        let mut junk = tplink_legacy_image();
        junk[TPLINK_VERSION_OFF..TPLINK_VERSION_OFF + 9].copy_from_slice(b"not-a-ver");
        let meta = detect_image("renamed.bin", &junk).unwrap();
        assert_eq!(meta.version, "");
    }

    #[test]
    fn tplink_cloud_image_support_list() {
        let header = r#"{"soft-version":"2.0.1",
            "support-list":"TL-AP1300GI-PoE:2.0\r\nTL-AP300C-PoE:1.0"}"#;
        let mut data = vec![0u8; TPLINK_JSON_OFF + TPLINK_JSON_LEN];
        data[TPLINK_JSON_OFF..TPLINK_JSON_OFF + header.len()].copy_from_slice(header.as_bytes());

        // Named after one of the supported models: that entry is picked.
        let meta = detect_image("TL-AP300C-PoE_V1.0_2.0.1.bin", &data).unwrap();
        assert_eq!(meta.format, FirmwareFormat::TpLink);
        assert_eq!(meta.model, "TL-AP300C-PoE");
        assert_eq!(meta.hw_version, "1.0");
        assert_eq!(meta.version, "2.0.1");

        // Unparsable name: the first supported model is used.
        let meta = detect_image("image.bin", &data).unwrap();
        assert_eq!(meta.model, "TL-AP1300GI-PoE");
        assert_eq!(meta.hw_version, "2.0");
        assert_eq!(meta.version, "2.0.1");
    }

    #[test]
    fn upload_fills_metadata_from_format() {
        let dir = std::env::temp_dir().join(format!("miniac-fw-detect-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let db = Arc::new(Db::open_in_memory().unwrap());
        let s = FirmwareStore::with_root(db, &dir);

        let mut h3c = vec![0u8; 0x200];
        h3c[..8].copy_from_slice(b"H3C_+k+f");
        h3c[0x63..0x72].copy_from_slice(b"SWBA1B0V100R010");
        let img = s
            .save_upload("SWBA1B0V100R010.bin", &h3c, None, None, None)
            .unwrap();
        assert_eq!(img.vendor, "h3c");
        assert_eq!(img.model, "SWBA1B0");
        assert_eq!(img.hw_version, ""); // applies to every revision
        assert_eq!(img.version, "SWBA1B0V100R010");
        assert_eq!(img.stored_path, "h3c/SWBA1B0/any/SWBA1B0V100R010.bin");
        let h3c_id = img.id;

        // An unknown format needs explicit metadata; overrides win over detection.
        assert!(s
            .save_upload("mystery.bin", b"junk", None, None, None)
            .is_err());
        let img = s
            .save_upload("mystery.bin", b"junk", Some("acme"), Some("x1"), Some("1.0"))
            .unwrap();
        assert_eq!(img.stored_path, "acme/x1/1.0/mystery.bin");
        assert_eq!(img.version, "");

        // The catalogued H3C image matches any hardware revision of its model.
        let picked = s
            .select_for_wtp("other.bin", "h3c", "SWBA1B0", "02020101")
            .unwrap()
            .unwrap();
        assert_eq!(picked.id, h3c_id);
        assert!(s
            .select_for_wtp("other.bin", "h3c", "OTHER", "02020101")
            .unwrap()
            .is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn upgrade_registry_trigger() {
        use tokio::sync::mpsc;

        let mac = [1, 2, 3, 4, 5, 6];
        let reg = UpgradeRegistry::new();
        assert!(!reg.trigger(
            mac,
            UpgradeCmd::Start {
                image: vec![],
                name: "fw.bin".to_string(),
                version: "1.0".to_string(),
            }
        )); // no live session

        let (tx, mut rx) = mpsc::channel(1);
        reg.register(mac, tx);
        assert!(reg.is_active(mac));
        assert!(reg.trigger(
            mac,
            UpgradeCmd::Start {
                image: vec![1, 2, 3],
                name: "fw.bin".to_string(),
                version: "1.0".to_string(),
            }
        ));
        match rx.blocking_recv() {
            Some(UpgradeCmd::Start {
                image,
                name,
                version,
            }) => {
                assert_eq!(image, vec![1, 2, 3]);
                assert_eq!(name, "fw.bin");
                assert_eq!(version, "1.0");
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn firmware_policy_defaults_off_and_persists() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let policy = FirmwarePolicy::new(db.clone()).unwrap();
        assert!(!policy.update_on_join()); // startup updates are opt-in
        policy.set_update_on_join(true).unwrap();
        assert!(policy.update_on_join());
        // A fresh instance (a restart) reads the stored value back.
        assert!(FirmwarePolicy::new(db).unwrap().update_on_join());
    }
}
