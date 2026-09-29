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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageIdentifier {
    pub vendor_id: u32,
    pub name: String,
}

impl ImageIdentifier {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.name.len());
        v.extend_from_slice(&self.vendor_id.to_be_bytes());
        v.extend_from_slice(self.name.as_bytes());
        v
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < 5 {
            return Err(anyhow!("Image Identifier too short"));
        }
        let vendor_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let name = String::from_utf8(body[4..].to_vec())?;
        Ok(ImageIdentifier { vendor_id, name })
    }
}

/// Image Information element (tag 26): file size (4) + 16-byte MD5 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub file_size: u32,
    pub hash: [u8; 16],
}

impl ImageInfo {
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
}

impl FirmwareUpgrade {
    pub fn new() -> Self {
        FirmwareUpgrade {
            state: UpgradeState::Idle,
            session: None,
            inflight: None,
        }
    }

    pub fn begin(&mut self, image: Vec<u8>, block_size: usize) {
        let mut sess = ImageSession::new(image, block_size);
        self.inflight = sess.next_block();
        self.session = Some(sess);
        self.state = UpgradeState::Downloading;
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

    pub(crate) fn abort(&mut self) {
        self.session = None;
        self.inflight = None;
        self.state = UpgradeState::Idle;
    }
}

/// A catalogued firmware image, stored on disk under the AC's firmware root
/// as `{vendor}/{model}/{hw_version}/{file_name}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareImage {
    pub id: i64,
    pub vendor: String,
    pub model: String,
    pub hw_version: String,
    pub file_name: String,
    pub size: u64,
    pub hash: [u8; 16],
    pub stored_path: String,
    pub uploaded_at: u64,
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

    /// Persist an upload: compute MD5, write the image file under the firmware
    /// root, and upsert the catalog row (keyed by vendor/model/hw_version/file).
    pub fn save_image(
        &self,
        vendor: &str,
        model: &str,
        hw_version: &str,
        file_name: &str,
        data: &[u8],
    ) -> Result<FirmwareImage> {
        let hash = md5_of(data);
        let stored_path = format!("{vendor}/{model}/{hw_version}/{file_name}");
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
                    "UPDATE firmware_images SET size=?2, hash=?3, stored_path=?4, uploaded_at=?5
                     WHERE id=?1",
                    params![rid, data.len() as i64, &hash[..], stored_path, now],
                )?;
                rid
            }
            None => {
                conn.execute(
                    "INSERT INTO firmware_images (vendor,model,hw_version,file_name,size,hash,stored_path,uploaded_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![vendor, model, hw_version, file_name, data.len() as i64, &hash[..], stored_path, now],
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
            "SELECT id,vendor,model,hw_version,file_name,size,hash,stored_path,uploaded_at
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
                "SELECT id,vendor,model,hw_version,file_name,size,hash,stored_path,uploaded_at
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
    let hash: Vec<u8> = r.get(6)?;
    let mut h = [0u8; 16];
    if hash.len() == 16 {
        h.copy_from_slice(&hash);
    }
    Ok(FirmwareImage {
        id: r.get(0)?,
        vendor: r.get(1)?,
        model: r.get(2)?,
        hw_version: r.get(3)?,
        file_name: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        hash: h,
        stored_path: r.get(7)?,
        uploaded_at: r.get::<_, i64>(8)? as u64,
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
    Start { image: Vec<u8> },
}

/// Registry mapping a WTP MAC to its live session's command channel, letting
/// the web/API layer trigger a firmware download into the running CAPWAP flow.
pub struct UpgradeRegistry {
    inner: std::sync::Mutex<std::collections::HashMap<Mac, Sender<UpgradeCmd>>>,
}

impl UpgradeRegistry {
    pub fn new() -> Self {
        UpgradeRegistry {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
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
            name: "ac-fw-2.1".to_string(),
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
        u.begin((0..4u8).collect(), 2); // two blocks of 2 bytes
        assert_eq!(u.state, UpgradeState::Downloading);

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

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn upgrade_registry_trigger() {
        use tokio::sync::mpsc;

        let mac = [1, 2, 3, 4, 5, 6];
        let reg = UpgradeRegistry::new();
        assert!(!reg.trigger(mac, UpgradeCmd::Start { image: vec![] })); // no live session

        let (tx, mut rx) = mpsc::channel(1);
        reg.register(mac, tx);
        assert!(reg.is_active(mac));
        assert!(reg.trigger(
            mac,
            UpgradeCmd::Start {
                image: vec![1, 2, 3]
            }
        ));
        match rx.blocking_recv() {
            Some(UpgradeCmd::Start { image }) => assert_eq!(image, vec![1, 2, 3]),
            _ => panic!("expected Start command"),
        }
    }
}
