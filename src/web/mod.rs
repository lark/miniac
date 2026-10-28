//! Web management plane (M7): HTTP/REST API plus an embedded management frontend.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Exposes AP/radio/station/security/firmware views and the management event
//! stream, running alongside the CAPWAP UDP control channel. Store models keep
//! their own (MAC-as-`[u8;6]`) types; handlers map results to lightweight
//! `serde` DTOs here so no `Serialize` derive leaks into the data layer.

use std::{
    ffi::CStr,
    fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    serve::Listener,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::config::{Akm, Cipher, Pmf, SecurityPolicy, ConfigUpdateCmd, ConfigUpdateRegistry};
use crate::fleet::{ClientGroup, ProductCapsStore};
use crate::vendor::h3c::ConfigUpdateElem;
use crate::vendor::profile::VendorProfile;
use crate::device::{self, DeviceStore};
use crate::firmware::{FirmwareStore, UpgradeCmd, UpgradeRegistry};
use crate::logx;
use crate::radio::{H3cRadioHeader, RadioStore, RadioWlan};
use crate::security::ProfileStore;
use crate::settings::{ListenAddr, WebSettings};
use crate::station::StationStore;
use crate::wcfg::{ApOverride, Band, GlobalRadio, GlobalWlan, WirelessConfigStore};
use crate::wtpcmd::{WtpCmd, WtpCmdRegistry};

/// Shared store handles handed to every handler via axum state.
#[derive(Clone)]
pub struct AppData {
    pub devices: Arc<DeviceStore>,
    pub radios: Arc<RadioStore>,
    pub stations: Arc<StationStore>,
    pub profiles: Arc<ProfileStore>,
    pub fw: Arc<FirmwareStore>,
    pub upgrade: Arc<UpgradeRegistry>,
    pub cfg_update: Arc<ConfigUpdateRegistry>,
    pub wtp_cmd: Arc<WtpCmdRegistry>,
    pub wcfg: Arc<WirelessConfigStore>,
    /// Product capability registry, read by the security recommender.
    pub caps: Arc<ProductCapsStore>,
}

impl AppData {
    pub fn new(
        devices: Arc<DeviceStore>,
        radios: Arc<RadioStore>,
        stations: Arc<StationStore>,
        profiles: Arc<ProfileStore>,
        fw: Arc<FirmwareStore>,
        upgrade: Arc<UpgradeRegistry>,
        cfg_update: Arc<ConfigUpdateRegistry>,
        wtp_cmd: Arc<WtpCmdRegistry>,
        wcfg: Arc<WirelessConfigStore>,
        caps: Arc<ProductCapsStore>,
    ) -> Self {
        AppData {
            devices,
            radios,
            stations,
            profiles,
            fw,
            upgrade,
            cfg_update,
            wtp_cmd,
            wcfg,
            caps,
        }
    }
}

/// Error wrapper that renders failures as text responses (default 500).
struct ApiError {
    status: StatusCode,
    msg: String,
}

impl ApiError {
    fn not_found(msg: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::NOT_FOUND,
            msg: msg.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            msg: e.to_string(),
        }
    }
}

impl From<axum::extract::multipart::MultipartError> for ApiError {
    fn from(e: axum::extract::multipart::MultipartError) -> Self {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            msg: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.msg).into_response()
    }
}

/// Build the routed axum service.
fn router(state: Arc<AppData>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/devices", get(list_devices))
        .route("/api/devices/{mac}", get(get_device).put(update_device))
        .route("/api/devices/{mac}/approve", post(approve_device))
        .route("/api/radios", get(list_radios))
        .route("/api/devices/{mac}/wlans", get(list_device_wlans).post(set_device_wlan))
        .route(
            "/api/devices/{mac}/radios/{radio_id}",
            get(get_radio_h3c_header).put(set_radio_h3c_header),
        )
        .route("/api/stations", get(list_stations))
        .route("/api/profiles", get(list_profiles).post(create_profile))
        .route("/api/firmware", get(list_firmware).post(upload_firmware))
        .route("/api/devices/{mac}/upgrade", post(trigger_upgrade))
        .route("/api/devices/{mac}/config-update", post(trigger_config_update))
        .route("/api/devices/{mac}/reset", post(reset_device))
        .route("/api/devices/{mac}/disable", post(disable_device))
        .route(
            "/api/devices/{mac}/stations/{smac}/disconnect",
            post(disconnect_station),
        )
        .route("/api/wcfg", get(get_wcfg))
        .route("/api/wcfg/global/radio/{band}", get(get_global_radio).put(set_global_radio))
        .route(
            "/api/wcfg/global/wlan",
            get(list_global_wlans).post(set_global_wlan),
        )
        .route(
            "/api/wcfg/global/wlan/{band}/{wlan_id}",
            axum::routing::delete(delete_global_wlan),
        )
        .route(
            "/api/wcfg/override/{mac}/{band}",
            get(get_override).put(set_override).delete(clear_override),
        )
        .route("/api/wcfg/commit", post(commit_wcfg))
        .route("/api/wcfg/security/recommend", get(recommend_security))
        .route("/api/events", get(list_events))
        .with_state(state)
}

const INDEX_HTML: &str = include_str!("static/index.html");

async fn index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

// --- DTOs: JSON-facing views mapped from store models ---

#[derive(Serialize)]
struct DeviceDto {
    mac: String,
    name: String,
    description: String,
    vendor: Option<String>,
    model: Option<String>,
    hw_version: Option<String>,
    sw_version: Option<String>,
    ip_addr: Option<String>,
    state: String,
    first_seen: u64,
    last_seen: u64,
    joined_at: Option<u64>,
    approved: bool,
    /// Whether the WTP currently has a live CAPWAP session, derived from the
    /// last control packet rather than the persisted lifecycle state.
    online: bool,
    /// Last known AP LED state; `null` when the WTP never reported one (the
    /// TP-Link form reports it in every Echo Request).
    led_on: Option<bool>,
}

impl DeviceDto {
    fn new(d: &device::Device, online: bool) -> Self {
        DeviceDto {
            mac: device::mac_to_str(d.mac),
            name: d.name.clone(),
            description: d.description.clone(),
            vendor: d.vendor.clone(),
            model: d.model.clone(),
            hw_version: d.hw_version.clone(),
            sw_version: d.sw_version.clone(),
            ip_addr: d.ip_addr.clone(),
            state: d.state.clone(),
            first_seen: d.first_seen,
            last_seen: d.last_seen,
            joined_at: d.joined_at,
            approved: d.approved,
            online,
            led_on: d.led_on,
        }
    }
}

#[derive(Serialize)]
struct RadioDto {
    mac: String,
    radio_id: u8,
    band: Option<String>,
    admin_state: u8,
    op_state: u8,
    channel: Option<u32>,
    tx_power: Option<i32>,
    last_seen: u64,
}

impl From<&crate::radio::Radio> for RadioDto {
    fn from(r: &crate::radio::Radio) -> Self {
        RadioDto {
            mac: device::mac_to_str(r.mac),
            radio_id: r.radio_id,
            band: r.band.clone(),
            admin_state: r.admin_state,
            op_state: r.op_state,
            channel: r.channel,
            tx_power: r.tx_power,
            last_seen: r.last_seen,
        }
    }
}

#[derive(Serialize)]
struct StationDto {
    wmac: String,
    mac: String,
    radio_id: u8,
    wlan_id: u8,
    state: String,
    ip_addr: Option<String>,
    ssid: Option<String>,
    rssi: Option<i32>,
    associated_at: Option<u64>,
    last_seen: u64,
}

impl From<&crate::station::Station> for StationDto {
    fn from(s: &crate::station::Station) -> Self {
        StationDto {
            wmac: device::mac_to_str(s.wmac),
            mac: device::mac_to_str(s.mac),
            radio_id: s.radio_id,
            wlan_id: s.wlan_id,
            state: s.state.clone(),
            ip_addr: s.ip_addr.clone(),
            ssid: s.ssid.clone(),
            rssi: s.rssi,
            associated_at: s.associated_at,
            last_seen: s.last_seen,
        }
    }
}

#[derive(Serialize)]
struct ProfileDto {
    id: i64,
    name: String,
    method: String,
    cipher: String,
    caps: u16,
}

impl From<&crate::security::SecurityProfile> for ProfileDto {
    fn from(p: &crate::security::SecurityProfile) -> Self {
        ProfileDto {
            id: p.id,
            name: p.name.clone(),
            method: p.method.clone(),
            cipher: p.cipher.clone(),
            caps: p.caps,
        }
    }
}

#[derive(Serialize)]
struct EventDto {
    seq: u64,
    ts_unix: u64,
    category: &'static str,
    level: &'static str,
    message: String,
}

impl From<logx::MgmtEvent> for EventDto {
    fn from(e: logx::MgmtEvent) -> Self {
        EventDto {
            seq: e.seq,
            ts_unix: e.ts_unix,
            category: e.category,
            level: e.level,
            message: e.message,
        }
    }
}

#[derive(Serialize)]
struct FirmwareImageDto {
    id: i64,
    vendor: String,
    model: String,
    hw_version: String,
    file_name: String,
    size: u64,
    hash: String,
    stored_path: String,
    uploaded_at: u64,
}

impl From<&crate::firmware::FirmwareImage> for FirmwareImageDto {
    fn from(i: &crate::firmware::FirmwareImage) -> Self {
        let hash: String = i.hash.iter().map(|b| format!("{:02x}", b)).collect();
        FirmwareImageDto {
            id: i.id,
            vendor: i.vendor.clone(),
            model: i.model.clone(),
            hw_version: i.hw_version.clone(),
            file_name: i.file_name.clone(),
            size: i.size,
            hash,
            stored_path: i.stored_path.clone(),
            uploaded_at: i.uploaded_at,
        }
    }
}

#[derive(Deserialize)]
struct UpgradeReq {
    image_id: i64,
}

// --- Handlers ---

async fn list_devices(State(st): State<Arc<AppData>>) -> Result<Json<Vec<DeviceDto>>, ApiError> {
    let mut out: Vec<DeviceDto> = st
        .devices
        .list()?
        .iter()
        .map(|d| DeviceDto::new(d, st.devices.is_online(d.mac)))
        .collect();
    out.sort_by(|a, b| a.mac.cmp(&b.mac));
    Ok(Json(out))
}

async fn get_device(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
) -> Result<Json<DeviceDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    match st.devices.get(mac)? {
        Some(d) => Ok(Json(DeviceDto::new(&d, st.devices.is_online(mac)))),
        None => Err(ApiError::not_found("device not found")),
    }
}

#[derive(Deserialize)]
struct DeviceMeta {
    name: Option<String>,
    description: Option<String>,
}

async fn update_device(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
    Json(meta): Json<DeviceMeta>,
) -> Result<Json<DeviceDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let name = meta.name.unwrap_or_default();
    let description = meta.description.unwrap_or_default();
    st.devices.set_metadata(mac, &name, &description)?;
    match st.devices.get(mac)? {
        Some(d) => Ok(Json(DeviceDto::new(&d, st.devices.is_online(mac)))),
        None => Err(ApiError::not_found("device not found")),
    }
}

/// Approve a pending WTP so it becomes managed.
async fn approve_device(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
) -> Result<Json<DeviceDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    st.devices.approve(mac)?;
    match st.devices.get(mac)? {
        Some(d) => Ok(Json(DeviceDto::new(&d, st.devices.is_online(mac)))),
        None => Err(ApiError::not_found("device not found")),
    }
}

#[derive(Deserialize)]
struct RadioFilter {
    mac: Option<String>,
}

async fn list_radios(
    State(st): State<Arc<AppData>>,
    Query(q): Query<RadioFilter>,
) -> Result<Json<Vec<RadioDto>>, ApiError> {
    let out = match q.mac {
        Some(m) => {
            let mac = device::mac_from_str(&m).map_err(ApiError::from)?;
            st.radios
                .list_by_device(mac)?
                .iter()
                .map(RadioDto::from)
                .collect::<Vec<_>>()
        }
        None => st
            .radios
            .list_all()?
            .iter()
            .map(RadioDto::from)
            .collect::<Vec<_>>(),
    };
    Ok(Json(out))
}

#[derive(Serialize)]
struct RadioWlanDto {
    mac: String,
    radio_id: u8,
    wlan_id: u8,
    ssid: String,
    security: SecurityDto,
    wlan_enable: bool,
    isolate: bool,
    broadcast: bool,
    client_count: u32,
    vlan_id: u32,
    rekey_period: u32,
    /// Compatibility caveats; empty unless the set involved a trade-off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// API view of a WLAN security policy, keeping the two dimensions apart.
#[derive(Serialize)]
struct SecurityDto {
    akm: String,
    cipher: String,
    pmf: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    psk: Option<String>,
}

impl From<&SecurityPolicy> for SecurityDto {
    fn from(p: &SecurityPolicy) -> Self {
        SecurityDto {
            akm: p.akm.as_str().into(),
            cipher: p.cipher.as_str().into(),
            pmf: p.pmf.as_str().into(),
            psk: p.psk.clone(),
        }
    }
}

fn serde_default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct RadioWlanReq {
    radio_id: u8,
    wlan_id: Option<u8>,
    ssid: String,
    /// Key-management ("open" | "psk" | "psk-sae" | "sae") and cipher
    /// ("tkip" | "ccmp" | "tkip+ccmp"); pmf defaults to disabled.
    akm: String,
    cipher: Option<String>,
    pmf: Option<String>,
    psk: Option<String>,
    /// H3C 0xfde8 record fields; optional with DB-matching defaults
    /// (record up, SSID visible).
    #[serde(default = "serde_default_true")]
    wlan_enable: bool,
    #[serde(default)]
    isolate: bool,
    #[serde(default = "serde_default_true")]
    broadcast: bool,
    #[serde(default)]
    client_count: u32,
    #[serde(default)]
    vlan_id: u32,
    #[serde(default)]
    rekey_period: u32,
}

/// List the per-radio WLAN configurations pushed to a WTP.
async fn list_device_wlans(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
) -> Result<Json<Vec<RadioWlanDto>>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let wlans = st.radios.list_wlans(mac)?;
    Ok(Json(
        wlans
            .iter()
            .map(|w| RadioWlanDto {
                mac: device::mac_to_str(w.mac),
                radio_id: w.radio_id,
                wlan_id: w.wlan_id,
                ssid: w.ssid.clone(),
                security: (&w.security).into(),
                wlan_enable: w.wlan_enable,
                isolate: w.isolate,
                broadcast: w.broadcast,
                client_count: w.client_count,
                vlan_id: w.vlan_id,
                rekey_period: w.rekey_period,
                warnings: Vec::new(),
            })
            .collect(),
    ))
}

/// Set (insert or overwrite) a per-radio WLAN configuration for a WTP. The new
/// value takes effect on the WTP's next Configure-phase push. Compatibility
/// caveats are returned in `warnings`.
async fn set_device_wlan(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
    Json(req): Json<RadioWlanReq>,
) -> Result<Json<RadioWlanDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let security = parse_security_policy(
        &req.akm,
        req.cipher.as_deref(),
        req.pmf.as_deref(),
        req.psk.as_deref(),
    )?;
    let warnings = policy_warnings(&st, &security);
    let wlan_id = req.wlan_id.unwrap_or(1);
    let w = RadioWlan {
        mac,
        radio_id: req.radio_id,
        wlan_id,
        ssid: req.ssid.clone(),
        security: security.clone(),
        wlan_enable: req.wlan_enable,
        isolate: req.isolate,
        broadcast: req.broadcast,
        client_count: req.client_count,
        vlan_id: req.vlan_id,
        rekey_period: req.rekey_period,
    };
    st.radios.set_wlan(&w)?;
    logx::admin(format!(
        "WLAN config set for {} radio {}: ssid={}, akm={}, cipher={}, pmf={}, broadcast={}",
        device::mac_to_str(mac),
        req.radio_id,
        req.ssid,
        security.akm.as_str(),
        security.cipher.as_str(),
        security.pmf.as_str(),
        req.broadcast
    ));
    Ok(Json(RadioWlanDto {
        mac: device::mac_to_str(mac),
        radio_id: req.radio_id,
        wlan_id,
        ssid: req.ssid,
        security: (&security).into(),
        wlan_enable: req.wlan_enable,
        isolate: req.isolate,
        broadcast: req.broadcast,
        client_count: req.client_count,
        vlan_id: req.vlan_id,
        rekey_period: req.rekey_period,
        warnings,
    }))
}

#[derive(Serialize)]
struct H3cRadioHeaderDto {
    radio_id: u8,
    enable: bool,
    power: u32,
    mode: u32,
    channel: u32,
}

impl From<H3cRadioHeader> for H3cRadioHeaderDto {
    fn from(h: H3cRadioHeader) -> Self {
        H3cRadioHeaderDto {
            radio_id: h.radio_id,
            enable: h.enable,
            power: h.power,
            mode: h.mode,
            channel: h.channel,
        }
    }
}

/// H3C band-header config body; absent fields keep the stored value.
#[derive(Deserialize)]
struct H3cRadioHeaderPatch {
    enable: Option<bool>,
    power: Option<u32>,
    mode: Option<u32>,
    channel: Option<u32>,
}

/// Read a radio's H3C 0xfde8 band-header config (defaults when never stored).
async fn get_radio_h3c_header(
    State(st): State<Arc<AppData>>,
    Path((mac, radio_id)): Path<(String, u8)>,
) -> Result<Json<H3cRadioHeaderDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let h = st.radios.h3c_header(mac, radio_id)?;
    Ok(Json(h.into()))
}

/// Update a radio's H3C 0xfde8 band-header config (enable/power/mode/channel).
async fn set_radio_h3c_header(
    State(st): State<Arc<AppData>>,
    Path((mac, radio_id)): Path<(String, u8)>,
    Json(p): Json<H3cRadioHeaderPatch>,
) -> Result<Json<H3cRadioHeaderDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let mut h = st.radios.h3c_header(mac, radio_id)?;
    if let Some(v) = p.enable {
        h.enable = v;
    }
    if let Some(v) = p.power {
        h.power = v;
    }
    if let Some(v) = p.mode {
        h.mode = v;
    }
    if let Some(v) = p.channel {
        h.channel = v;
    }
    st.radios.set_h3c_header(mac, &h)?;
    logx::admin(format!(
        "H3C radio header set for {} radio {}: enable={}, power={}, mode={}, channel={}",
        device::mac_to_str(mac),
        h.radio_id,
        h.enable,
        h.power,
        h.mode,
        h.channel
    ));
    Ok(Json(h.into()))
}

#[derive(Deserialize)]
struct StationFilter {
    mac: Option<String>,
}

async fn list_stations(
    State(st): State<Arc<AppData>>,
    Query(q): Query<StationFilter>,
) -> Result<Json<Vec<StationDto>>, ApiError> {
    let out = match q.mac {
        Some(m) => {
            let mac = device::mac_from_str(&m).map_err(ApiError::from)?;
            st.stations
                .list_by_wtp(mac)?
                .iter()
                .map(StationDto::from)
                .collect::<Vec<_>>()
        }
        None => st
            .stations
            .list_all()?
            .iter()
            .map(StationDto::from)
            .collect::<Vec<_>>(),
    };
    Ok(Json(out))
}

async fn list_profiles(State(st): State<Arc<AppData>>) -> Result<Json<Vec<ProfileDto>>, ApiError> {
    Ok(Json(
        st.profiles.list()?.iter().map(ProfileDto::from).collect(),
    ))
}

#[derive(Deserialize)]
struct ProfileCreate {
    name: String,
    method: String,
    cipher: String,
    caps: Option<u16>,
}

async fn create_profile(
    State(st): State<Arc<AppData>>,
    Json(p): Json<ProfileCreate>,
) -> Result<Json<ProfileDto>, ApiError> {
    st.profiles
        .upsert(&p.name, &p.method, &p.cipher, p.caps.unwrap_or(0))?;
    match st.profiles.get(&p.name)? {
        Some(prof) => Ok(Json((&prof).into())),
        None => Err(ApiError::not_found("profile create failed")),
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    /// Return events with `seq > since` (default 0 = full buffer). Non-destructive.
    since: Option<u64>,
}

async fn list_events(Query(q): Query<EventsQuery>) -> Result<Json<Vec<EventDto>>, ApiError> {
    let since = q.since.unwrap_or(0);
    Ok(Json(
        logx::snapshot(since)
            .into_iter()
            .map(EventDto::from)
            .collect(),
    ))
}

async fn list_firmware(
    State(st): State<Arc<AppData>>,
) -> Result<Json<Vec<FirmwareImageDto>>, ApiError> {
    Ok(Json(
        st.fw
            .list_images()?
            .iter()
            .map(FirmwareImageDto::from)
            .collect(),
    ))
}

async fn upload_firmware(
    State(st): State<Arc<AppData>>,
    mut multipart: Multipart,
) -> Result<Json<FirmwareImageDto>, ApiError> {
    let mut vendor = String::new();
    let mut model = String::new();
    let mut hw_version = String::new();
    let mut file_name: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.map_err(ApiError::from)? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "vendor" => vendor = field.text().await.map_err(ApiError::from)?,
            "model" => model = field.text().await.map_err(ApiError::from)?,
            "hw_version" => hw_version = field.text().await.map_err(ApiError::from)?,
            "file" => {
                file_name = field.file_name().map(|s| s.to_string());
                file_bytes = Some(field.bytes().await.map_err(ApiError::from)?.to_vec());
            }
            _ => {}
        }
    }

    let file_name = file_name.filter(|f| !f.is_empty());
    let file_bytes = file_bytes.unwrap_or_default();
    if vendor.is_empty()
        || model.is_empty()
        || hw_version.is_empty()
        || file_name.is_none()
        || file_bytes.is_empty()
    {
        return Err(ApiError::not_found(
            "missing firmware fields ('vendor','model','hw_version','file')",
        ));
    }

    let img = st.fw.save_image(
        &vendor,
        &model,
        &hw_version,
        file_name.unwrap().as_str(),
        &file_bytes,
    )?;
    logx::firmware(format!(
        "firmware uploaded: {} ({:.1} KiB)",
        img.stored_path,
        img.size as f64 / 1024.0,
    ));
    Ok(Json((&img).into()))
}

async fn trigger_upgrade(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
    Json(req): Json<UpgradeReq>,
) -> Result<Json<FirmwareImageDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let img = match st.fw.get_image(req.image_id)? {
        Some(i) => i,
        None => return Err(ApiError::not_found("image not found")),
    };
    let bytes = st.fw.load_image_bytes(req.image_id)?.unwrap_or_default();
    let name = format!(
        "{}/{}/{}/{}",
        img.vendor, img.model, img.hw_version, img.file_name
    );

    let _record = st.fw.record_start(&mac, &name, img.size as u32, &img.hash);
    if !st.upgrade.trigger(mac, UpgradeCmd::Start { image: bytes }) {
        return Err(ApiError::not_found(format!(
            "WTP {} is not in a live session",
            device::mac_to_str(mac)
        )));
    }
    logx::firmware(format!(
        "firmware {} queued for WTP {}",
        name,
        device::mac_to_str(mac)
    ));
    Ok(Json((&img).into()))
}

/// Request body for a management-plane Configuration Update push: the list of
/// H3C config-update elements to place in a Configuration Update Request (mtype
/// 7). Only the element types the AX60 request parser recognizes are exposed;
/// WLAN runtime config uses the opaque 0xfdf1 batch blob (not yet decoded) and
/// firmware image signalling rides the Image Data exchange instead.
#[derive(Deserialize)]
struct ConfigUpdateReq {
    elements: Vec<ConfigUpdateElemReq>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ConfigUpdateElemReq {
    KeepAlive { value: u32 },
    ApName { name: String },
    Led { value: u32 },
    Telnet { value: u32 },
    Roaming { value: u32 },
    Channel { radio: u8, channel: u8 },
    Power { radio: u8, power: u32 },
    AcAddressChange { ip: String },
}

impl ConfigUpdateElemReq {
    fn into_elem(self) -> Result<ConfigUpdateElem, ApiError> {
        Ok(match self {
            ConfigUpdateElemReq::KeepAlive { value } => ConfigUpdateElem::KeepAlive(value),
            ConfigUpdateElemReq::ApName { name } => ConfigUpdateElem::ApName(name.into_bytes()),
            ConfigUpdateElemReq::Led { value } => ConfigUpdateElem::Led(value),
            ConfigUpdateElemReq::Telnet { value } => ConfigUpdateElem::Telnet(value),
            ConfigUpdateElemReq::Roaming { value } => ConfigUpdateElem::Roaming(value),
            ConfigUpdateElemReq::Channel { radio, channel } => {
                ConfigUpdateElem::Channel { radio, channel }
            }
            ConfigUpdateElemReq::Power { radio, power } => ConfigUpdateElem::Power { radio, power },
            ConfigUpdateElemReq::AcAddressChange { ip } => ConfigUpdateElem::AcAddressChange(
                ip.parse().map_err(|_| ApiError {
                    status: StatusCode::BAD_REQUEST,
                    msg: format!("invalid AC address: {ip}"),
                })?,
            ),
        })
    }
}

#[derive(Serialize)]
struct ConfigUpdateAck {
    queued: bool,
}

/// Queue a Configuration Update Request for a WTP's live CAPWAP session. The
/// session sends it and matches the WTP's Configuration Update Response (mtype
/// 8), whose Result Code (tag 33) confirms or rejects the push.
async fn trigger_config_update(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
    Json(req): Json<ConfigUpdateReq>,
) -> Result<Json<ConfigUpdateAck>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    if req.elements.is_empty() {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            msg: "elements must not be empty".into(),
        });
    }
    let mut elems = Vec::with_capacity(req.elements.len());
    let led = req.elements.iter().find_map(|e| match e {
        ConfigUpdateElemReq::Led { value } => Some(*value != 0),
        _ => None,
    });
    for e in req.elements {
        elems.push(e.into_elem()?);
    }
    // The LED state is also a per-device setting: remember the requested value
    // so it is shown in the UI and re-applied when the WTP next enters Run,
    // whether or not it currently has a live session.
    if let Some(on) = led {
        st.devices.set_led_on(mac, on)?;
    }
    let led_only = matches!(elems.as_slice(), [ConfigUpdateElem::Led(_)]);
    if !st.cfg_update.trigger(mac, ConfigUpdateCmd::Push { elems }) {
        if led_only {
            // Nothing to send right now; the setting is stored above and takes
            // effect at the WTP's next join.
            return Ok(Json(ConfigUpdateAck { queued: false }));
        }
        return Err(ApiError::not_found(format!(
            "WTP {} is not in a live session",
            device::mac_to_str(mac)
        )));
    }
    logx::device(format!(
        "configuration update queued for WTP {}",
        device::mac_to_str(mac)
    ));
    Ok(Json(ConfigUpdateAck { queued: true }))
}

// --- G1/G3: AP lifecycle (reset / disable) and client eviction ---

#[derive(Serialize)]
struct WtpCmdAck {
    queued: bool,
}

/// Error for a WTP whose live CAPWAP session is absent.
fn not_live(mac: &device::Mac) -> ApiError {
    ApiError::not_found(format!(
        "WTP {} is not in a live session",
        device::mac_to_str(*mac)
    ))
}

/// Restart a WTP (Reset Request, mtype 17); it reboots on its current image.
async fn reset_device(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
) -> Result<Json<WtpCmdAck>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    if !st.wtp_cmd.trigger(mac, WtpCmd::Reset) {
        return Err(not_live(&mac));
    }
    logx::device(format!("reset queued for WTP {}", device::mac_to_str(mac)));
    Ok(Json(WtpCmdAck { queued: true }))
}

/// Disable a WTP: restore factory defaults (Clear Configuration Request, mtype
/// 23) and, once acknowledged, restart it (Reset Request, mtype 17).
async fn disable_device(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
) -> Result<Json<WtpCmdAck>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    if !st.wtp_cmd.trigger(mac, WtpCmd::Disable) {
        return Err(not_live(&mac));
    }
    logx::device(format!(
        "disable queued for WTP {} (clear configuration, then reset)",
        device::mac_to_str(mac)
    ));
    Ok(Json(WtpCmdAck { queued: true }))
}

#[derive(Serialize)]
struct DisconnectAck {
    queued: bool,
    client: String,
}

/// Evict one station from a WTP by MAC (Release Client by AC Request, mtype
/// 139). The station must belong to the named AP; the AC does not remove the
/// local record — it disappears when the WTP reports the de-association.
async fn disconnect_station(
    State(st): State<Arc<AppData>>,
    Path((mac, smac)): Path<(String, String)>,
) -> Result<Json<DisconnectAck>, ApiError> {
    let wmac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let smac = device::mac_from_str(&smac).map_err(ApiError::from)?;
    if st.stations.get(wmac, smac)?.is_none() {
        return Err(ApiError::not_found(format!(
            "station {} is not associated with AP {}",
            device::mac_to_str(smac),
            device::mac_to_str(wmac)
        )));
    }
    if !st.wtp_cmd.trigger(wmac, WtpCmd::ReleaseClient(smac)) {
        return Err(not_live(&wmac));
    }
    logx::device(format!(
        "client {} release queued for WTP {}",
        device::mac_to_str(smac),
        device::mac_to_str(wmac)
    ));
    Ok(Json(DisconnectAck {
        queued: true,
        client: device::mac_to_str(smac),
    }))
}

// --- D1: global wireless config, per-AP overrides and commit ---

/// Shared WLAN security/PSK validation. The key-management and cipher
/// dimensions are parsed separately (they are orthogonal); a secured network
/// requires an 8..63 char passphrase, an open one ignores any supplied key.
fn parse_security_policy(
    akm: &str,
    cipher: Option<&str>,
    pmf: Option<&str>,
    psk: Option<&str>,
) -> Result<SecurityPolicy, ApiError> {
    let akm = Akm::from_str(akm).ok_or_else(|| ApiError {
        status: StatusCode::BAD_REQUEST,
        msg: format!("invalid akm '{akm}' (open|psk|psk-sae|sae)"),
    })?;
    let cipher = match cipher {
        Some(c) => Cipher::from_str(c).ok_or_else(|| ApiError {
            status: StatusCode::BAD_REQUEST,
            msg: format!("invalid cipher '{c}' (tkip|ccmp|tkip+ccmp)"),
        })?,
        None => Cipher::default(),
    };
    let pmf = match pmf {
        Some(p) => Pmf::from_str(p).ok_or_else(|| ApiError {
            status: StatusCode::BAD_REQUEST,
            msg: format!("invalid pmf '{p}' (disabled|capable|required)"),
        })?,
        None => Pmf::default(),
    };
    let psk = if akm.secured() {
        let len = psk.map(str::len).unwrap_or(0);
        if !(8..=63).contains(&len) {
            return Err(ApiError {
                status: StatusCode::BAD_REQUEST,
                msg: "psk must be 8..63 characters for a secured network".into(),
            });
        }
        psk.map(str::to_string)
    } else {
        None
    };
    Ok(SecurityPolicy {
        akm,
        cipher,
        psk,
        pmf,
    })
}

/// Set-time compatibility caveats for a chosen policy: the floor and
/// client-group check plus every characterized product the push may target.
fn policy_warnings(st: &AppData, policy: &SecurityPolicy) -> Vec<String> {
    match st.caps.list() {
        Ok(caps) => crate::fleet::assess_choice(policy, ClientGroup::Wpa2Plus, &caps).messages,
        Err(_) => Vec::new(),
    }
}

/// The vendor profiles of the APs in the fleet, used by the recommender.
fn fleet_profiles(st: &AppData) -> Vec<VendorProfile> {
    let mut out = Vec::new();
    if let Ok(devices) = st.devices.list() {
        for d in devices {
            if !d.approved {
                continue;
            }
            let profile = match d.vendor.as_deref() {
                Some(v) if v.eq_ignore_ascii_case("h3c") => Some(VendorProfile::H3c),
                Some(v) if v.eq_ignore_ascii_case("tp-link") || v.eq_ignore_ascii_case("tplink") => {
                    Some(VendorProfile::TpLink)
                }
                _ => None,
            };
            if let Some(p) = profile {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

#[derive(Serialize)]
struct GlobalRadioDto {
    band: u8,
    enable: bool,
    channel_mode: u8,
    channel: u32,
    power: u32,
    mode: u32,
}

impl From<GlobalRadio> for GlobalRadioDto {
    fn from(g: GlobalRadio) -> Self {
        GlobalRadioDto {
            band: g.band,
            enable: g.enable,
            // The DB stores a single IEEE channel (0 = auto); the UI still works
            // in mode+channel terms, so derive the mode for display.
            channel_mode: u8::from(g.channel != 0),
            channel: g.channel,
            power: g.power,
            mode: g.mode,
        }
    }
}

#[derive(Serialize)]
struct GlobalWlanDto {
    band: u8,
    wlan_id: u8,
    ssid: String,
    security: SecurityDto,
    wlan_enable: bool,
    isolate: bool,
    broadcast: bool,
    client_count: u32,
    vlan_id: u32,
    rekey_period: u32,
    /// Compatibility caveats; empty unless the set involved a trade-off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

impl GlobalWlanDto {
    fn new(w: &GlobalWlan, warnings: Vec<String>) -> Self {
        GlobalWlanDto {
            band: w.band,
            wlan_id: w.wlan_id,
            ssid: w.ssid.clone(),
            security: (&w.security).into(),
            wlan_enable: w.wlan_enable,
            isolate: w.isolate,
            broadcast: w.broadcast,
            client_count: w.client_count,
            vlan_id: w.vlan_id,
            rekey_period: w.rekey_period,
            warnings,
        }
    }
}

impl From<GlobalWlan> for GlobalWlanDto {
    fn from(w: GlobalWlan) -> Self {
        GlobalWlanDto::new(&w, Vec::new())
    }
}

#[derive(Serialize)]
struct ApOverrideDto {
    mac: String,
    band: u8,
    channel: Option<u32>,
    power: Option<u32>,
    mode: Option<u32>,
}

impl From<ApOverride> for ApOverrideDto {
    fn from(o: ApOverride) -> Self {
        ApOverrideDto {
            mac: device::mac_to_str(o.mac),
            band: o.band,
            channel: o.channel,
            power: o.power,
            mode: o.mode,
        }
    }
}

#[derive(Serialize)]
struct WcfgDto {
    global_radios: Vec<GlobalRadioDto>,
    global_wlans: Vec<GlobalWlanDto>,
    overrides: Vec<ApOverrideDto>,
    pending: Vec<String>,
}

fn wcfg_dto(st: &AppData) -> Result<WcfgDto, ApiError> {
    let mut global_wlans = Vec::new();
    for b in Band::ALL {
        for w in st.wcfg.list_global_wlans(b.radio_id())? {
            global_wlans.push(GlobalWlanDto::from(w));
        }
    }
    Ok(WcfgDto {
        global_radios: st
            .wcfg
            .list_global_radios()?
            .into_iter()
            .map(GlobalRadioDto::from)
            .collect(),
        global_wlans,
        overrides: st
            .wcfg
            .list_overrides()?
            .into_iter()
            .map(ApOverrideDto::from)
            .collect(),
        pending: st
            .wcfg
            .list_pending()?
            .iter()
            .map(|m| device::mac_to_str(*m))
            .collect(),
    })
}

/// Materialize the global template into every approved WTP's per-AP rows and
/// mark them pending (an AC-wide edit applies to all managed APs).
fn propagate_global(st: &AppData) -> Result<(), ApiError> {
    let macs: Vec<crate::device::Mac> = st
        .devices
        .list()?
        .into_iter()
        .filter(|d| d.approved)
        .map(|d| d.mac)
        .collect();
    st.wcfg.materialize_all(&st.radios, &macs)?;
    Ok(())
}

/// The full wireless configuration: global templates, per-AP overrides and the
/// pending-sync set.
async fn get_wcfg(State(st): State<Arc<AppData>>) -> Result<Json<WcfgDto>, ApiError> {
    Ok(Json(wcfg_dto(&st)?))
}

#[derive(Deserialize)]
struct GlobalRadioReq {
    enable: Option<bool>,
    channel_mode: Option<u8>,
    channel: Option<u32>,
    power: Option<u32>,
    mode: Option<u32>,
}

async fn get_global_radio(
    State(st): State<Arc<AppData>>,
    Path(band): Path<u8>,
) -> Result<Json<GlobalRadioDto>, ApiError> {
    Ok(Json(st.wcfg.get_global_radio(band)?.into()))
}

/// Patch a band's global radio template (absent fields keep their value). The
/// change is materialized into every approved WTP and marked pending.
async fn set_global_radio(
    State(st): State<Arc<AppData>>,
    Path(band): Path<u8>,
    Json(req): Json<GlobalRadioReq>,
) -> Result<Json<GlobalRadioDto>, ApiError> {
    let mut g = st.wcfg.get_global_radio(band)?;
    if let Some(v) = req.enable {
        g.enable = v;
    }
    // Fold the UI's mode+channel into the single stored IEEE channel: mode 0
    // means auto (channel 0); mode 1 takes the requested channel (or keeps the
    // stored one). A bare `channel` is applied directly (0 = auto).
    if let Some(v) = req.channel_mode {
        g.channel = if v == 0 {
            0
        } else {
            req.channel.unwrap_or(g.channel)
        };
    } else if let Some(v) = req.channel {
        g.channel = v;
    }
    if let Some(v) = req.power {
        g.power = v;
    }
    if let Some(v) = req.mode {
        g.mode = v;
    }
    st.wcfg.set_global_radio(&g)?;
    propagate_global(&st)?;
    logx::admin(format!(
        "global radio set for band {band}: enable={}, channel_mode={}, channel={}, power={}, mode={}",
        g.enable,
        u8::from(g.channel != 0),
        g.channel,
        g.power,
        g.mode
    ));
    Ok(Json(g.into()))
}

#[derive(Deserialize)]
struct GlobalWlanReq {
    band: u8,
    wlan_id: Option<u8>,
    ssid: String,
    /// Key-management and cipher dimensions, kept separate; pmf defaults to
    /// disabled.
    akm: String,
    cipher: Option<String>,
    pmf: Option<String>,
    psk: Option<String>,
    #[serde(default = "serde_default_true")]
    wlan_enable: bool,
    #[serde(default)]
    isolate: bool,
    #[serde(default = "serde_default_true")]
    broadcast: bool,
    #[serde(default)]
    client_count: u32,
    #[serde(default)]
    vlan_id: u32,
    #[serde(default)]
    rekey_period: u32,
}

async fn list_global_wlans(State(st): State<Arc<AppData>>) -> Result<Json<Vec<GlobalWlanDto>>, ApiError> {
    let mut out = Vec::new();
    for b in Band::ALL {
        for w in st.wcfg.list_global_wlans(b.radio_id())? {
            out.push(GlobalWlanDto::from(w));
        }
    }
    Ok(Json(out))
}

/// Insert or overwrite a global SSID template for a band. Materialized into
/// every approved WTP and marked pending. Compatibility caveats are returned in
/// `warnings`.
async fn set_global_wlan(
    State(st): State<Arc<AppData>>,
    Json(req): Json<GlobalWlanReq>,
) -> Result<Json<GlobalWlanDto>, ApiError> {
    let security = parse_security_policy(
        &req.akm,
        req.cipher.as_deref(),
        req.pmf.as_deref(),
        req.psk.as_deref(),
    )?;
    let warnings = policy_warnings(&st, &security);
    let w = GlobalWlan {
        band: req.band,
        wlan_id: req.wlan_id.unwrap_or(1),
        ssid: req.ssid,
        security: security.clone(),
        wlan_enable: req.wlan_enable,
        isolate: req.isolate,
        broadcast: req.broadcast,
        client_count: req.client_count,
        vlan_id: req.vlan_id,
        rekey_period: req.rekey_period,
    };
    st.wcfg.set_global_wlan(&w)?;
    propagate_global(&st)?;
    logx::admin(format!(
        "global WLAN set for band {} wlan {}: ssid={}, akm={}, cipher={}, pmf={}",
        w.band,
        w.wlan_id,
        w.ssid,
        security.akm.as_str(),
        security.cipher.as_str(),
        security.pmf.as_str()
    ));
    Ok(Json(GlobalWlanDto::new(&w, warnings)))
}

/// Recommended WLAN security for the fleet's APs and target client group.
#[derive(Serialize)]
struct SecurityRecommendDto {
    akm: String,
    cipher: String,
    pmf: String,
    group: String,
    /// A separate legacy SSID when WPA1 clients must be kept working.
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy_akm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy_cipher: Option<String>,
    level: &'static str,
    messages: Vec<String>,
}

#[derive(Deserialize)]
struct RecommendQuery {
    group: Option<String>,
}

/// Recommend the strongest policy that the fleet can express while still
/// serving the target client group, never below WPA-PSK+AES.
async fn recommend_security(
    State(st): State<Arc<AppData>>,
    Query(q): Query<RecommendQuery>,
) -> Result<Json<SecurityRecommendDto>, ApiError> {
    let group = match q.group.as_deref() {
        Some(g) => ClientGroup::from_str(g).ok_or_else(|| ApiError {
            status: StatusCode::BAD_REQUEST,
            msg: format!("invalid client group '{g}' (legacy|wpa2+|wpa3)"),
        })?,
        None => ClientGroup::default(),
    };
    let profiles = fleet_profiles(&st);
    let rec = crate::fleet::recommend(&st.caps, &profiles, group)?;
    Ok(Json(SecurityRecommendDto {
        akm: rec.policy.akm.as_str().into(),
        cipher: rec.policy.cipher.as_str().into(),
        pmf: rec.policy.pmf.as_str().into(),
        group: group.as_str().into(),
        legacy_akm: rec.legacy.as_ref().map(|p| p.akm.as_str().to_string()),
        legacy_cipher: rec.legacy.as_ref().map(|p| p.cipher.as_str().to_string()),
        level: match rec.assessment.level {
            crate::fleet::Level::Ok => "ok",
            crate::fleet::Level::Warn => "warn",
            crate::fleet::Level::Error => "error",
        },
        messages: rec.assessment.messages,
    }))
}

async fn delete_global_wlan(
    State(st): State<Arc<AppData>>,
    Path((band, wlan_id)): Path<(u8, u8)>,
) -> Result<Json<WcfgDto>, ApiError> {
    st.wcfg.delete_global_wlan(band, wlan_id)?;
    propagate_global(&st)?;
    logx::admin(format!("global WLAN removed: band {band} wlan {wlan_id}"));
    Ok(Json(wcfg_dto(&st)?))
}

#[derive(Deserialize)]
struct OverrideReq {
    channel: Option<u32>,
    power: Option<u32>,
    mode: Option<u32>,
}

async fn get_override(
    State(st): State<Arc<AppData>>,
    Path((mac, band)): Path<(String, u8)>,
) -> Result<Json<Option<ApOverrideDto>>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    Ok(Json(st.wcfg.get_override(mac, band)?.map(ApOverrideDto::from)))
}

/// Set a per-AP override (absent fields inherit the global value). The AP's
/// rows are re-materialized and it is marked pending.
async fn set_override(
    State(st): State<Arc<AppData>>,
    Path((mac, band)): Path<(String, u8)>,
    Json(req): Json<OverrideReq>,
) -> Result<Json<ApOverrideDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    let o = ApOverride {
        mac,
        band,
        channel: req.channel,
        power: req.power,
        mode: req.mode,
    };
    st.wcfg.set_override(&o)?;
    st.wcfg.materialize(&st.radios, mac)?;
    st.wcfg.mark_pending(mac)?;
    logx::admin(format!(
        "override set for {} band {band}: channel={:?}, power={:?}, mode={:?}",
        device::mac_to_str(mac),
        o.channel,
        o.power,
        o.mode
    ));
    Ok(Json(o.into()))
}

/// Clear a per-AP override (back to the global template); re-materialize and
/// mark pending.
async fn clear_override(
    State(st): State<Arc<AppData>>,
    Path((mac, band)): Path<(String, u8)>,
) -> Result<Json<WcfgDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    st.wcfg.clear_override(mac, band)?;
    st.wcfg.materialize(&st.radios, mac)?;
    st.wcfg.mark_pending(mac)?;
    logx::admin(format!(
        "override cleared for {} band {band}",
        device::mac_to_str(mac)
    ));
    Ok(Json(wcfg_dto(&st)?))
}

#[derive(Deserialize, Default)]
struct CommitReq {
    #[serde(default)]
    macs: Vec<String>,
}

#[derive(Serialize)]
struct CommitResult {
    pushed: Vec<String>,
    /// APs with a pending change but no live session; they keep the materialized
    /// config and pick it up at their next Configure push.
    offline: Vec<String>,
}

/// Commit the pending configuration: for each target WTP push a Configuration
/// Update Request carrying the effective channel/power per band. The pending
/// entry clears when the WTP acknowledges (CONFIG_UPDATE_RESP, main.rs).
async fn commit_wcfg(
    State(st): State<Arc<AppData>>,
    Json(req): Json<CommitReq>,
) -> Result<Json<CommitResult>, ApiError> {
    let targets: Vec<crate::device::Mac> = if req.macs.is_empty() {
        st.wcfg.list_pending()?
    } else {
        req.macs
            .iter()
            .map(|m| device::mac_from_str(m))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::from)?
    };
    if targets.is_empty() {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            msg: "no pending WTPs to commit".into(),
        });
    }
    let mut pushed = Vec::new();
    let mut offline = Vec::new();
    for mac in targets {
        let mut elems = Vec::new();
        for b in Band::ALL {
            let h = st.wcfg.effective_radio(mac, b.radio_id())?;
            elems.push(ConfigUpdateElem::Channel {
                radio: b.radio_id(),
                channel: h.channel as u8,
            });
            elems.push(ConfigUpdateElem::Power {
                radio: b.radio_id(),
                power: h.power,
            });
        }
        let name = device::mac_to_str(mac);
        if st.cfg_update.trigger(mac, ConfigUpdateCmd::Push { elems }) {
            pushed.push(name);
        } else {
            offline.push(name);
        }
    }
    logx::device(format!(
        "wireless config commit: pushed {:?}, offline {:?}",
        pushed, offline
    ));
    Ok(Json(CommitResult { pushed, offline }))
}

/// Serve the management plane. HTTP is always on; HTTPS starts when configured.
/// A missing certificate/key pair is generated (self-signed) and persisted, so
/// the same identity is reused on the next start.
pub async fn serve(state: Arc<AppData>, settings: WebSettings) -> Result<()> {
    let app = router(state);
    let http = TcpListener::bind(settings.http.socket_addr())
        .await
        .with_context(|| format!("bind web http on {}", settings.http))?;
    logx::admin(format!(
        "web management plane listening on http://{}",
        settings.http
    ));
    let Some(https) = settings.https else {
        axum::serve(http, app).await?;
        return Ok(());
    };

    let (certs, key, fingerprint) = load_or_create_identity(&settings, https)?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("invalid TLS certificate/key: {e}"))?;
    let listener = TcpListener::bind(https.socket_addr())
        .await
        .with_context(|| format!("bind web https on {https}"))?;
    logx::admin(format!(
        "web management plane listening on https://{https} (cert sha256 {fingerprint})"
    ));
    let tls_listener = TlsListener {
        inner: listener,
        acceptor: TlsAcceptor::from(Arc::new(tls)),
    };
    // HTTP and HTTPS run side by side; either one ending is fatal.
    let http_app = app.clone();
    let https_app = app;
    tokio::try_join!(
        async { axum::serve(http, http_app).await.map_err(anyhow::Error::from) },
        async { axum::serve(tls_listener, https_app).await.map_err(anyhow::Error::from) },
    )?;
    Ok(())
}

/// A TCP listener that completes the TLS handshake before yielding a connection.
struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = match self.inner.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("web TLS accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match self.acceptor.accept(tcp).await {
                Ok(tls) => return (tls, addr),
                Err(e) => {
                    // Typically a client that speaks plain HTTP to the TLS port
                    // or drops mid-handshake; keep serving others.
                    tracing::debug!("web TLS handshake from {addr} failed: {e}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Load the configured certificate/key, or create a persistent self-signed pair
/// when neither file exists. Returns the chain, key, and leaf SHA-256 fingerprint.
fn load_or_create_identity(
    settings: &WebSettings,
    bind: ListenAddr,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>, String)> {
    let cert_path = settings
        .https_cert
        .clone()
        .unwrap_or_else(|| PathBuf::from("certs/web/cert.pem"));
    let key_path = settings
        .https_key
        .clone()
        .unwrap_or_else(|| PathBuf::from("certs/web/key.pem"));

    match (cert_path.is_file(), key_path.is_file()) {
        (true, true) => {
            tracing::info!("[*] web TLS: using {}", cert_path.display());
        }
        (false, false) => {
            generate_self_signed(&cert_path, &key_path, bind)?;
            tracing::info!(
                "[*] web TLS: generated self-signed certificate {}",
                cert_path.display()
            );
        }
        _ => bail!(
            "TLS certificate/key must both exist: {} and {}",
            cert_path.display(),
            key_path.display()
        ),
    }

    let certs = load_pem_certs(&cert_path)?;
    let fingerprint = fingerprint(certs[0].as_ref());
    let key = load_pem_key(&key_path)?;
    Ok((certs, key, fingerprint))
}

fn load_pem_certs(path: &FsPath) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let blocks = pem::parse_many(&data).with_context(|| format!("parse PEM {}", path.display()))?;
    let mut out = Vec::new();
    for block in blocks {
        if block.tag() == "CERTIFICATE" {
            out.push(rustls::pki_types::CertificateDer::from(block.into_contents()));
        }
    }
    if out.is_empty() {
        bail!("no CERTIFICATE block in {}", path.display());
    }
    Ok(out)
}

fn load_pem_key(path: &FsPath) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let blocks = pem::parse_many(&data).with_context(|| format!("parse PEM {}", path.display()))?;
    for block in blocks {
        let tag = block.tag().to_string();
        let der = block.into_contents();
        match tag.as_str() {
            "PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))),
            "RSA PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))),
            "EC PRIVATE KEY" => return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der))),
            _ => {}
        }
    }
    bail!("no private key block in {}", path.display())
}

/// Create a self-signed certificate covering loopback, the bind address and the
/// host name, and write certificate and key as PEM.
fn generate_self_signed(cert_path: &FsPath, key_path: &FsPath, bind: ListenAddr) -> Result<()> {
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    if !bind.addr.is_unspecified() {
        let addr = bind.addr.to_string();
        if !sans.contains(&addr) {
            sans.push(addr);
        }
    }
    if let Some(name) = hostname() {
        if !sans.contains(&name) {
            sans.push(name);
        }
    }
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(sans)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "miniac");
    let cert = params.self_signed(&key)?;

    for path in [cert_path, key_path] {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
    }
    fs::write(cert_path, cert.pem()).with_context(|| format!("write {}", cert_path.display()))?;
    fs::write(key_path, key.serialize_pem())
        .with_context(|| format!("write {}", key_path.display()))?;
    Ok(())
}

fn hostname() -> Option<String> {
    let mut buf = [0 as libc::c_char; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    (!name.is_empty()).then_some(name)
}

/// Colon-separated uppercase hex SHA-256 of a DER certificate.
fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state() -> Arc<AppData> {
        let db = Arc::new(crate::db::Db::open_in_memory().unwrap());
        Arc::new(AppData::new(
            Arc::new(DeviceStore::new(db.clone())),
            Arc::new(RadioStore::new(db.clone())),
            Arc::new(StationStore::new(db.clone())),
            Arc::new(ProfileStore::new(db.clone())),
            Arc::new(FirmwareStore::new(db.clone())),
            Arc::new(UpgradeRegistry::new()),
            Arc::new(ConfigUpdateRegistry::new()),
            Arc::new(WtpCmdRegistry::new()),
            Arc::new(WirelessConfigStore::new(db.clone())),
            Arc::new(ProductCapsStore::new(db.clone())),
        ))
    }

    #[test]
    fn self_signed_identity_is_reused() {
        let dir = std::env::temp_dir().join(format!(
            "miniac-tls-{}-{}",
            std::process::id(),
            line!()
        ));
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let loopback = ListenAddr {
            addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 8443,
        };
        let settings = WebSettings {
            http: ListenAddr {
                addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port: 8246,
            },
            https: Some(loopback),
            https_cert: Some(cert.clone()),
            https_key: Some(key.clone()),
        };
        let (_, _, first_fp) = load_or_create_identity(&settings, loopback).unwrap();
        let first = fs::read(&cert).unwrap();
        let (_, _, second_fp) = load_or_create_identity(&settings, loopback).unwrap();
        assert_eq!(first_fp, second_fp);
        assert_eq!(first, fs::read(&cert).unwrap());
        assert!(key.is_file());
        fs::remove_dir_all(dir).ok();
    }

    /// POST helper returning the response for a request with no body.
    async fn post_empty(state: Arc<AppData>, uri: &str) -> StatusCode {
        router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn wtp_lifecycle_and_disconnect_endpoints() {
        use tokio::sync::mpsc;

        let state = test_state();
        let wmac = [1, 2, 3, 4, 5, 6];
        let smac = [9, 8, 7, 6, 5, 4];
        let wmac_s = device::mac_to_str(wmac);
        let smac_s = device::mac_to_str(smac);

        // Without a live session the lifecycle endpoints report 404.
        assert_eq!(
            post_empty(state.clone(), &format!("/api/devices/{wmac_s}/reset")).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post_empty(state.clone(), &format!("/api/devices/{wmac_s}/disable")).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post_empty(
                state.clone(),
                &format!("/api/devices/{wmac_s}/stations/{smac_s}/disconnect")
            )
            .await,
            StatusCode::NOT_FOUND
        );

        // Register a live session and an associated station.
        let (tx, mut rx) = mpsc::channel(8);
        state.wtp_cmd.register(wmac, tx);
        state
            .stations
            .upsert(wmac, smac, 1, 1, "associated", None, None, None)
            .unwrap();

        assert_eq!(
            post_empty(state.clone(), &format!("/api/devices/{wmac_s}/reset")).await,
            StatusCode::OK
        );
        assert_eq!(rx.recv().await, Some(WtpCmd::Reset));

        assert_eq!(
            post_empty(
                state.clone(),
                &format!("/api/devices/{wmac_s}/stations/{smac_s}/disconnect")
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(rx.recv().await, Some(WtpCmd::ReleaseClient(smac)));
    }

    #[tokio::test]
    async fn device_list_and_metadata_update() {
        let state = test_state();
        state
            .devices
            .register(
                [1, 2, 3, 4, 5, 6],
                Some("10.0.0.9"),
                Some("v1"),
                None,
                None,
                "discovery",
            )
            .unwrap();
        let app = router(state.clone());

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let devs: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0]["mac"], "01:02:03:04:05:06");

        let body = serde_json::json!({"name":"Hall-AP","description":"lobby"}).to_string();
        let res = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/devices/01:02:03:04:05:06")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let d = state.devices.get([1, 2, 3, 4, 5, 6]).unwrap().unwrap();
        assert_eq!(d.name, "Hall-AP");
        assert_eq!(d.description, "lobby");
    }

    #[tokio::test]
    async fn radio_wlan_set_and_list() {
        let state = test_state();
        let mac = device::mac_to_str([1, 2, 3, 4, 5, 6]);
        let body = serde_json::json!({
            "radio_id": 1,
            "ssid": "minimac",
            "akm": "psk-sae",
            "cipher": "ccmp",
            "psk": "person0finterest"
        })
        .to_string();
        let app = router(state.clone());
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/devices/{mac}/wlans"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let wlans = state.radios.list_wlans([1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(wlans.len(), 1);
        assert_eq!(wlans[0].ssid, "minimac");
        assert_eq!(wlans[0].security.akm, Akm::PskSae);
        assert_eq!(wlans[0].security.cipher, Cipher::Ccmp);
        assert_eq!(wlans[0].security.pmf, Pmf::Disabled);
        assert_eq!(wlans[0].security.psk.as_deref(), Some("person0finterest"));
        // Omitted record fields fall back to the DB defaults: record up,
        // SSID visible, no isolation/limit/vlan/rekey.
        assert_eq!(wlans[0].wlan_enable, true);
        assert_eq!(wlans[0].isolate, false);
        assert_eq!(wlans[0].broadcast, true);
        assert_eq!(wlans[0].client_count, 0);
        assert_eq!(wlans[0].vlan_id, 0);
        assert_eq!(wlans[0].rekey_period, 0);
        // Invalid key-management is rejected.
        let bad = serde_json::json!({
            "radio_id": 2,
            "ssid": "x",
            "akm": "wep-64",
            "psk": "person0finterest"
        })
        .to_string();
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/devices/{mac}/wlans"))
                    .header("content-type", "application/json")
                    .body(Body::from(bad))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn config_update_queues_into_live_session() {
        let state = test_state();
        let mac = [1, 2, 3, 4, 5, 6];
        let macs = device::mac_to_str(mac);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        state.cfg_update.register(mac, tx);
        state
            .devices
            .register(mac, Some("10.0.0.1"), None, None, None, "Run")
            .unwrap();

        let body = serde_json::json!({
            "elements": [
                { "type": "led", "value": 1 },
                { "type": "telnet", "value": 0 },
                { "type": "ap_name", "name": "WTP-1" },
                { "type": "channel", "radio": 1, "channel": 36 }
            ]
        })
        .to_string();
        let app = router(state.clone());
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/devices/{macs}/config-update"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        match rx.recv().await {
            Some(ConfigUpdateCmd::Push { elems }) => assert_eq!(
                elems,
                vec![
                    ConfigUpdateElem::Led(1),
                    ConfigUpdateElem::Telnet(0),
                    ConfigUpdateElem::ApName(b"WTP-1".to_vec()),
                    ConfigUpdateElem::Channel { radio: 1, channel: 36 },
                ]
            ),
            _ => panic!("expected a queued Push command"),
        }
        // The LED value is also remembered as the device's setting.
        assert_eq!(state.devices.get(mac).unwrap().unwrap().led_on, Some(true));

        // A WTP with no live session still remembers an LED setting, applied on
        // its next join; any other push needs the live session.
        let offline = device::mac_from_str("0a:0b:0c:0d:0e:0f").unwrap();
        state
            .devices
            .register(offline, None, None, None, None, "unknown")
            .unwrap();
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/devices/0a:0b:0c:0d:0e:0f/config-update")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "elements": [{ "type": "led", "value": 0 }] })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            state.devices.get(offline).unwrap().unwrap().led_on,
            Some(false)
        );
    }

    async fn put_json(
        app: &Router,
        uri: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn wcfg_global_override_and_commit() {
        let state = test_state();
        let mac = [1, 2, 3, 4, 5, 6];
        let s = device::mac_to_str(mac);
        state
            .devices
            .register(mac, Some("10.0.0.9"), None, None, None, "discovery")
            .unwrap();
        state.devices.approve(mac).unwrap();
        let app = router(state.clone());

        // Global 2.4G radio: manual channel 6, power 2.
        let res = put_json(&app, "/api/wcfg/global/radio/1", serde_json::json!({
            "channel_mode": 1, "channel": 6, "power": 2
        }))
        .await;
        assert_eq!(res.status(), StatusCode::OK);

        // Global 2.4G SSID, materialized into the approved AP.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/wcfg/global/wlan")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "band": 1, "wlan_id": 1, "ssid": "corp",
                            "akm": "psk", "cipher": "ccmp", "psk": "passphrase0"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let wlans = state.radios.list_wlans(mac).unwrap();
        // 2.4G: the posted "corp"; 5G: the initialization-default SSID.
        assert_eq!(wlans.len(), 2);
        assert_eq!(wlans[0].ssid, "corp");
        assert_eq!(wlans[0].radio_id, 1);
        assert_eq!(wlans.iter().filter(|w| w.radio_id == 2).count(), 1);
        assert!(state.wcfg.is_pending(mac).unwrap());

        // Per-AP power override wins over the global value.
        let res = put_json(
            &app,
            &format!("/api/wcfg/override/{s}/1"),
            serde_json::json!({ "channel": null, "power": 9, "mode": null }),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        let e = state.wcfg.effective_radio(mac, 1).unwrap();
        assert_eq!(e.power, 9);
        assert_eq!(e.channel, 6); // channel still inherited from the global

        // The full config view reports the override and the pending entry.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/wcfg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["global_radios"].as_array().unwrap().len(), 2);
        // One seeded SSID per band plus the posted 2.4G one.
        assert_eq!(v["global_wlans"].as_array().unwrap().len(), 2);
        assert_eq!(v["overrides"].as_array().unwrap().len(), 1);
        assert_eq!(v["overrides"][0]["power"], 9);
        assert_eq!(v["pending"].as_array().unwrap().len(), 1);

        // Commit defaults to the pending set; no live session -> offline only.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/wcfg/commit")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let r: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(r["pushed"].as_array().unwrap().is_empty());
        assert_eq!(r["offline"].as_array().unwrap().len(), 1);

        // Clearing the override returns to the global template.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/wcfg/override/{s}/1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(state.wcfg.get_override(mac, 1).unwrap().is_none());
        assert_eq!(state.wcfg.effective_radio(mac, 1).unwrap().power, 2);
    }
}
