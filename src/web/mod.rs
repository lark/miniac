//! Web management plane (M7): HTTP/REST API plus an embedded management frontend.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Exposes AP/radio/station/security/firmware views and the management event
//! stream, running alongside the CAPWAP UDP control channel. Store models keep
//! their own (MAC-as-`[u8;6]`) types; handlers map results to lightweight
//! `serde` DTOs here so no `Serialize` derive leaks into the data layer.

use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::device::{self, DeviceStore};
use crate::firmware::{FirmwareStore, UpgradeCmd, UpgradeRegistry};
use crate::logx;
use crate::radio::RadioStore;
use crate::security::ProfileStore;
use crate::station::StationStore;

/// Shared store handles handed to every handler via axum state.
#[derive(Clone)]
pub struct AppData {
    pub devices: Arc<DeviceStore>,
    pub radios: Arc<RadioStore>,
    pub stations: Arc<StationStore>,
    pub profiles: Arc<ProfileStore>,
    pub fw: Arc<FirmwareStore>,
    pub upgrade: Arc<UpgradeRegistry>,
}

impl AppData {
    pub fn new(
        devices: Arc<DeviceStore>,
        radios: Arc<RadioStore>,
        stations: Arc<StationStore>,
        profiles: Arc<ProfileStore>,
        fw: Arc<FirmwareStore>,
        upgrade: Arc<UpgradeRegistry>,
    ) -> Self {
        AppData {
            devices,
            radios,
            stations,
            profiles,
            fw,
            upgrade,
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
        .route("/api/stations", get(list_stations))
        .route("/api/profiles", get(list_profiles).post(create_profile))
        .route("/api/firmware", get(list_firmware).post(upload_firmware))
        .route("/api/devices/{mac}/upgrade", post(trigger_upgrade))
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
}

impl From<&device::Device> for DeviceDto {
    fn from(d: &device::Device) -> Self {
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
    ts_unix: u64,
    category: &'static str,
    level: &'static str,
    message: String,
}

impl From<logx::MgmtEvent> for EventDto {
    fn from(e: logx::MgmtEvent) -> Self {
        EventDto {
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
    let mut out: Vec<DeviceDto> = st.devices.list()?.iter().map(DeviceDto::from).collect();
    out.sort_by(|a, b| a.mac.cmp(&b.mac));
    Ok(Json(out))
}

async fn get_device(
    State(st): State<Arc<AppData>>,
    Path(mac): Path<String>,
) -> Result<Json<DeviceDto>, ApiError> {
    let mac = device::mac_from_str(&mac).map_err(ApiError::from)?;
    match st.devices.get(mac)? {
        Some(d) => Ok(Json((&d).into())),
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
        Some(d) => Ok(Json((&d).into())),
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
        Some(d) => Ok(Json((&d).into())),
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

async fn list_events() -> Result<Json<Vec<EventDto>>, ApiError> {
    Ok(Json(
        logx::drain().into_iter().map(EventDto::from).collect(),
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

/// Spawn the HTTP service bound to `addr` sharing `state`; returns on bind error.
pub async fn serve(state: Arc<AppData>, addr: String) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let app = router(state);
    logx::admin(format!("web management plane listening on http://{addr}"));
    axum::serve(listener, app).await?;
    Ok(())
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
        ))
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
}
