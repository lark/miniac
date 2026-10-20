//! CAPWAP Access Controller entrypoint: UDP/DTLS session dispatch and device orchestration.
//!
//! Copyright (c) 2026  Wang Jian

mod capwap;
mod config;
mod connection;
mod db;
mod device;
mod dtls_local;
mod dump;
mod elements;
mod firmware;
mod fleet;
mod logx;
mod radio;
mod roaming;
mod security;
mod stage1;
mod station;
mod vendor;
mod wcfg;
mod web;
mod wtpcmd;

use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, warn};

use capwap::{CtrlMsg, CwElem, MsgElemType, MsgType, WtpContext, WtpState};
use elements::BaseElem;

const CTRL_PORT: u16 = 5246;
const HTTP_DEFAULT_PORT: &str = "8080";

/// Image name carried by a Reset Request's Image Identifier on the RFC and
/// TP-Link paths (AC100 names its own software version there). H3C ignores it:
/// its reset requests carry the fixed `all_version` image identifier.
const RESET_IMAGE_NAME: &[u8] = b"all_version";

/// How long to wait for the WTP's reply to a serialized vendor push frame
/// before releasing the next one (`WtpContext::push_queue`). AC100's own pacing
/// is ~2.3s; this leaves margin for a slower WTP without stalling the push.
const PUSH_REPLY_TIMEOUT: Duration = Duration::from_secs(12);

/// Framing used for a session's control messages. It is the detected profile of
/// the peer's device, so several vendors' WTPs can share one miniac.
fn frame(profile: vendor::profile::VendorProfile) -> vendor::framing::CtrlFrame {
    profile.frame()
}

/// Whether an inbound datagram is a DTLS record for a session on the control
/// port. RFC 5415 §4.1/§4.2 prefix every DTLS-carried CAPWAP datagram with the
/// 4-byte CAPWAP DTLS Header, whose first byte is 1 (Preamble Version 0, Type 1
/// = DTLS). Clear-text CAPWAP uses Preamble Type 0, i.e. a first byte of 0.
fn is_dtls_frame(pkt: &[u8]) -> bool {
    pkt.first() == Some(&1)
}

/// Whether a datagram opens a new DTLS handshake: after the 4-byte CAPWAP DTLS
/// header, a handshake record (content type 22) whose first message is a
/// ClientHello (type 1).
fn is_dtls_client_hello(pkt: &[u8]) -> bool {
    is_dtls_frame(pkt) && pkt.get(4) == Some(&22) && pkt.get(17) == Some(&1)
}

/// Command-line settings: `-a` (repeatable) names the CAPWAP control bind
/// addresses (the control port 5246 is fixed by RFC 5415), `-l` gives the
/// web/API listen address (`ip[:port]` or `:port`), and `-D <file>` enables
/// plaintext control-message dumping for offline replay analysis.
struct Cli {
    control_ips: Vec<String>,
    http_listen: Option<String>,
    dump_file: Option<String>,
}

/// Value picked up from `-a` / `-l` / `-D` flags. Unknown flags are ignored.
/// With no `-a`, the control plane defaults to all interfaces (0.0.0.0).
fn parse_cli() -> Cli {
    let mut cli = Cli {
        control_ips: Vec::new(),
        http_listen: None,
        dump_file: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-a" => {
                if let Some(addr) = args.next() {
                    cli.control_ips.push(addr);
                }
            }
            "-l" => {
                if let Some(addr) = args.next() {
                    cli.http_listen = Some(addr);
                }
            }
            "-D" => {
                if let Some(path) = args.next() {
                    cli.dump_file = Some(path);
                }
            }
            _ => {}
        }
    }
    if cli.control_ips.is_empty() {
        cli.control_ips.push("0.0.0.0".to_string());
    }
    cli
}

/// Resolve the final `host:port` listen address for the web/API service from
/// the `-l` argument, falling back to `MINIAC_HTTP_PORT` and then the default
/// port bound to all interfaces.
fn resolve_http_addr(listen: Option<String>) -> String {
    let default_port =
        std::env::var("MINIAC_HTTP_PORT").unwrap_or_else(|_| HTTP_DEFAULT_PORT.to_string());
    let Some(listen) = listen else {
        return format!("0.0.0.0:{default_port}");
    };
    if let Some(rest) = listen.strip_prefix(':') {
        let port = if rest.is_empty() { &default_port } else { rest };
        return format!("0.0.0.0:{port}");
    }
    match listen.rfind(':') {
        Some(idx) => {
            let (host, rest) = listen.split_at(idx);
            let port = if rest.len() <= 1 {
                &default_port
            } else {
                &rest[1..]
            };
            format!("{host}:{port}")
        }
        None => format!("{listen}:{default_port}"),
    }
}

/// Parse the optional `MINIAC_WTP_NET` override (`a.b.c.d/prefix`) into a
/// network base and prefix length, defaulting to 192.168.0.0/24.
fn wtp_net_from_env() -> (std::net::Ipv4Addr, u8) {
    let default = (std::net::Ipv4Addr::new(192, 168, 0, 0), 24u8);
    let Some(v) = std::env::var("MINIAC_WTP_NET").ok() else {
        return default;
    };
    let (ip, prefix) = match v.rsplit_once('/') {
        Some((ip, p)) => (ip, p.parse().unwrap_or(24)),
        None => (v.as_str(), 24),
    };
    let base: std::net::Ipv4Addr = ip.parse().unwrap_or(default.0);
    (base, prefix)
}

/// Add a host offset to an IPv4 address (u32 host order).
fn add_ip(ip: std::net::Ipv4Addr, delta: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(u32::from(ip).wrapping_add(delta))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Honor RUST_LOG (e.g. RUST_LOG=debug) for runtime message-level tracing.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = parse_cli();

    if let Some(dump_path) = &cli.dump_file {
        dump::open(dump_path)?;
        info!("[*] plaintext control dump -> {dump_path}");
    }

    // One DTLS identity per vendor profile: the detected device profile picks
    // the certificate directory (and whether the client certificate is pinned).
    let dtls_configs: Arc<HashMap<vendor::profile::VendorProfile, Arc<rtc_dtls::config::HandshakeConfig>>> = {
        use vendor::profile::VendorProfile;
        let mut m = HashMap::new();
        for p in [VendorProfile::H3c, VendorProfile::TpLink, VendorProfile::Rfc] {
            m.insert(p, generate_dtls_config(p)?);
        }
        Arc::new(m)
    };

    // Peer IP -> profile detected from the device's Discovery/Join Request. Keyed
    // by IP, not the full socket address: some WTPs (TP-Link TL-AP1300GI, H3C
    // AX60) start DTLS from a different source port than their Discovery, so a
    // port-keyed map would miss and misdetect the profile at DTLS time.
    let peer_profiles: Arc<Mutex<HashMap<IpAddr, vendor::profile::VendorProfile>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let dispatcher_map: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let db = Arc::new(db::Db::open("miniac.db")?);
    let devices = Arc::new(device::DeviceStore::new(db.clone()));
    let radios = Arc::new(radio::RadioStore::new(db.clone()));
    let stations = Arc::new(station::StationStore::new(db.clone()));
    let profiles = Arc::new(security::ProfileStore::new(db.clone())); // 802.1X / RSN policy store
    let fw = Arc::new(firmware::FirmwareStore::with_root(db.clone(), "firmware")); // image catalog + upgrade audit
    std::fs::create_dir_all("firmware")?;
    let upgrade_reg = Arc::new(firmware::UpgradeRegistry::new()); // web -> live-session firmware trigger
    let cfg_update_reg = Arc::new(config::ConfigUpdateRegistry::new()); // web -> live-session config-update trigger
    let wtp_cmd_reg = Arc::new(wtpcmd::WtpCmdRegistry::new()); // web -> live-session reset/disable/release-client trigger
    let wcfg = Arc::new(wcfg::WirelessConfigStore::new(db.clone())); // global wireless config + overrides + pending set
    let caps = Arc::new(fleet::ProductCapsStore::new(db.clone())); // product capability registry for the security recommender
    info!("[*] persistence ready (miniac.db)");
    logx::system("persistence initialized (miniac.db)".to_string());

    // M7: web management plane (REST + embedded frontend), shared store handles.
    // Listen address from `-l ip[:port]` / `-l :port`, else $MINIAC_HTTP_PORT, else 0.0.0.0:8080.
    let http_addr = resolve_http_addr(cli.http_listen);
    let web_state = std::sync::Arc::new(web::AppData::new(
        devices.clone(),
        radios.clone(),
        stations.clone(),
        profiles.clone(),
        fw.clone(),
        upgrade_reg.clone(),
        cfg_update_reg.clone(),
        wtp_cmd_reg.clone(),
        wcfg.clone(),
        caps.clone(),
    ));
    tokio::spawn(web::serve(web_state, http_addr));

    // M8: H3C FIT-AP stage-1 discovery responder. The WTP leases its own IP,
    // gateway and the AC IP (DHCP-like) over the private port 10087 before it
    // starts CAPWAP unicast on 5246. The allocatable pool defaults to
    // 192.168.0.50..192.168.0.80 (persisted in miniac.db); the base/prefix is
    // overridable via MINIAC_WTP_NET (e.g. 10.0.0.0/24).
    let stage_bind = format!("0.0.0.0:{}", stage1::STAGE1_PORT);
    {
        let (base, prefix) = wtp_net_from_env();
        let gateway = add_ip(base, 1);
        let ac_ip = add_ip(base, 2);
        // The AC IP and gateway are the WTP's stage-1 DHCP-like lease fields; on
        // real hardware they must equal miniac's own address / the network
        // gateway on the WTP subnet, so override them via the environment when
        // they differ from the base+2 / base+1 defaults.
        let gateway = std::env::var("MINIAC_WTP_GW")
            .ok()
            .and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
            .unwrap_or(gateway);
        let ac_ip = std::env::var("MINIAC_WTP_AC")
            .ok()
            .and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
            .unwrap_or(ac_ip);
        // The pool defaults to base+50..base+80; override the bounds individually
        // (MINIAC_WTP_POOL_START / MINIAC_WTP_POOL_END) so a site with a fixed,
        // small range can be pinned without shifting the network base.
        let pool_ip = |key: &str, default: std::net::Ipv4Addr| {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
                .unwrap_or(default)
        };
        let pool_start = pool_ip("MINIAC_WTP_POOL_START", add_ip(base, 50));
        let pool_end = pool_ip("MINIAC_WTP_POOL_END", add_ip(base, 80));
        let netmask = std::net::Ipv4Addr::from(0xffff_ffffu32 << (32 - prefix));
        let pool = std::sync::Arc::new(stage1::AcPool::prefill(
            db.clone(),
            pool_start,
            pool_end,
            gateway,
            netmask,
            ac_ip,
        )?);
        info!(
            "[*] stage-1 pool {}-{} gw {} ac {}",
            pool_start, pool_end, gateway, ac_ip
        );
        let sb = stage_bind.clone();
        tokio::spawn(async move {
            if let Err(e) = stage1::serve(&sb, pool).await {
                error!("stage-1 discovery server: {e}");
            }
        });
    }

    // CAPWAP control plane: one UDP socket per `-a` address (RFC 5415 control
    // port is fixed at 5246; only the bind address is configurable).
    let mut control_tasks = Vec::new();
    for ip in cli.control_ips {
        let ctrl = format!("{ip}:{CTRL_PORT}");
        let socket = Arc::new(UdpSocket::bind(&ctrl).await?);
        info!("[!] miniac control listening on {ctrl}");
        logx::system(format!("AC control listening on {ctrl}"));
        control_tasks.push(tokio::spawn(run_control_socket(
            socket,
            dispatcher_map.clone(),
            peer_profiles.clone(),
            dtls_configs.clone(),
            devices.clone(),
            radios.clone(),
            stations.clone(),
            fw.clone(),
            upgrade_reg.clone(),
            cfg_update_reg.clone(),
            wtp_cmd_reg.clone(),
            wcfg.clone(),
        )));
    }

    for task in control_tasks {
        task.await
            .map_err(|e| anyhow!("control task join: {e}"))??;
    }
    Ok(())
}

/// Per-address CAPWAP control dispatch loop: match in-progress sessions by
/// peer, answer Discovery Request, and hand off new DTLS hellos to a fresh
/// session thread.
async fn run_control_socket(
    socket: Arc<UdpSocket>,
    dispatcher_map: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    peer_profiles: Arc<Mutex<HashMap<IpAddr, vendor::profile::VendorProfile>>>,
    dtls_configs: Arc<HashMap<vendor::profile::VendorProfile, Arc<rtc_dtls::config::HandshakeConfig>>>,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    upgrade_reg: Arc<firmware::UpgradeRegistry>,
    cfg_update_reg: Arc<config::ConfigUpdateRegistry>,
    wtp_cmd_reg: Arc<wtpcmd::WtpCmdRegistry>,
    wcfg: Arc<wcfg::WirelessConfigStore>,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();
        use vendor::profile::VendorProfile;

        // Profile already detected for this peer's device, if any (in-session
        // traffic and DTLS handshakes reuse it, even from a new source port).
        let known_profile = {
            let map = peer_profiles.lock().await;
            map.get(&peer.ip()).copied()
        };

        let tx = {
            let map = dispatcher_map.lock().await;
            map.get(&peer).cloned()
        };

        if let Some(tx) = tx {
            // A restarted peer begins again with a plaintext Discovery Request;
            // from a live address that means its old session is gone, so drop it
            // and answer. Anything else belongs to the live session.
            if pkt.get(0) == Some(&0) && pkt.get(11) == Some(&1) {
                info!("[<] from {}: Discovery Request on a live address, replacing session", peer);
                dispatcher_map.lock().await.remove(&peer);
                // fall through to answer the Discovery
            } else {
                if is_dtls_frame(&pkt) {
                    let _ = tx.try_send(pkt);
                }
                continue;
            }
        }

        // 3. New Discovery
        if pkt.get(0) == Some(&0) {
            if pkt.get(11) == Some(&1) {
                // MsgType: 1 (Discovery Request)
                info!("[<] from {}: disc req", peer);

                // The profile is detected from the device's own Discovery
                // Request; an operator override (`MINIAC_VENDOR`) wins.
                let prof =
                    VendorProfile::forced().unwrap_or_else(|| VendorProfile::detect(&pkt));
                peer_profiles.lock().await.insert(peer.ip(), prof);

                // The AC advertises its own control address (AC IPv4 List) so
                // the WTP knows which destination to start DTLS/Join against.
                // Prefer the operator override, else the bound interface IP,
                // else the stage-1 default.
                let ac_ip = std::env::var("MINIAC_WTP_AC")
                    .ok()
                    .and_then(|v| v.parse::<Ipv4Addr>().ok())
                    .or_else(|| {
                        socket.local_addr().ok().and_then(|a| match a.ip() {
                            IpAddr::V4(v) if !v.is_unspecified() => Some(v),
                            _ => None,
                        })
                    })
                    .unwrap_or(Ipv4Addr::new(192, 168, 0, 2));
                match prof.discovery_response(&pkt, ac_ip, b"My AC") {
                    Some(resp) => {
                        logx::device(format!("Discovery response to {} ({}B)", peer, resp.len()));
                        socket.send_to(&resp, peer).await?;
                    }
                    None => warn!(
                        "[?] disc req from {} not {:?}-framed, dropped",
                        peer, prof
                    ),
                }
            }
        }

        // A fresh DTLS hello: reuse the profile detected at Discovery for this
        // peer's address (WTPs often start DTLS from a new source port), else the
        // operator override. A ClientHello carries no vendor information, so an
        // unknown peer falls back to the vendor-neutral RFC profile until a
        // Discovery refines it.
        let prof = VendorProfile::forced().or(known_profile).unwrap_or_default();
        if is_dtls_frame(&pkt) {
            if !is_dtls_client_hello(&pkt) {
                // Application data for a session we do not have (e.g. after an AC
                // restart). No DTLS state to feed it into, so drop it; the peer
                // re-discovers after its own timeout.
                debug!("[<] from {}: dtls frame for unknown session, dropped", peer);
                continue;
            }
            info!("[<] from {}: direct dtls hello ({:?})", peer, prof);
            peer_profiles.lock().await.insert(peer.ip(), prof);
            let config = dtls_configs
                .get(&prof)
                .cloned()
                .unwrap_or_else(|| dtls_configs[&VendorProfile::Rfc].clone());
            let tx = start_new_session(
                peer,
                prof,
                &dispatcher_map,
                &socket,
                &config,
                devices.clone(),
                radios.clone(),
                stations.clone(),
                fw.clone(),
                upgrade_reg.clone(),
                cfg_update_reg.clone(),
                wtp_cmd_reg.clone(),
                wcfg.clone(),
            )
            .await;
            let _ = tx.send(pkt).await;
            continue;
        }
    }
}

/// Device identifier (board MAC) of a WTP that is joining.
///
/// The RFC path reads the WTP Board Data element (38) as RFC 5415 4.6.40
/// defines it - a vendor identifier followed by board data sub-elements - and
/// takes the Base MAC Address sub-element (type 4). Vendors that do not report
/// the MAC there are consulted first through their own module, so the RFC path
/// stays protocol-conformant.
fn wtp_mac_from_elems(
    elems: &HashMap<u16, Vec<CwElem>>,
    profile: vendor::profile::VendorProfile,
) -> Option<device::Mac> {
    use vendor::profile::VendorProfile;
    if profile == VendorProfile::H3c {
        if let Some(mac) = vendor::h3c::wtp_mac(elems) {
            return Some(mac);
        }
    }
    match elems.get(&MsgElemType::WTP_BOARD_DATA).and_then(|v| v.first()) {
        Some(CwElem::Unknown(_, body)) => elements::WtpBoardData::decode(body)?.base_mac(),
        _ => None,
    }
}

/// WTP model string from the WTP Board Data model number (RFC 5415 §4.6.40
/// sub-element 0). WTPs report it either as a NUL-padded text name (H3C
/// "SWBA1B0") or as a binary model code, which is rendered as hex.
fn wtp_model_from_elems(elems: &HashMap<u16, Vec<CwElem>>) -> Option<String> {
    let Some(CwElem::Unknown(_, body)) =
        elems.get(&MsgElemType::WTP_BOARD_DATA).and_then(|v| v.first())
    else {
        return None;
    };
    let board = elements::WtpBoardData::decode(body)?;
    let value = board
        .sub_elems
        .iter()
        .find(|(t, _)| *t == elements::board_data::MODEL_NUMBER)
        .map(|(_, v)| v.as_slice())?;
    Some(render_model(value))
}

/// Text when the model number is a printable, NUL-terminated string (H3C),
/// else the hexadecimal code the device reported (TP-Link).
fn render_model(value: &[u8]) -> String {
    let text: Vec<u8> = value.iter().copied().take_while(|b| *b != 0).collect();
    if !text.is_empty() && text.iter().all(|b| (0x20..0x7f).contains(b)) {
        String::from_utf8_lossy(&text).into_owned()
    } else {
        value.iter().map(|b| format!("{b:02x}")).collect()
    }
}

async fn start_new_session(
    peer: SocketAddr,
    profile: vendor::profile::VendorProfile,
    map: &Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    socket: &Arc<UdpSocket>,
    config: &Arc<rtc_dtls::config::HandshakeConfig>,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    upgrade: Arc<firmware::UpgradeRegistry>,
    cfg_update: Arc<config::ConfigUpdateRegistry>,
    wtp_cmd: Arc<wtpcmd::WtpCmdRegistry>,
    wcfg: Arc<wcfg::WirelessConfigStore>,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel(100);
    map.lock().await.insert(peer, tx.clone());

    let sock_clone = Arc::clone(socket);
    let conf_clone = Arc::clone(config);

    tokio::spawn(async move {
        info!("[*] with {}: session thread spawned ({:?})", peer, profile);
        if let Err(e) = handle_session(
            peer, profile, rx, sock_clone, conf_clone, devices, radios, stations, fw, upgrade,
            cfg_update, wtp_cmd, wcfg,
        )
        .await
        {
            warn!("[!] with {}: session end: {}", peer, e);
        }
    });

    tx
}

/// Build the ordered list of WLAN configurations to push to a WTP from its
/// per-radio store entries (`radio_wlans`). Auth type follows the security
/// policy: open networks use the legacy open-authentication byte, anything with
/// a PSK uses RSN.
fn configs_from_store(
    radios: &radio::RadioStore,
    mac: device::Mac,
) -> Result<Vec<config::WlanConfig>> {
    let mut out = Vec::new();
    for rw in radios.list_wlans_enabled(mac)? {
        let auth_type = rw.security.auth_type();
        out.push(config::WlanConfig {
            radio_id: rw.radio_id,
            wlan_id: rw.wlan_id,
            capability: 0x0001, // ESS
            qos: 0,
            auth_type,
            mac_mode: 0,
            tunnel_mode: 0,
            suppress_ssid: false,
            ssid: rw.ssid.clone().into_bytes(),
            security: rw.security.clone(),
            wlan_enable: rw.wlan_enable,
            isolate: rw.isolate,
            broadcast: rw.broadcast,
            client_count: rw.client_count,
            vlan_id: rw.vlan_id,
            rekey_period: rw.rekey_period,
        });
    }
    Ok(out)
}

/// Apply one TP-Link station report: upsert the reported stations and delete the
/// ones the radio no longer reports, since each report is its complete associated
/// set. Returns the change count so only real changes are logged.
fn apply_station_report(
    stations: &station::StationStore,
    wmac: device::Mac,
    rep: &vendor::tplink::StationReport,
) -> Result<usize> {
    let mut changed = 0;
    for st in &rep.stations {
        // The report carries the MAC and RSSI only, so the WLAN id is unknown (0)
        // and the SSID/IP are filled in later from other sources.
        if stations.upsert(
            wmac,
            st.mac,
            rep.radio_id,
            0,
            "associated",
            None,
            None,
            Some(st.rssi),
        )? {
            changed += 1;
        }
    }
    for st in stations.list_by_wtp(wmac)? {
        if st.radio_id == rep.radio_id && !rep.stations.iter().any(|r| r.mac == st.mac) {
            stations.delete(wmac, st.mac)?;
            changed += 1;
        }
    }
    Ok(changed)
}

async fn handle_session(
    peer: SocketAddr,
    profile: vendor::profile::VendorProfile,
    mut rx: mpsc::Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    config: Arc<rtc_dtls::config::HandshakeConfig>,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    upgrade: Arc<firmware::UpgradeRegistry>,
    cfg_update: Arc<config::ConfigUpdateRegistry>,
    wtp_cmd: Arc<wtpcmd::WtpCmdRegistry>,
    wcfg: Arc<wcfg::WirelessConfigStore>,
) -> Result<()> {
    let local_addr = socket.local_addr()?;
    let mut capdtls = connection::CapwapDtls::new(local_addr, peer, socket, config);
    let mut handshake_logged = false;

    // Vendor form for the configuration message families (Configuration Status
    // Response, Configuration Update Request, Reset Request, Clear
    // Configuration Request), detected from this device's Discovery/Join Request.
    if profile != vendor::profile::VendorProfile::H3c {
        info!("[!] with {}: vendor profile {:?} active", peer, profile);
    }

    let mut ctx = WtpContext::new(peer);
    // Session-scoped state for configuration push-down tracking and the
    // firmware Image Data transfer exchange.
    let mut cfg_status = config::ConfigStatus::new();
    let mut fw_upgrade = firmware::FirmwareUpgrade::new();
    let mut fw_record_id: Option<i64> = None;
    // Management-plane firmware trigger: the web/API layer pushes an UpgradeCmd
    // keyed by WTP MAC (via `upgrade`); we register after the join identifies
    // the MAC and act on a Start command by running the Image Data download.
    let (upgrade_tx, mut upgrade_rx) = mpsc::channel::<firmware::UpgradeCmd>(8);
    // Management-plane configuration trigger: the web/API layer pushes a
    // ConfigUpdateCmd keyed by WTP MAC; we register after the join identifies the
    // MAC and act on a Push command by sending a Configuration Update Request.
    let (cfg_update_tx, mut cfg_update_rx) = mpsc::channel::<config::ConfigUpdateCmd>(8);
    // Management-plane WTP command trigger (Reset / Disable / ReleaseClient),
    // registered after the join identifies the MAC.
    let (wtp_cmd_tx, mut wtp_cmd_rx) = mpsc::channel::<wtpcmd::WtpCmd>(8);
    // UI-issued command awaiting its WTP response; a firmware-driven reset is
    // tracked separately by `fw_upgrade`/`fw_record_id`.
    let mut pending_cmd: Option<wtpcmd::WtpCmd> = None;
    // WLANs the WTP reports already holding (TP-Link private 30).
    let mut wtp_saved_wlans: Option<Vec<vendor::tplink::SavedWlan>> = None;

    loop {
        let retrans_duration = ctx
            .last_sent
            .as_ref()
            .filter(|last| MsgType::is_request(last.msg_type))
            .map(|last| {
                ctx.retrans_interval_for(last.retry_count)
                    .saturating_sub(last.send_time.elapsed())
            })
            .unwrap_or(Duration::from_secs(60));
        let idle_duration = ctx.echo_interval.saturating_sub(ctx.last_seen.elapsed());
        // Also wake in time to send the next keep-alive Echo Request in Run state.
        let next_echo = ctx.echo_interval.saturating_sub(ctx.last_echo_sent.elapsed());
        // Also wake in time to release the next serialized vendor push frame if
        // the WTP's reply does not arrive.
        let next_push = if ctx.push_queue.is_empty() {
            Duration::from_secs(60)
        } else {
            ctx.push_last_sent
                .map_or(Duration::ZERO, |t| PUSH_REPLY_TIMEOUT.saturating_sub(t.elapsed()))
        };
        let mut sleep_duration = std::cmp::min(
            retrans_duration,
            std::cmp::min(idle_duration, std::cmp::min(next_echo, next_push)),
        );
        // Keep the DTLS retransmit timer ahead of the sleep, so handshake
        // flights are resent even while no CAPWAP message is due.
        if let Some(t) = capdtls.next_timeout() {
            sleep_duration = sleep_duration.min(t.saturating_duration_since(Instant::now()));
        }
        if sleep_duration.is_zero() {
            sleep_duration = Duration::from_millis(1);
        }

        // RFC 5415 4.5.3: one Request at a time. The management triggers below
        // are gated so a new Request waits for the pending one's Response.
        let outstanding = ctx.has_outstanding_request();

        tokio::select! {
            maybe_pkt = rx.recv() => {
                // Channel closed: the dispatcher replaced this session.
                let Some(pkt) = maybe_pkt else {
                    info!("[*] with {}: session channel closed, ending", peer);
                    return Ok(());
                };
                let app_datas = capdtls.feed(&pkt).await?;
                if capdtls.handshake_complete() && !handshake_logged {
                    handshake_logged = true;
                    info!("[!] with {}: dtls handshake done", peer);
                }
                for app_data in app_datas {
                    let n = app_data.len();
                    if n < 16 { continue }
                    ctx.keep_alive();

                    let msg = match CtrlMsg::decode(frame(profile), &app_data[8..n]) {
                        Ok(m) => m,
                        // A frame below the control-header minimum is not fatal:
                        // logging and carrying on keeps the session (and its
                        // applied config) alive instead of tearing the control
                        // channel down. Zero-element keepalives (the 19B ECHO_REQ)
                        // decode cleanly through parse_hdr.
                        Err(e) => {
                            warn!("[?] ctrl decode: {e} ({n}B); keep session");
                            continue;
                        }
                    };
                    debug!("[?] ctrl payload:\n{:?}", &app_data[8..n]);
                    let seq = msg.hdr.seq_num;
                    let m_type = msg.hdr.msg_type;

                    // Elements begin after the 8-byte base header plus the framed
                    // control header (RFC: 16; H3C: 19).
                    let elem_off = 8 + frame(profile).elem_off();
                    let ac_ip = std::env::var("MINIAC_WTP_AC")
                        .ok()
                        .and_then(|v| v.parse::<Ipv4Addr>().ok())
                        .or_else(|| match local_addr.ip() {
                            IpAddr::V4(v) if !v.is_unspecified() => Some(v),
                            _ => None,
                        })
                        .unwrap_or(Ipv4Addr::new(192, 168, 0, 2));
                    let elems = if let Some(schema) = capwap::MSG_SCHEMAS.get(&m_type) {
                        // Lenient: H3C AX60 packs many vendor/extra elements
                        // (30, and private IDs 45-131) that the RFC schema does
                        // not declare; unknown ones are kept as `Unknown`.
                        match schema.validate_lenient(m_type, &app_data[elem_off..n]) {
                            Ok(e) => e,
                            Err(e) => {
                                error!("[!] from {}: validation failed: {}", peer, e);
                                // A Response carrying an error code could be sent back to the WTP here.
                                continue;
                            }
                        }
                    } else {
                        debug!("[?] from {}: unknown msg type {}", peer, m_type);
                        continue;
                    };

                    // RFC 5415 4.5.3: replay the cached Response for a repeated
                    // Request, ignore an older one, process a newer one. Ordering
                    // is over the framing's counter width (RFC 256, H3C 2^32).
                    if MsgType::is_request(m_type) {
                        if let Some(last) = ctx.last_req_seq {
                            if seq == last {
                                match ctx.last_resp_buf.clone() {
                                    Some(buf) => {
                                        info!("[<] from {}: duplicate request (seq {}), replaying cached response", peer, seq);
                                        capdtls.write(&buf).await?;
                                    }
                                    None => debug!("[<] from {}: duplicate request (seq {}) with no cached response", peer, seq),
                                }
                                continue;
                            }
                            if capwap::seq_is_older(seq, last, frame(profile)) {
                                info!("[<] from {}: stale request (seq {} older than {}), ignored", peer, seq, last);
                                continue;
                            }
                        }
                        ctx.last_req_seq = Some(seq);
                        ctx.last_resp_buf = None;
                    }

                    // RFC 5415 4.5.3: record each Response as handled, so its
                    // retransmission does not re-run the state machine.
                    if MsgType::is_response(m_type) {
                        if ctx.last_resp_done == Some((seq, m_type)) {
                            debug!("[<] from {}: duplicate response (seq {}), discarded", peer, seq);
                            continue;
                        }
                        ctx.last_resp_done = Some((seq, m_type));
                    }

                    if MsgType::is_response(m_type) {
                        if let Some(last) = ctx.last_sent.as_ref().filter(|l| l.seq == seq && MsgType::is_request(l.msg_type)) {
                            info!("[<] from {}: received response for {:?} (seq {})", peer, last.msg_type, seq);
                            // On success clear the pushed config tags from the
                            // outstanding set; on a non-zero Result Code keep them
                            // pending.
                            if last.msg_type == MsgType::CONFIG_UPDATE_REQ {
                                match vendor::h3c::ConfigUpdateResp::decode(&msg) {
                                    Ok(r) if r.is_success() => {
                                        cfg_status.mark_acked(cfg_status.pending().collect::<Vec<u16>>());
                                        info!("[<] from {}: configuration update acked", peer);
                                    }
                                    Ok(r) => warn!(
                                        "[!] from {}: configuration update rejected (result {})",
                                        peer, r.result_code
                                    ),
                                    Err(e) => warn!(
                                        "[!] from {}: configuration update response undecodable: {e}",
                                        peer
                                    ),
                                }
                            }
                            ctx.last_sent = None;
                        }
                    }

                    match (ctx.state, m_type) {
                        (WtpState::Join, MsgType::JOIN_REQ) => {
                            info!("[<] from {}: join req (seq {})", peer, seq);
                            let mut hw_ver: Option<String> = None;
                            let mut sw_ver: Option<String> = None;
                            if let Some(CwElem::WtpDescriptor { hardware, software }) = elems.get(&MsgElemType::WTP_DESCRIPTOR).and_then(|v| v.first()) {
                                info!("[*] wtp hw: {:08x}, sw: {:08x}", hardware, software);
                                ctx.hardware_version = *hardware;
                                ctx.software_version = *software;
                                hw_ver = Some(format!("{:08x}", hardware));
                                sw_ver = Some(format!("{:08x}", software));
                            }
                            // Persist device learned from the join exchange (keyed by MAC).
                            if let Some(mac) = wtp_mac_from_elems(&elems, profile) {
                                ctx.mac = Some(mac);
                                let ip = peer.ip().to_string();
                                let created = devices.register(mac, Some(&ip), sw_ver.as_deref(), None, None, "registered")?;
                                devices.set_identity(
                                    mac,
                                    Some(profile.vendor_name()),
                                    wtp_model_from_elems(&elems).as_deref(),
                                    hw_ver.as_deref(),
                                    None,
                                )?;
                                logx::device(format!(
                                    "WTP {} {} (ip {})",
                                    device::mac_to_str(mac),
                                    if created { "registered" } else { "seen" },
                                    ip,
                                ));
                                // First contact / unapproved WTPs are refused until
                                // the admin confirms them in the management UI; the
                                // WTP keeps retrying and joins once approved.
                                let approved = devices.get(mac)?.map(|d| d.approved).unwrap_or(false);
                                if !approved {
                                    let resp_msg = profile.join_response(seq, ac_ip, b"miniac", false);
                                    let resp_buf = resp_msg.encode_for(frame(profile));
                                    capdtls.write(&resp_buf).await?;
                                    logx::device(format!(
                                        "WTP {} refused: pending approval",
                                        device::mac_to_str(mac)
                                    ));
                                    return Ok(());
                                }
                                // Advertise this session so the web plane can
                                // trigger firmware upgrades for this WTP.
                                upgrade.register(mac, upgrade_tx.clone());
                                cfg_update.register(mac, cfg_update_tx.clone());
                                wtp_cmd.register(mac, wtp_cmd_tx.clone());
                            } else {
                                debug!("[*] join: no WTP Board Data MAC present");
                            }
                            // response
                            // The H3C join form keeps the AX60-specific element
                            // set (the tag-10 value must be the 6-byte AC IPv4
                            // entry; WTP.dis 0x23754 counts entries and re-parses
                            // each at 0x1df5c). The RFC / TP-Link form uses the
                            // standards-shaped builder.
                            let resp_msg = profile.join_response(seq, ac_ip, b"miniac", true);
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);

                            ctx.state = WtpState::Configure;
                            info!("[>] to {}: join resp sent, state -> Configure", peer);
                        }

                        (WtpState::Configure, MsgType::CONFIG_STATUS_REQ) => {
                            info!("[<] from {}: config status req (seq {})", peer, seq);
                            // Decode the WTP-reported name, radio operational states
                            // and declared radios (vendor::h3c::ConfigStatusReq). The
                            // AX60 reports each radio as admin_state=1 (Disabled) in
                            // its Config Status Request, and its apply chain silently
                            // skips WLAN/SSID config for radios that stay disabled --
                            // so the AC must turn them on by echoing a
                            // RADIO_ADMIN_STATE element with admin_state=0 before any
                            // per-radio WLAN config can take effect.
                            let req = vendor::h3c::ConfigStatusReq::parse(&msg);
                            if let Some(name) = &req.wtp_name {
                                ctx.name = name.clone();
                                info!("[*] WTP Name updated: {}", ctx.name);
                            }
                            for (radio_id, state) in &req.radio_op_states {
                                info!("[*] Radio ID: {}, Operational State: {}", radio_id, state);
                            }
                            let mut declared_radios = req.declared_radios;
                            if declared_radios.is_empty() {
                                info!("[*] no RADIO_ADMIN_STATE declared; assuming radios 0 and 1");
                                declared_radios.push((0, 1));
                                declared_radios.push((1, 1));
                            }

                            // TP-Link reports the WLANs it already holds (private
                            // 30) here; only TP-Link sends it.
                            if profile == vendor::profile::VendorProfile::TpLink {
                                wtp_saved_wlans = elems
                                    .get(&MsgElemType::VENDOR_SPECIFIC_PAYLOAD)
                                    .into_iter()
                                    .flatten()
                                    .filter_map(|e| match e {
                                        CwElem::Unknown(_, v) => vendor::vsp::split_value(v),
                                        _ => None,
                                    })
                                    .filter(|(vendor_id, _, _)| *vendor_id == vendor::tplink::VENDOR_ID)
                                    .find_map(|(_, _, tlvs)| {
                                        vendor::vsp::find(&tlvs, vendor::tplink::priv_id::WLAN_LIST)
                                            .and_then(vendor::tplink::parse_wlan_list)
                                    });
                                match &wtp_saved_wlans {
                                    Some(w) => info!(
                                        "[*] WTP {} holds {} saved WLAN(s): {}",
                                        peer,
                                        w.len(),
                                        w.iter().map(|s| format!("radio {}={}", s.radio_id, s.ssid)).collect::<Vec<_>>().join(", ")
                                    ),
                                    None => debug!("[*] WTP {} reported no saved WLAN list", peer),
                                }
                            }

                            let mac = ctx.mac.unwrap_or([0; 6]);
                            // On first contact with a WTP that carries no per-AP
                            // rows yet, seed them from the AC-wide global template
                            // so the Configure push reflects the global config;
                            // WTPs already carrying rows (materialized or legacy)
                            // are left as-is.
                            if radios.list_wlans(mac)?.is_empty() {
                                wcfg.materialize(&radios, mac)?;
                            }
                            // Build the WTP's WLAN list from the radio_wlans store,
                            // which `materialize` above seeded from the AC-wide
                            // global template (the initialization defaults live in
                            // the DB, so there is no hardcoded fallback here).
                            let wlans = configs_from_store(&*radios, mac)?;
                            if wlans.is_empty() {
                                anyhow::bail!(
                                    "no WLAN configuration for {} (global_wlan default missing)",
                                    device::mac_to_str(mac)
                                );
                            }
                            // Build the Config Status Response in the M60 AC's
                            // assembly order: [2][3][12][32][16][23][40][55] then
                            // one 0xfde8 per radio/WLAN. The full assembly lives
                            // in vendor::h3c::config_status_response.
                            let g24_hdr = radios.h3c_header(mac, 1)?;
                            let g5_hdr = radios.h3c_header(mac, 2)?;
                            // Advanced radio features (fe28 OFDMA/MU-MIMO, fe31
                            // band navigation): driven by env overrides until a
                            // DB source exists; all-zero or unset omits the
                            // element.
                            let ofdma = std::env::var("MINIAC_H3C_OFDMA")
                                .ok()
                                .and_then(|v| v.parse::<u32>().ok())
                                .unwrap_or(0);
                            let mumimo = std::env::var("MINIAC_H3C_MUMIMO")
                                .ok()
                                .and_then(|v| v.parse::<u32>().ok())
                                .unwrap_or(0);
                            let fe28 = if ofdma != 0 || mumimo != 0 {
                                Some((ofdma, mumimo))
                            } else {
                                None
                            };
                            let fe31 = std::env::var("MINIAC_H3C_LBD")
                                .ok()
                                .and_then(|v| v.parse::<u32>().ok())
                                .filter(|&v| v != 0);
                            let resp_msg = match profile {
                                // TP-Link WTPs accept only a narrow set of base
                                // element types here (2/3/12/16/23/32/37/40) and
                                // drop the whole message on anything else; the
                                // response carries no WLAN configuration. The
                                // form is built by vendor::tplink. The echo
                                // interval stays below miniac's 30s Run-state
                                // inbound deadline (see the builder's doc).
                                vendor::profile::VendorProfile::TpLink => {
                                    vendor::tplink::config_status_response(
                                        &vendor::tplink::ConfigStatusResp {
                                            seq,
                                            timers: (20, 20),
                                            ac_ip,
                                            ap_user: &[],
                                        },
                                    )
                                }
                                _ => vendor::h3c::config_status_response(
                                    &vendor::h3c::ConfigStatusResp {
                                        seq,
                                        ac_ip,
                                        peer,
                                        declared_radios: &declared_radios,
                                        wlans: &wlans,
                                        g24_hdr: &g24_hdr,
                                        g5_hdr: &g5_hdr,
                                        wtp_mac: ctx.mac,
                                        fe28,
                                        fe31,
                                    },
                                ),
                            };
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            cfg_status.mark_pushed([vendor::h3c::WLAN_CFG_H3C]);
                            // The TP-Link form carries no WLAN configuration, so
                            // the WLANs go out only in the later Run-entry push.
                            let resp_wlans = if profile == vendor::profile::VendorProfile::TpLink {
                                0
                            } else {
                                wlans.len()
                            };
                            logx::device(format!(
                                "pushed {} WLAN config(s) to {} in the config response",
                                resp_wlans,
                                peer
                            ));
                            info!(
                                "[>] to {}: config response with {} WLAN config(s) sent",
                                peer, resp_wlans
                            );

                            ctx.state = WtpState::DataCheck;
                            info!("[>] to {}: config resp sent, state -> DataCheck", peer);
                        }

                        (WtpState::DataCheck, MsgType::CHANGE_STATE_EV_REQ) => {
                            info!("[<] from {}: change state event req (seq {})", peer, seq);
                            if let Some(radio_states) = elems.get(&MsgElemType::RADIO_OP_STATE) {
                                for elem in radio_states {
                                    if let CwElem::RadioOp { radio_id, state } = elem {
                                        debug!("[*] radio {} state changed to {}", radio_id, state);
                                        // ctx.update_radio(*radio_id, *state);
                                    }
                                }
                            }
                            let resp_msg = CtrlMsg::new(MsgType::CHANGE_STATE_EV_RESP, seq);
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);

                            ctx.state = WtpState::Run;
                            info!("[>] to {}: change state event resp sent, state -> Run", peer);
                            logx::device(format!("WTP {} entered Run state", peer));
                            // Persist the runtime FSM state and reachability for a
                            // MAC we know as of this peer.
                            if let Some(mac) = ctx.mac {
                                devices.set_state(mac, "Run")?;
                            }
                            // Proceeding to Run means the pushed configuration was
                            // accepted; drop the outstanding push so it is not
                            // retransmitted.
                            cfg_status.mark_acked(cfg_status.pending().collect::<Vec<u16>>());
                            ctx.last_sent = None;

                            // TP-Link accepts WLAN configuration only in this
                            // private message and only while the WTP runs: its
                            // RFC Configuration Update Request parser drops the
                            // IEEE 802.11 Add WLAN element. One message carries
                            // one WLAN, so the set is pushed as a sequence. The
                            // message is not queued for retransmission - a
                            // vendor-form reply is not guaranteed, and a
                            // retransmit miss would tear the session down.
                            if profile == vendor::profile::VendorProfile::TpLink {
                                let mac = ctx.mac.unwrap_or([0; 6]);
                                // Seed per-AP rows from the AC-wide global template
                                // on first contact; the initialization defaults live
                                // in the DB, so there is no hardcoded fallback.
                                if radios.list_wlans(mac)?.is_empty() {
                                    wcfg.materialize(&radios, mac)?;
                                }
                                let wlans = configs_from_store(&*radios, mac)?;
                                if wlans.is_empty() {
                                    anyhow::bail!(
                                        "no WLAN configuration for {} (global_wlan default missing)",
                                        device::mac_to_str(mac)
                                    );
                                }
                                // WLANs are re-applied on Run entry. Add WLAN
                                // (1024) overwrites its slot in place, so a
                                // modification needs no Del (1027) - which is never
                                // sent: on this WTP a delete clears the whole saved
                                // table. The push is not skipped when the WTP
                                // reports the same WLANs (private 30), because
                                // radio bring-up re-initializes the VAPs and the
                                // Adds must follow it.
                                //
                                // A radio starts admin-down and the WTP drops its
                                // WLAN config while down, so each radio is brought
                                // up first with a bare RADIO_ADMIN_STATE then the
                                // private radio record, one Configuration Update
                                // Request per reply (the WTP admits a single
                                // in-flight radio op). See `WtpContext::push_queue`.
                                for radio_id in 1..=2u8 {
                                    let channel = wcfg.effective_channel(mac, radio_id)?;
                                    let channel = vendor::tplink::channel_field(channel);
                                    for msg in [
                                        vendor::tplink::radio_admin_state_request(
                                            ctx.next_seq(),
                                            radio_id,
                                            2,
                                        ),
                                        vendor::tplink::radio_config_request(
                                            ctx.next_seq(),
                                            radio_id,
                                            channel,
                                        ),
                                    ] {
                                        ctx.push_msg(msg.encode_for(frame(profile)));
                                    }
                                }
                                for w in &wlans {
                                    let req = vendor::tplink::wlan_config_update_request(
                                        ctx.next_seq(),
                                        w,
                                    );
                                    ctx.burst_msg(req.encode_for(frame(profile)));
                                }
                                let radios_queued = ctx.push_queue.len();
                                let burst_queued = ctx.push_burst.len();
                                for buf in ctx.release_push() {
                                    capdtls.write(&buf).await?;
                                }
                                info!(
                                    "[>] to {}: {} radio bring-up message(s) serialized, {} WLAN message(s) queued",
                                    peer, radios_queued, burst_queued
                                );
                                logx::device(format!(
                                    "pushed {} WLAN config(s) to {} in Run state",
                                    wlans.len(),
                                    peer
                                ));
                            }
                        }

                        (WtpState::Run, MsgType::ECHO_REQ) => {
                            debug!("[<] from {}: echo req (seq {})", peer, seq);
                            let resp_msg = CtrlMsg::new(MsgType::ECHO_RESP, seq);
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            debug!("[>] to {}: echo resp", peer);
                        }
                        (WtpState::Run, MsgType::ECHO_RESP) => {
                            debug!("[<] from {}: echo resp (seq {})", peer, seq);
                        }

                        (WtpState::Run, t) if t == vendor::tplink::WLAN_CONFIG_UPDATE_RESP => {
                            // Reply to the private WLAN Configuration Update
                            // Request (0x0033DD02). It echoes the private
                            // arguments the WTP accepted; the push itself is not
                            // queued, so this only records that the WTP answered.
                            info!("[<] from {}: WLAN configuration update resp (seq {})", peer, seq);
                            // Release the next serialized push, if any is due.
                            for buf in ctx.release_push() {
                                debug!("[>] to {}: next serialized push sent", peer);
                                capdtls.write(&buf).await?;
                            }
                        }

                        (WtpState::Run, t) if t == vendor::h3c::WTP_CHAN_UTIL_REQ => {
                            // AX60 channel-utilization report (element 0xfe20,
                            // [2G%, 5G%]); ack with mtype 146 + zero Result Code
                            // so the WTP drops its pending copy instead of
                            // retransmitting every 10s.
                            debug!("[<] from {}: chan util report (seq {})", peer, seq);
                            let resp_msg = CtrlMsg::new(vendor::h3c::WTP_CHAN_UTIL_RESP, seq)
                                .with_result_success();
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            debug!("[>] to {}: chan util ack", peer);
                        }

                        (WtpState::Run, MsgType::WTP_EVENT_REQ) => {
                            info!("[<] from {}: wtp event (seq {})", peer, seq);
                            // Log radio/station event elements for observability.
                            for (tag, items) in &elems {
                                let label = match *tag {
                                    MsgElemType::DECRYPT_ERR_REPORT => "decrypt-err",
                                    MsgElemType::DUPLICATE_IPV4_ADDR => "dup-ipv4",
                                    MsgElemType::DUPLICATE_IPV6_ADDR => "dup-ipv6",
                                    MsgElemType::WTP_RADIO_STATS => "radio-stats",
                                    MsgElemType::WTP_REBOOT_STATS => "reboot-stats",
                                    MsgElemType::DEL_STATION => "del-station",
                                    MsgElemType::VENDOR_SPECIFIC_PAYLOAD => "vendor",
                                    _ => "other",
                                };
                                for item in items {
                                    debug!("[*] wtp event element {}: {:?}", label, item);
                                }
                            }
                            // TP-Link reports two things here: the per-radio station
                            // report (top-level element 51) and, every ~20 s, the
                            // per-radio resource info (private 37). Both are
                            // TP-Link-only (RFC id 51 is Transport Protocol).
                            if profile == vendor::profile::VendorProfile::TpLink {
                                let wmac = ctx.mac.unwrap_or([0; 6]);
                                // Each report is the radio's complete associated
                                // set: it refreshes the listed stations and drops
                                // the rest.
                                if let Some(items) = elems.get(&vendor::tplink::STATION_REPORT_TAG) {
                                    for item in items {
                                        if let CwElem::Unknown(_, v) = item {
                                            match vendor::tplink::parse_station_report(v) {
                                                Some(rep) => {
                                                    match apply_station_report(&stations, wmac, &rep) {
                                                        Ok(n) if n > 0 => logx::station(format!(
                                                            "station report on {}: radio {} has {} station(s) ({} changed)",
                                                            device::mac_to_str(wmac),
                                                            rep.radio_id,
                                                            rep.stations.len(),
                                                            n
                                                        )),
                                                        Ok(_) => debug!(
                                                            "[*] station report: radio {} has {} station(s), unchanged",
                                                            rep.radio_id,
                                                            rep.stations.len()
                                                        ),
                                                        Err(e) => warn!("[!] station report persist failed: {}", e),
                                                    }
                                                }
                                                None => debug!(
                                                    "[*] station report: malformed value ({}B)",
                                                    v.len()
                                                ),
                                            }
                                        }
                                    }
                                }
                                // Private 37 records the radio's live band, channel
                                // and TX power, so the web view shows the RF state
                                // actually in use.
                                if let Some(items) = elems.get(&MsgElemType::VENDOR_SPECIFIC_PAYLOAD) {
                                    for item in items {
                                        if let CwElem::Unknown(_, v) = item {
                                            let Some((vendor_id, _, tlvs)) = vendor::vsp::split_value(v) else {
                                                continue;
                                            };
                                            if vendor_id != vendor::tplink::VENDOR_ID {
                                                continue;
                                            }
                                            let Some(ri) = vendor::vsp::find(&tlvs, vendor::tplink::priv_id::AP_RES_INFO)
                                                .and_then(vendor::tplink::parse_ap_res_info)
                                            else {
                                                continue;
                                            };
                                            if let Err(e) = radios.set_rf(wmac, ri.radio_id, ri.band, ri.channel, ri.tx_power) {
                                                warn!("[!] radio RF persist failed: {}", e);
                                            }
                                        }
                                    }
                                }
                                // This traffic also proves the WTP is alive.
                                if let Some(mac) = ctx.mac {
                                    devices.mark_joined(mac)?;
                                }
                            }
                            logx::device(format!("WTP {} reported events", peer));
                            let resp_msg = CtrlMsg::new(MsgType::WTP_EVENT_RESP, seq);
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            info!("[>] to {}: wtp event resp", peer);
                        }

                        (WtpState::Run, MsgType::STATION_CONFIG_REQ) => {
                            info!("[<] from {}: station config (seq {})", peer, seq);
                            if let Some(adds) = elems.get(&MsgElemType::ADD_STATION) {
                                // Resolve each station's band/SSID by matching
                                // the WLAN it joined against the per-radio
                                // configuration pushed for this WTP.
                                let wlans = radios.list_wlans(ctx.mac.unwrap_or([0; 6])).unwrap_or_default();
                                for a in adds {
                                    if let CwElem::Unknown(_, v) = a {
                                        if v.len() >= 7 {
                                            let mut mac = [0u8; 6];
                                            mac.copy_from_slice(&v[..6]);
                                            let wlan_id = v[6];
                                            let mut radio_id = 0u8;
                                            let mut ssid = None;
                                            if let Some(rw) = wlans.iter().find(|w| w.wlan_id == wlan_id) {
                                                radio_id = rw.radio_id;
                                                ssid = Some(rw.ssid.clone());
                                            }
                                            let assoc_at = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_secs())
                                                .unwrap_or(0);
                                            let st = stations.upsert(
                                                ctx.mac.unwrap_or([0; 6]),
                                                mac,
                                                radio_id,
                                                wlan_id,
                                                "associated",
                                                None,
                                                ssid.as_deref(),
                                                None,
                                            );
                                            match st {
                                                Ok(_) => {
                                                    ctx.add_station(capwap::RuntimeStation {
                                                        mac,
                                                        radio_id,
                                                        wlan_id,
                                                        ssid,
                                                        rssi: None,
                                                        ip: None,
                                                        state: "associated".into(),
                                                        associated_at: assoc_at,
                                                    });
                                                    logx::station(format!(
                                                        "station {} added on {} (radio {}, wlan {})",
                                                        device::mac_to_str(mac), peer, radio_id, wlan_id,
                                                    ));
                                                }
                                                Err(e) => warn!("[!] station persist failed: {}", e),
                                            }
                                        } else {
                                            debug!("[*] add-station: short payload ({})", v.len());
                                        }
                                    }
                                }
                            }
                            if let Some(dels) = elems.get(&MsgElemType::DEL_STATION) {
                                for d in dels {
                                    if let CwElem::Unknown(_, v) = d {
                                        if v.len() >= 6 {
                                            let mut mac = [0u8; 6];
                                            mac.copy_from_slice(&v[..6]);
                                            if let Err(e) = stations.delete(ctx.mac.unwrap_or([0; 6]), mac) {
                                                warn!("[!] station delete failed: {}", e);
                                            }
                                            ctx.remove_station(mac);
                                            logx::station(format!("station {} removed from {}", device::mac_to_str(mac), peer));
                                        }
                                    }
                                }
                            }
                            let resp_msg = CtrlMsg::new(MsgType::STATION_CONFIG_RESP, seq)
                                .with_result_success();
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            info!("[>] to {}: station config resp", peer);
                        }

                        (_, MsgType::CONFIG_UPDATE_RESP) => {
                            info!("[<] from {}: config update resp (seq {})", peer, seq);
                            // H3C WTPs answer with tag 33 (Result Code) as a 4-byte
                            // big-endian value (AX60 CWAssembleConfigurationUpdateResponse
                            // 0x3029c); 0 means applied, non-zero rejects the update.
                            match vendor::h3c::ConfigUpdateResp::decode(&msg) {
                                Ok(resp) if resp.is_success() => {
                                    cfg_status.mark_acked(cfg_status.pending().collect::<Vec<u16>>());
                                    // Acknowledged: this WTP's materialized config is
                                    // now in sync, so it leaves the pending-sync set.
                                    if let Some(mac) = ctx.mac {
                                        if let Err(e) = wcfg.clear_pending(mac) {
                                            warn!("[!] clear pending for {} failed: {}", peer, e);
                                        }
                                    }
                                    logx::device(format!("WTP {} acknowledged configuration update", peer));
                                }
                                Ok(resp) => {
                                    warn!("[!] from {}: config update rejected (result {})", peer, resp.result_code);
                                    logx::device(format!(
                                        "WTP {} rejected configuration update (result {})",
                                        peer, resp.result_code
                                    ));
                                }
                                Err(e) => warn!("[!] from {}: malformed config update resp: {}", peer, e),
                            }
                            // Clear the outstanding request only if it was our Config
                            // Update Request, so an unrelated response cannot drop a
                            // pending retransmission.
                            if ctx.last_sent.as_ref().map(|l| l.msg_type) == Some(MsgType::CONFIG_UPDATE_REQ) {
                                ctx.last_sent = None;
                            }
                            // Release the next serialized radio bring-up message.
                            for buf in ctx.release_push() {
                                debug!("[>] to {}: next serialized push sent", peer);
                                capdtls.write(&buf).await?;
                            }
                        }

                        (WtpState::Run, MsgType::IMAGE_DATA_REQ) => {
                            info!("[<] from {}: image data req (seq {})", peer, seq);
                            // A WTP that lacks the expected firmware requests a
                            // download via Image Identifier / Initiate Download.
                            let wants = elems.contains_key(&MsgElemType::INIT_DOWNLOAD)
                                || elems.contains_key(&MsgElemType::IMAGE_ID);
                            if wants && fw_upgrade.session.is_none() {
                                // Placeholder image; replace once a real firmware
                                // source is wired (M7 upload / config repo).
                                let image: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
                                let mac = ctx.mac.unwrap_or([0; 6]);
                                match fw.record_start(&mac, "miniac-boot", image.len() as u32, &[0u8; 16]) {
                                    Ok(id) => {
                                        fw_record_id = Some(id);
                                        logx::firmware(format!("firmware download started for {}", device::mac_to_str(mac)));
                                    }
                                    Err(e) => warn!("[!] firmware record start failed: {}", e),
                                }
                                fw_upgrade.begin(image, 512);
                            }
                            if let Some(blk) = fw_upgrade.current() {
                                let dl = CtrlMsg::new(MsgType::IMAGE_DATA_REQ, ctx.next_seq())
                                    .add_elem(MsgElemType::IMAGE_DATA, &blk.encode());
                                let buf = dl.encode_for(frame(profile));
                                capdtls.write(&buf).await?;
                                ctx.set_last_sent(&dl, buf);
                                info!("[>] to {}: image data block ({}B) sent", peer, blk.data.len());
                            }
                        }

                        (WtpState::Run, MsgType::IMAGE_DATA_RESP) => {
                            info!("[<] from {}: image data resp (seq {})", peer, seq);
                            if fw_upgrade.session.is_none() {
                                ctx.last_sent = None;
                                continue;
                            }
                            fw_upgrade.complete_block();
                            if let Some(blk) = fw_upgrade.current() {
                                let dl = CtrlMsg::new(MsgType::IMAGE_DATA_REQ, ctx.next_seq())
                                    .add_elem(MsgElemType::IMAGE_DATA, &blk.encode());
                                let buf = dl.encode_for(frame(profile));
                                capdtls.write(&buf).await?;
                                ctx.set_last_sent(&dl, buf);
                                info!("[>] to {}: image data block ({}B) sent", peer, blk.data.len());
                            } else if fw_upgrade.state == firmware::UpgradeState::AwaitReset {
                                // All blocks acknowledged; order the WTP to reset
                                // onto the delivered image.
                                // The H3C image-name field is NUL-terminated: the
                                // AX60 parser forces the last value byte to 0, so
                                // an unterminated name is truncated (and never
                                // matches the delivered image).
                                let name = firmware::ImageIdentifier { vendor_id: 1916, name: "miniac-boot".to_string() };
                                let mut id_body = name.encode();
                                id_body.push(0);
                                let reset = CtrlMsg::new(MsgType::RESET_REQ, ctx.next_seq())
                                    .add_elem(MsgElemType::IMAGE_ID, &id_body);
                                let buf = reset.encode_for(frame(profile));
                                capdtls.write(&buf).await?;
                                ctx.set_last_sent(&reset, buf);
                                if let Some(id) = fw_record_id {
                                    let _ = fw.mark_done(id);
                                }
                                logx::firmware(format!("firmware transfer done; reset requested for {}", peer));
                                fw_upgrade.reset_sent();
                            }
                        }

                        (WtpState::Run, MsgType::RESET_RESP) => {
                            info!("[<] from {}: reset resp (seq {})", peer, seq);
                            if pending_cmd.take() == Some(wtpcmd::WtpCmd::Reset) {
                                // UI-issued reset acknowledged; the WTP reboots and
                                // the session drops shortly after.
                                let code = vendor::h3c::result_code(&msg).unwrap_or(0);
                                logx::device(format!(
                                    "WTP {} reset acknowledged (result {})",
                                    device::mac_to_str(ctx.mac.unwrap_or([0; 6])),
                                    code
                                ));
                                ctx.last_sent = None;
                            } else {
                                // Firmware-driven reset completing the upgrade.
                                if let Some(id) = fw_record_id {
                                    let _ = fw.mark_done(id);
                                }
                                logx::firmware(format!("WTP {} acked reset; upgrade complete", peer));
                                ctx.last_sent = None;
                            }
                        }

                        (WtpState::Run, MsgType::CLEAR_CONFIG_RESP) => {
                            info!("[<] from {}: clear config resp (seq {})", peer, seq);
                            let code = vendor::h3c::result_code(&msg).unwrap_or(0);
                            if pending_cmd == Some(wtpcmd::WtpCmd::Disable) {
                                if code == 0 {
                                    // Defaults restored; now restart the WTP.
                                    logx::device(format!(
                                        "WTP {} cleared to factory defaults; restarting",
                                        device::mac_to_str(ctx.mac.unwrap_or([0; 6]))
                                    ));
                                    pending_cmd = Some(wtpcmd::WtpCmd::Reset);
                                    let reset =
                                        profile.reset_request(ctx.next_seq(), RESET_IMAGE_NAME);
                                    let buf = reset.encode_for(frame(profile));
                                    capdtls.write(&buf).await?;
                                    ctx.set_last_sent(&reset, buf);
                                } else {
                                    warn!("[!] with {}: clear config rejected (result {})", peer, code);
                                    logx::device(format!(
                                        "WTP {} clear configuration rejected (result {})",
                                        device::mac_to_str(ctx.mac.unwrap_or([0; 6])),
                                        code
                                    ));
                                    pending_cmd = None;
                                    ctx.last_sent = None;
                                }
                            }
                        }

                        (WtpState::Run, MsgType::RELEASE_CLIENT_RESP) => {
                            info!("[<] from {}: release client resp (seq {})", peer, seq);
                            let code = vendor::h3c::result_code(&msg).unwrap_or(0);
                            if let Some(wtpcmd::WtpCmd::ReleaseClient(smac)) = pending_cmd.take() {
                                // The station stays visible until the WTP reports
                                // the de-association through its own state events.
                                logx::device(format!(
                                    "client {} released from WTP {} (result {})",
                                    device::mac_to_str(smac),
                                    device::mac_to_str(ctx.mac.unwrap_or([0; 6])),
                                    code
                                ));
                            }
                            ctx.last_sent = None;
                        }

                        _ => debug!("[?] from {}: unhandled state/msg", peer),
                    }
                }
            }

            _ = tokio::time::sleep(sleep_duration) => {
                let now = Instant::now();

                if capdtls.next_timeout().is_some() {
                    capdtls.on_timeout(now).await?;
                }

                let retrans_interval = ctx
                    .last_sent
                    .as_ref()
                    .map(|last| ctx.retrans_interval_for(last.retry_count))
                    .unwrap_or_default();
                if let Some(ref mut last) = ctx.last_sent {
                    if MsgType::is_request(last.msg_type) && now >= last.send_time + retrans_interval {
                        if last.retry_count < ctx.max_retries {
                            last.retry_count += 1;
                            last.send_time = now;
                            warn!("[>] to {}: retransmitting {:?} (seq {}, attempt {})",
                                peer, last.msg_type, last.seq, last.retry_count);
                            // Re-encrypted through DTLS so the peer does not drop
                            // it as a replay (RFC 5415 4.5.3).
                            capdtls.write(&last.buf).await?;
                        } else {
                            error!("[!] with {}: max retries reached", peer);
                            return Err(anyhow::anyhow!("retransmit timeout"));
                        }
                    }
                }
                // Serialized vendor push: release the next frame if the WTP
                // never replied to the one in flight, so one missing reply
                // cannot stall the whole configuration push.
                if !ctx.push_queue.is_empty() {
                    let due = ctx
                        .push_last_sent
                        .is_none_or(|t| now >= t + PUSH_REPLY_TIMEOUT);
                    if due {
                        warn!(
                            "[>] to {}: no reply to serialized push, releasing next ({} left)",
                            peer,
                            ctx.push_queue.len()
                        );
                        for buf in ctx.release_push() {
                            capdtls.write(&buf).await?;
                        }
                    }
                }
                if ctx.state == WtpState::Run
                    && !outstanding
                    && now >= ctx.last_echo_sent + ctx.echo_interval
                {
                    // Active keep-alive: send an Echo Request each interval. It is
                    // not queued in `last_sent` (so unacknowledged echoes do not
                    // force a retransmit loop) — liveness is still gated by the
                    // inbound-traffic deadline below, which tolerates vendor
                    // keep-alives that are not standard Echo Responses. Not sent
                    // while a Request is outstanding (RFC 5415 4.5.3).
                    let echo = CtrlMsg::new(MsgType::ECHO_REQ, ctx.next_seq());
                    let echo_buf = echo.encode_for(frame(profile));
                    capdtls.write(&echo_buf).await?;
                    ctx.last_echo_sent = now;
                    debug!("[>] to {}: echo keep-alive (seq {})", peer, echo.hdr.seq_num);
                }
                if ctx.state == WtpState::Run && now >= ctx.last_seen + ctx.echo_interval {
                    error!("[!] with {}: echo timeout (no traffic for {}s)", peer, ctx.echo_interval.as_secs());
                    return Err(anyhow::anyhow!("echo timeout"));
                }
            }

            cmd = upgrade_rx.recv(), if !outstanding => {
                match cmd {
                    Some(firmware::UpgradeCmd::Start { image }) => {
                        info!("[>] to {}: firmware download triggered via management plane", peer);
                        fw_upgrade.begin(image, 512);
                        if let Some(blk) = fw_upgrade.current() {
                            let dl = CtrlMsg::new(MsgType::IMAGE_DATA_REQ, ctx.next_seq())
                                .add_elem(MsgElemType::IMAGE_DATA, &blk.encode());
                            let buf = dl.encode_for(frame(profile));
                            capdtls.write(&buf).await?;
                            ctx.set_last_sent(&dl, buf);
                            info!("[>] to {}: image data block ({}B) sent", peer, blk.data.len());
                        }
                    }
                    None => {}
                }
            }

            cmd = cfg_update_rx.recv(), if !outstanding => {
                match cmd {
                    Some(config::ConfigUpdateCmd::Push { elems }) => {
                        info!("[>] to {}: configuration update triggered via management plane", peer);
                        let req = config::config_update(ctx.next_seq(), &[], &elems);
                        // Remember which tags are now outstanding so the response
                        // handler can confirm (or reject) the push.
                        cfg_status.mark_pushed(elems.iter().map(|e| e.tag()));
                        let buf = req.encode_for(frame(profile));
                        capdtls.write(&buf).await?;
                        ctx.set_last_sent(&req, buf);
                    }
                    None => {}
                }
            }

            cmd = wtp_cmd_rx.recv(), if !outstanding => {
                match cmd {
                    Some(wtpcmd::WtpCmd::Reset) => {
                        info!("[>] to {}: reset requested via management plane", peer);
                        pending_cmd = Some(wtpcmd::WtpCmd::Reset);
                        let req = profile.reset_request(ctx.next_seq(), RESET_IMAGE_NAME);
                        let buf = req.encode_for(frame(profile));
                        capdtls.write(&buf).await?;
                        ctx.set_last_sent(&req, buf);
                    }
                    Some(wtpcmd::WtpCmd::Disable) => {
                        // Restore defaults first; the Reset Request follows once
                        // the WTP acknowledges the Clear Configuration Response.
                        info!("[>] to {}: clear configuration requested via management plane", peer);
                        pending_cmd = Some(wtpcmd::WtpCmd::Disable);
                        let req = profile.clear_config_request(ctx.next_seq());
                        let buf = req.encode_for(frame(profile));
                        capdtls.write(&buf).await?;
                        ctx.set_last_sent(&req, buf);
                    }
                    Some(wtpcmd::WtpCmd::ReleaseClient(smac)) => {
                        info!("[>] to {}: release client {} requested via management plane",
                            peer, device::mac_to_str(smac));
                        pending_cmd = Some(wtpcmd::WtpCmd::ReleaseClient(smac));
                        let req = vendor::h3c::release_client_request(ctx.next_seq(), smac);
                        let buf = req.encode_for(frame(profile));
                        capdtls.write(&buf).await?;
                        ctx.set_last_sent(&req, buf);
                    }
                    None => {}
                }
            }
        }
    }
}

/// Builds the DTLS handshake configuration.
///
/// When the profile's certificate directory (`certs/h3c`, or `certs/tplink` for
/// TP-Link) holds the CAPWAP identity (`server.pem` + `root.pem`), the server
/// presents that RSA certificate. H3C also requires and pins the client chain
/// against `root.pem`, ignoring validity periods; the RFC / TP-Link forms keep
/// server-only authentication. Otherwise a self-signed Ed25519 certificate is
/// used and no client certificate is requested.
fn generate_dtls_config(
    prof: vendor::profile::VendorProfile,
) -> Result<Arc<rtc_dtls::config::HandshakeConfig>> {
    use rtc_dtls::config::{ClientAuthType, ConfigBuilder};
    use rtc_dtls::crypto::Certificate;
    use rtc_dtls::crypto_provider;
    use rtc_dtls::signature_hash_algorithm::SignatureScheme;

    let provider =
        crypto_provider::default_provider().map_err(|e| anyhow!("crypto provider: {e}"))?;

    let cert_dir = prof.cert_dir();
    if cert_dir.exists() {
        let identity = dtls_local::load_identity(cert_dir)?;
        let cert = Certificate::from_signing_key(identity.certificate_chain, identity.signing_key);
        let mut builder = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![cert])
            .with_cipher_suites(vec![
                rtc_dtls::cipher_suite::CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha,
            ])
            .with_signature_schemes(vec![
                SignatureScheme::Pkcs1WithSha256,
                SignatureScheme::Pkcs1WithSha1,
            ]);
        if prof.requires_client_cert() {
            let root_der = dtls_local::load_root_cert_der(cert_dir)?;
            builder = builder
                .with_client_auth(ClientAuthType::RequireAnyClientCert)
                .with_verify_peer_certificate(Some(dtls_local::verify_client_chain_callback(root_der)));
        }
        let config = builder
            .with_insecure_hashes(true)
            .with_insecure_verification(true)
            .build(false, None)
            .map_err(|e| anyhow!("DTLS config: {e}"))?;
        return Ok(Arc::new(config));
    }

    // Fallback: self-signed Ed25519 identity, no client certificate policy.
    //
    // This identity offers only the default ECDHE suites, so a WTP that offers
    // static-RSA CBC suites alone (TP-Link TL-AP1300GI: 0x002f/0x000a) can never
    // negotiate with it - the failure surfaces only later as
    // `ErrCipherSuiteNoIntersection`. The identity is resolved relative to the
    // working directory, so a run that does not carry the cert tree with it lands
    // here, which is why the miss is reported loudly.
    warn!(
        "DTLS identity {} not found (cwd {}); falling back to a self-signed Ed25519 key, \
         which cannot negotiate with WTPs offering only static-RSA CBC suites",
        cert_dir.display(),
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    );
    let cert =
        Certificate::generate_self_signed(vec!["miniac.local".to_string()], provider.crypto())
            .map_err(|e| anyhow!("self-signed certificate: {e}"))?;
    let config = ConfigBuilder::default()
        .with_crypto_provider(provider)
        .with_certificates(vec![cert])
        .build(false, None)
        .map_err(|e| anyhow!("DTLS config: {e}"))?;
    Ok(Arc::new(config))
}
