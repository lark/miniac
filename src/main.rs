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
mod logx;
mod radio;
mod roaming;
mod security;
mod stage1;
mod station;
mod vendor;
mod web;

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

use capwap::{CtrlMsg, CwElem, CwResult, MsgElemType, MsgType, WtpContext, WtpState};

const CTRL_PORT: u16 = 5246;
const HTTP_DEFAULT_PORT: &str = "8080";

/// Framing used for the whole DTLS control session. H3C AX60-style WTPs widen
/// the control header Seq to 4 bytes and expect the 8-byte base header on
/// every message (not just discovery), so responses are framed accordingly.
const FRAME: vendor::framing::CtrlFrame = vendor::framing::CtrlFrame::H3c;

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

    let dtls_config = generate_dtls_config()?;

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
        let pool_start = add_ip(base, 50);
        let pool_end = add_ip(base, 80);
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
            dtls_config.clone(),
            devices.clone(),
            radios.clone(),
            stations.clone(),
            fw.clone(),
            upgrade_reg.clone(),
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
    dtls_config: Arc<rtc_dtls::config::HandshakeConfig>,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    upgrade_reg: Arc<firmware::UpgradeRegistry>,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();

        let tx = {
            let map = dispatcher_map.lock().await;
            map.get(&peer).cloned()
        };

        if let Some(tx) = tx {
            if pkt.get(0) == Some(&1) {
                let _ = tx.try_send(pkt);
            }
            continue;
        }

        // 3. New Discovery
        if pkt.get(0) == Some(&0) {
            if pkt.get(11) == Some(&1) {
                // MsgType: 1 (Discovery Request)
                info!("[<] from {}: disc req", peer);

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
                match vendor::h3c::discovery_response(&pkt, ac_ip, b"My AC") {
                    Some(resp) => {
                        logx::device(format!("Discovery response to {} ({}B)", peer, resp.len()));
                        socket.send_to(&resp, peer).await?;
                    }
                    None => warn!("[?] disc req from {} not H3C-framed, dropped", peer),
                }
            }
        }

        if pkt.get(0) == Some(&1) {
            info!("[<] from {}: direct dtls hello", peer);
            let tx = start_new_session(
                peer,
                &dispatcher_map,
                &socket,
                &dtls_config,
                devices.clone(),
                radios.clone(),
                stations.clone(),
                fw.clone(),
                upgrade_reg.clone(),
            )
            .await;
            let _ = tx.send(pkt).await;
            continue;
        }
    }
}

/// Extract a WTP board MAC from a decoded element map, when present.
///
/// H3C AX60 carries the WTP MAC in private element 54 (value = 6-byte MAC);
/// the RFC WTP Board Data element head is not the MAC, so check the vendor
/// element first and fall back to the Board Data head for other WTPs.
fn wtp_mac_from_elems(elems: &HashMap<u16, Vec<CwElem>>) -> Option<device::Mac> {
    const H3C_WTP_MAC: u16 = 54;
    if let Some(v) = elems.get(&H3C_WTP_MAC).and_then(|e| e.first()) {
        if let CwElem::Unknown(_, body) = v {
            if body.len() >= 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&body[..6]);
                return Some(mac);
            }
        }
    }
    let v = elems.get(&MsgElemType::WTP_BOARD_DATA)?.first()?;
    if let CwElem::Unknown(_, body) = v {
        if body.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&body[..6]);
            return Some(mac);
        }
    }
    None
}

async fn start_new_session(
    peer: SocketAddr,
    map: &Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    socket: &Arc<UdpSocket>,
    config: &Arc<rtc_dtls::config::HandshakeConfig>,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    upgrade: Arc<firmware::UpgradeRegistry>,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel(100);
    map.lock().await.insert(peer, tx.clone());

    let sock_clone = Arc::clone(socket);
    let conf_clone = Arc::clone(config);

    tokio::spawn(async move {
        info!("[*] with {}: session thread spawned", peer);
        if let Err(e) = handle_session(
            peer, rx, sock_clone, conf_clone, devices, radios, stations, fw, upgrade,
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
        let method = config::SecurityMethod::from_policy(&rw.security)
            .unwrap_or(config::SecurityMethod::Open);
        let auth_type = if method == config::SecurityMethod::Open {
            config::AuthType::Open
        } else {
            config::AuthType::Rsn
        };
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
            security: config::WlanSecurity {
                method,
                psk: rw.psk.clone(),
            },
            wlan_enable: rw.wlan_enable,
            isolate: rw.isolate,
            broadcast: rw.broadcast,
            client_count: rw.client_count,
            vlan_id: rw.vlan_id,
            cipher: rw.cipher,
            rekey_period: rw.rekey_period,
        });
    }
    Ok(out)
}

async fn handle_session(
    peer: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    config: Arc<rtc_dtls::config::HandshakeConfig>,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    upgrade: Arc<firmware::UpgradeRegistry>,
) -> Result<()> {
    let local_addr = socket.local_addr()?;
    let mut capdtls = connection::CapwapDtls::new(local_addr, peer, socket, config);
    let mut handshake_logged = false;

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

    loop {
        let retrans_duration = ctx
            .last_sent
            .as_ref()
            .filter(|last| MsgType::is_request(last.msg_type))
            .map(|last| {
                ctx.retrans_interval
                    .saturating_sub(last.send_time.elapsed())
            })
            .unwrap_or(Duration::from_secs(60));
        let idle_duration = ctx.echo_interval.saturating_sub(ctx.last_seen.elapsed());
        // Also wake in time to send the next keep-alive Echo Request in Run state.
        let next_echo = ctx.echo_interval.saturating_sub(ctx.last_echo_sent.elapsed());
        let mut sleep_duration =
            std::cmp::min(retrans_duration, std::cmp::min(idle_duration, next_echo));
        // Keep the DTLS retransmit timer ahead of the sleep, so handshake
        // flights are resent even while no CAPWAP message is due.
        if let Some(t) = capdtls.next_timeout() {
            sleep_duration = sleep_duration.min(t.saturating_duration_since(Instant::now()));
        }
        if sleep_duration.is_zero() {
            sleep_duration = Duration::from_millis(1);
        }

        tokio::select! {
            Some(pkt) = rx.recv() => {
                let app_datas = capdtls.feed(&pkt).await?;
                if capdtls.handshake_complete() && !handshake_logged {
                    handshake_logged = true;
                    info!("[!] with {}: dtls handshake done", peer);
                }
                for app_data in app_datas {
                    let n = app_data.len();
                    if n < 16 { continue }
                    ctx.keep_alive();

                    let msg = match CtrlMsg::decode(FRAME, &app_data[8..n]) {
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
                    let elem_off = 8 + FRAME.elem_off();
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

                    if let Some(ref last) = ctx.last_sent {
                        if seq == last.seq && m_type == last.msg_type {
                            if MsgType::is_response(last.msg_type) {
                                warn!("[!] from {}: dup req (seq {}), resending response", peer, seq);
                                capdtls.write(&last.buf).await?;
                                continue;
                            }
                        }
                    }

                    if MsgType::is_response(m_type) {
                        if let Some(last) = ctx.last_sent.as_ref().filter(|l| l.seq == seq && MsgType::is_request(l.msg_type)) {
                            info!("[<] from {}: received response for {:?} (seq {})", peer, last.msg_type, seq);
                            ctx.last_sent = None;
                        }
                    }

                    match (ctx.state, m_type) {
                        (WtpState::Join, MsgType::JOIN_REQ) => {
                            info!("[<] from {}: join req (seq {})", peer, seq);
                            if let Some(CwElem::WtpDescriptor { hardware, software }) = elems.get(&MsgElemType::WTP_DESCRIPTOR).and_then(|v| v.first()) {
                                info!("[*] wtp hw: {:08x}, sw: {:08x}", hardware, software);
                                ctx.hardware_version = *hardware;
                                ctx.software_version = *software;
                            }
                            // Persist device learned from the join exchange (keyed by MAC).
                            if let Some(mac) = wtp_mac_from_elems(&elems) {
                                ctx.mac = Some(mac);
                                let ip = peer.ip().to_string();
                                let sw = format!("{:08x}", ctx.software_version);
                                let created = devices.register(mac, Some(&ip), Some(&sw), None, None, "registered")?;
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
                                    let resp_msg = CtrlMsg::new(MsgType::JOIN_RESP, seq)
                                        .with_result(CwResult::Failure)
                                        .add_elem(MsgElemType::AC_NAME, b"miniac")
                                        .add_elem(MsgElemType::CAPWAP_CTRL_IPV4_ADDR, &[127, 0, 0, 1])
                                        .add_elem(MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, &[127, 0, 0, 1]);
                                    let resp_buf = resp_msg.encode_for(FRAME);
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
                            } else {
                                debug!("[*] join: no WTP Board Data MAC present");
                            }
                            // response
                            // The AX60 JoinResponse parser (WTP.dis 0x23754)
                            // counts tag-10 entries to size its AC list and then
                            // re-parses each as [4B IP][2B] (0x1df5c); a missing or
                            // 4-byte tag 10 makes it malloc(0)/desync and reject,
                            // so the tag 10 value must be the 6-byte AC IPv4 entry.
                            let resp_msg = CtrlMsg::new(MsgType::JOIN_RESP, seq)
                                .with_result_success()
                                .add_elem(MsgElemType::AC_DESCRIPTOR, &vendor::h3c::ac_descriptor("1.0", "1.0"))
                                .add_elem(MsgElemType::AC_NAME, b"miniac")
                                .add_elem(MsgElemType::ECN_SUPPORT, &[1])
                                .add_element(elements::BaseElem::MaxMessageLen(2048))
                                .add_elem(MsgElemType::CAPWAP_CTRL_IPV4_ADDR, &vendor::h3c::ac_ipv4_entry(ac_ip))
                                .add_elem(MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, &ac_ip.octets());
                            let resp_buf = resp_msg.encode_for(FRAME);
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);

                            ctx.state = WtpState::Configure;
                            info!("[>] to {}: join resp sent, state -> Configure", peer);
                        }

                        (WtpState::Configure, MsgType::CONFIG_STATUS_REQ) => {
                            info!("[<] from {}: config status req (seq {})", peer, seq);
                            // TEMP debug: dump raw config status request wire bytes and
                            // each parsed element for reverse-engineering analysis.
                            {
                                let hx: String =
                                    app_data.iter().map(|b| format!("{:02x}", b)).collect();
                                info!("[DBG] cfg-status-req app_data ({}B): {}", app_data.len(), hx);
                                for e in &msg.elems {
                                    info!("[DBG]   elem tag={:#06x} len={} val={}", e.tag, e.data.len(),
                                        e.data.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                                }
                            }
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

                            // Build the WTP's WLAN list first (from the radio_wlans
                            // store; a single default WLAN if none is configured yet).
                            let mut wlans = configs_from_store(&*radios, ctx.mac.unwrap_or([0; 6]))?;
                            if wlans.is_empty() {
                                // Empty configuration template: push the default
                                // SSID to both radios. The AX60 maps radio id to
                                // band as band = radio_id - 1 (0x3ff20), so radio 1
                                // is 2.4G and radio 2 is 5G.
                                for radio_id in [1u8, 2u8] {
                                    wlans.push(config::WlanConfig {
                                        radio_id,
                                        wlan_id: 1,
                                        capability: 0x0001, // ESS
                                        qos: 0,
                                        auth_type: config::AuthType::Rsn,
                                        mac_mode: 0,
                                        tunnel_mode: 0,
                                        suppress_ssid: false,
                                        ssid: b"miniac".to_vec(),
                                        security: config::WlanSecurity {
                                            method: config::SecurityMethod::Wpa2Wpa3,
                                            psk: Some("person0finterest".into()),
                                        },
                                        ..config::WlanConfig::default()
                                    });
                                }
                            }
                            // Rebuild the Config Status Response to mirror the M60
                            // AC's assembly order (AC.dis 0x1001d6a0-0x1001feec):
                            // [2][3][12][32][16][23][40][55] then one 0xfde8 per
                            // radio/WLAN. The full assembly (H3C base elements,
                            // radio records, the tag31 echo and the 0xfde8 WLAN
                            // config, with the MINIAC_H3C_EXP bisection switches)
                            // lives in vendor::h3c::config_status_response.
                            let mac = ctx.mac.unwrap_or([0; 6]);
                            let g24_hdr = radios.h3c_header(mac, 1)?;
                            let g5_hdr = radios.h3c_header(mac, 2)?;
                            // Advanced radio features (fe28 OFDMA/MU-MIMO, fe31
                            // band navigation): driven by env overrides until a
                            // DB source exists; None keeps the m60 wire layout
                            // byte-identical to the M60 718B capture.
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
                            let resp_msg = vendor::h3c::config_status_response(
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
                            );
                            let resp_buf = resp_msg.encode_for(FRAME);
                            // TEMP debug: dump the exact wire bytes sent as the
                            // Configuration Status Response (head + control + elems).
                            {
                                let hx: String =
                                    resp_buf.iter().map(|b| format!("{:02x}", b)).collect();
                                info!("[DBG] cfg-status-resp wire ({}B): {}", resp_buf.len(), hx);
                            }
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            cfg_status.mark_pushed([vendor::h3c::WLAN_CFG_H3C]);
                            logx::device(format!(
                                "pushed {} WLAN config(s) to {}",
                                wlans.len(),
                                peer
                            ));
                            info!("[>] to {}: config response with {} WLAN config(s) sent", peer, wlans.len());

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
                            let resp_buf = resp_msg.encode_for(FRAME);
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);

                            ctx.state = WtpState::Run;
                            info!("[>] to {}: change state event resp sent, state -> Run", peer);
                            logx::device(format!("WTP {} entered Run state", peer));
                            // Persist reachability for a MAC we know as of this peer.
                            if let Some(mac) = ctx.mac {
                                devices.mark_joined(mac)?;
                            }
                            // Proceeding to Run means the pushed configuration was
                            // accepted; drop the outstanding push so it is not
                            // retransmitted.
                            cfg_status.mark_acked(cfg_status.pending().collect::<Vec<u16>>());
                            ctx.last_sent = None;
                        }

                        (WtpState::Run, MsgType::ECHO_REQ) => {
                            debug!("[<] from {}: echo req (seq {})", peer, seq);
                            let resp_msg = CtrlMsg::new(MsgType::ECHO_RESP, seq);
                            let resp_buf = resp_msg.encode_for(FRAME);
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            debug!("[>] to {}: echo resp", peer);
                        }
                        (WtpState::Run, MsgType::ECHO_RESP) => {
                            debug!("[<] from {}: echo resp (seq {})", peer, seq);
                        }

                        (WtpState::Run, t) if t == vendor::h3c::WTP_CHAN_UTIL_REQ => {
                            // AX60 channel-utilization report (element 0xfe20,
                            // [2G%, 5G%]); ack with mtype 146 + zero Result Code
                            // so the WTP drops its pending copy instead of
                            // retransmitting every 10s.
                            debug!("[<] from {}: chan util report (seq {})", peer, seq);
                            let resp_msg = CtrlMsg::new(vendor::h3c::WTP_CHAN_UTIL_RESP, seq)
                                .with_result_success();
                            let resp_buf = resp_msg.encode_for(FRAME);
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
                            logx::device(format!("WTP {} reported events", peer));
                            let resp_msg = CtrlMsg::new(MsgType::WTP_EVENT_RESP, seq);
                            let resp_buf = resp_msg.encode_for(FRAME);
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
                            let resp_buf = resp_msg.encode_for(FRAME);
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            info!("[>] to {}: station config resp", peer);
                        }

                        (_, MsgType::CONFIG_UPDATE_RESP) => {
                            info!("[<] from {}: config update resp (seq {})", peer, seq);
                            for _ in elems.get(&MsgElemType::RESULT_CODE).into_iter().flatten() {
                                // any result confirms the WTP received our update
                            }
                            cfg_status.mark_acked(cfg_status.pending().collect::<Vec<u16>>());
                            ctx.last_sent = None;
                            logx::device(format!("WTP {} acknowledged configuration update", peer));
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
                                let buf = dl.encode_for(FRAME);
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
                                let buf = dl.encode_for(FRAME);
                                capdtls.write(&buf).await?;
                                ctx.set_last_sent(&dl, buf);
                                info!("[>] to {}: image data block ({}B) sent", peer, blk.data.len());
                            } else if fw_upgrade.state == firmware::UpgradeState::AwaitReset {
                                // All blocks acknowledged; order the WTP to reset
                                // onto the delivered image.
                                let name = firmware::ImageIdentifier { vendor_id: 1916, name: "miniac-boot".to_string() };
                                let reset = CtrlMsg::new(MsgType::RESET_REQ, ctx.next_seq())
                                    .add_elem(MsgElemType::IMAGE_ID, &name.encode());
                                let buf = reset.encode_for(FRAME);
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
                            if let Some(id) = fw_record_id {
                                let _ = fw.mark_done(id);
                            }
                            logx::firmware(format!("WTP {} acked reset; upgrade complete", peer));
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

                if let Some(ref mut last) = ctx.last_sent {
                    if MsgType::is_request(last.msg_type) && now >= last.send_time + ctx.retrans_interval {
                        if last.retry_count < ctx.max_retries {
                            last.retry_count += 1;
                            last.send_time = now;
                            warn!("[>] to {}: retransmitting {:?} (seq {}, attempt {})",
                                peer, last.msg_type, last.seq, last.retry_count);
                            capdtls.write(&last.buf).await?;
                        } else {
                            error!("[!] with {}: max retries reached", peer);
                            return Err(anyhow::anyhow!("retransmit timeout"));
                        }
                    }
                }
                if ctx.state == WtpState::Run && now >= ctx.last_echo_sent + ctx.echo_interval {
                    // Active keep-alive: send an Echo Request each interval. It is
                    // not queued in `last_sent` (so unacknowledged echoes do not
                    // force a retransmit loop) — liveness is still gated by the
                    // inbound-traffic deadline below, which tolerates vendor
                    // keep-alives that are not standard Echo Responses.
                    let echo = CtrlMsg::new(MsgType::ECHO_REQ, ctx.next_seq());
                    let echo_buf = echo.encode_for(FRAME);
                    capdtls.write(&echo_buf).await?;
                    ctx.last_echo_sent = now;
                    debug!("[>] to {}: echo keep-alive (seq {})", peer, echo.hdr.seq_num);
                }
                if ctx.state == WtpState::Run && now >= ctx.last_seen + ctx.echo_interval {
                    error!("[!] with {}: echo timeout (no traffic for {}s)", peer, ctx.echo_interval.as_secs());
                    return Err(anyhow::anyhow!("echo timeout"));
                }
            }

            cmd = upgrade_rx.recv() => {
                match cmd {
                    Some(firmware::UpgradeCmd::Start { image }) => {
                        info!("[>] to {}: firmware download triggered via management plane", peer);
                        fw_upgrade.begin(image, 512);
                        if let Some(blk) = fw_upgrade.current() {
                            let dl = CtrlMsg::new(MsgType::IMAGE_DATA_REQ, ctx.next_seq())
                                .add_elem(MsgElemType::IMAGE_DATA, &blk.encode());
                            let buf = dl.encode_for(FRAME);
                            capdtls.write(&buf).await?;
                            ctx.set_last_sent(&dl, buf);
                            info!("[>] to {}: image data block ({}B) sent", peer, blk.data.len());
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

/// Builds the DTLS handshake configuration.
///
/// When `certs/h3c/` holds the CAPWAP CA identity (`server.pem` + `root.pem`),
/// the server presents that 1024-bit RSA certificate and accepts clients whose
/// chain is signed by `root.pem`, ignoring validity periods — required by H3C
/// (and other legacy-vendor) APs. Otherwise a self-signed Ed25519 certificate
/// is used and no client certificate is requested.
fn generate_dtls_config() -> Result<Arc<rtc_dtls::config::HandshakeConfig>> {
    use rtc_dtls::config::{ClientAuthType, ConfigBuilder};
    use rtc_dtls::crypto::Certificate;
    use rtc_dtls::crypto_provider;
    use rtc_dtls::signature_hash_algorithm::SignatureScheme;

    let provider =
        crypto_provider::default_provider().map_err(|e| anyhow!("crypto provider: {e}"))?;

    let cert_dir = std::path::Path::new("certs/h3c");
    if cert_dir.exists() {
        let identity = dtls_local::load_identity(cert_dir)?;
        let root_der = dtls_local::load_root_cert_der(cert_dir)?;
        let cert = Certificate::from_signing_key(identity.certificate_chain, identity.signing_key);
        let config = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![cert])
            .with_cipher_suites(vec![
                rtc_dtls::cipher_suite::CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha,
            ])
            .with_signature_schemes(vec![
                SignatureScheme::Pkcs1WithSha256,
                SignatureScheme::Pkcs1WithSha1,
            ])
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_insecure_hashes(true)
            .with_insecure_verification(true)
            .with_verify_peer_certificate(Some(dtls_local::verify_client_chain_callback(root_der)))
            .build(false, None)
            .map_err(|e| anyhow!("DTLS config: {e}"))?;
        return Ok(Arc::new(config));
    }

    // Fallback: self-signed Ed25519 identity, no client certificate policy.
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
