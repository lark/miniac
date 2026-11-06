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
mod net;
mod radio;
mod roaming;
mod security;
mod settings;
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

/// Image name carried by a Reset Request's Image Identifier on the RFC and
/// TP-Link paths (AC100 names its own software version there). H3C ignores it:
/// its reset requests carry the fixed `all_version` image identifier.
const RESET_IMAGE_NAME: &[u8] = b"all_version";

/// Image Data block size used for firmware downloads. 512 bytes stays well
/// below the smallest MTU of the control path and matches the historical
/// transfer shape of the supported WTPs.
const IMAGE_BLOCK_SIZE: usize = 512;

/// Gap between the Image Data Response and the first block on the H3C path. The
/// AX60 reads datagrams while it waits for the answer to its Image Data Request
/// (WTP.dis `sub_15CB0`), so a block sent in the same burst never reaches its
/// Image Data state.
const FIRST_BLOCK_DELAY_MS: u64 = 500;

/// Delay before the H3C Run-state Reset Request. The AX60 answers a Reset
/// Request in the same burst as the last Image Data Response immediately
/// (result 0) but then does not flash or reboot (`CWWTPManageGenericRunMessage`
/// still holds the download state); sending the reset a moment later lets the
/// WTP settle and actually run `MW_UpdateApp`.
const RESET_DELAY: Duration = Duration::from_secs(3);

/// Gap between Reset Request retries while the WTP keeps its session. A reset
/// that takes effect reboots the WTP (the session dies), so retries only fire
/// when the previous reset did not stick.
const RESET_RETRY: Duration = Duration::from_secs(10);

/// Reset Requests sent before giving up on one transfer.
const RESET_ATTEMPTS: u32 = 3;

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

#[tokio::main]
async fn main() -> Result<()> {
    // Honor RUST_LOG (e.g. RUST_LOG=debug) for runtime message-level tracing.
    // Stamp events in the host's local time (with its UTC offset) so log files
    // line up with the host clock instead of UTC.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_timer(logx::LocalTimer)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let settings = settings::load()?;

    if let Some(dump_path) = &settings.dump_file {
        let path = dump_path
            .to_str()
            .ok_or_else(|| anyhow!("dump path {} is not UTF-8", dump_path.display()))?;
        dump::open(path)?;
        info!("[*] plaintext control dump -> {}", dump_path.display());
    }
    info!(
        "[*] CAPWAP peer allow list: {:?}; binds {:?}{}",
        settings.source.allow,
        settings.capwap.binds,
        settings
            .capwap
            .iface
            .as_ref()
            .map(|i| format!(" on {i}"))
            .unwrap_or_default()
    );

    // One DTLS identity per vendor profile: the detected device profile picks
    // the certificate directory (vendor override or the default identity set).
    let dtls_configs: Arc<
        HashMap<vendor::profile::VendorProfile, Arc<rtc_dtls::config::HandshakeConfig>>,
    > = {
        use vendor::profile::VendorProfile;
        let mut m = HashMap::new();
        for p in [
            VendorProfile::H3c,
            VendorProfile::TpLink,
            VendorProfile::Rfc,
        ] {
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
    // Liveness is runtime state: it stays in memory while the AC runs and is
    // written once on an orderly exit, so a WTP reporting every ~20 s costs no
    // disk write.
    {
        let devices = devices.clone();
        tokio::spawn(async move {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!("[!] SIGTERM handler unavailable: {e}");
                        return;
                    }
                };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
            info!("[*] exit: flushing runtime state");
            if let Err(e) = devices.flush_last_seen() {
                warn!("[!] last_seen flush failed: {e}");
            }
            logx::system("runtime state flushed".to_string());
            std::process::exit(0);
        });
    }
    let radios = Arc::new(radio::RadioStore::new(db.clone()));
    let stations = Arc::new(station::StationStore::new(db.clone()));
    let profiles = Arc::new(security::ProfileStore::new(db.clone())); // 802.1X / RSN policy store
    let fw = Arc::new(firmware::FirmwareStore::with_root(db.clone(), "firmware")); // image catalog + upgrade audit
    std::fs::create_dir_all("firmware")?;
    let fw_policy = Arc::new(firmware::FirmwarePolicy::new(db.clone())?); // join-time upgrade switch (default off)
    let upgrade_reg = Arc::new(firmware::UpgradeRegistry::new()); // web -> live-session firmware trigger
    let cfg_update_reg = Arc::new(config::ConfigUpdateRegistry::new()); // web -> live-session config-update trigger
    let wtp_cmd_reg = Arc::new(wtpcmd::WtpCmdRegistry::new()); // web -> live-session reset/disable/release-client trigger
    let wcfg = Arc::new(wcfg::WirelessConfigStore::new(db.clone())); // global wireless config + overrides + pending set
    let caps = Arc::new(fleet::ProductCapsStore::new(db.clone())); // product capability registry for the security recommender
    info!("[*] persistence ready (miniac.db)");
    logx::system("persistence initialized (miniac.db)".to_string());

    // M7: web management plane (REST + embedded frontend), shared store handles.
    // Defaults to loopback HTTP; HTTPS starts only when configured. A non-loopback
    // bind has no authentication, so it is announced loudly at startup.
    for warning in settings.web.warnings() {
        warn!("[!] {warning}");
        logx::system(warning);
    }
    let web_state = std::sync::Arc::new(web::AppData::new(
        devices.clone(),
        radios.clone(),
        stations.clone(),
        profiles.clone(),
        fw.clone(),
        fw_policy.clone(),
        upgrade_reg.clone(),
        cfg_update_reg.clone(),
        wtp_cmd_reg.clone(),
        wcfg.clone(),
        caps.clone(),
    ));
    {
        let web_settings = settings.web.clone();
        tokio::spawn(async move {
            if let Err(e) = web::serve(web_state, web_settings).await {
                error!("web server: {e}");
            }
        });
    }

    // M8: H3C FIT-AP stage-1 discovery responder. The WTP leases its own IP,
    // gateway and the AC address (DHCP-like) over the private port 10087 before
    // it starts CAPWAP unicast on 5246. The pool defaults to
    // 192.168.5.50..192.168.5.80 (persisted in miniac.db); the AC address is
    // the address the request arrived on, so a multihomed AC needs no override.
    if settings.stage1.enabled {
        let stage_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), stage1::STAGE1_PORT);
        let pool = std::sync::Arc::new(stage1::AcPool::prefill(
            db.clone(),
            settings.stage1.pool_start,
            settings.stage1.pool_end,
            settings.stage1.gateway,
            settings.stage1.netmask(),
        )?);
        info!(
            "[*] stage-1 pool {}-{} (net {}/{}) gw {}",
            settings.stage1.pool_start,
            settings.stage1.pool_end,
            settings.stage1.net.0,
            settings.stage1.net.1,
            settings
                .stage1
                .gateway
                .map(|g| g.to_string())
                .unwrap_or_else(|| "ingress AC".to_string()),
        );
        let source = std::sync::Arc::new(settings.source.clone());
        let iface = settings.capwap.iface.clone();
        let net = settings.stage1.net;
        tokio::spawn(async move {
            if let Err(e) = stage1::serve(stage_bind, pool, source, iface, net).await {
                error!("stage-1 discovery server: {e}");
            }
        });
    } else {
        info!("[*] stage-1 discovery responder disabled");
    }

    // CAPWAP control plane: one UDP socket per configured bind (RFC 5415 control
    // port is fixed at 5246; only the bind address is configurable). With no
    // bind, listen on the IPv4 and IPv6 wildcards to receive broadcast
    // discovery; a specific unicast bind receives no broadcast, so discovery
    // must then be unicast or DTLS to that address.
    let source = std::sync::Arc::new(settings.source.clone());
    let mut control_tasks = Vec::new();
    for bind in &settings.capwap.binds {
        let socket = match net::bind_udp(*bind, settings.capwap.iface.as_deref()) {
            Ok(s) => Arc::new(s),
            Err(e) if bind.ip().is_unspecified() && bind.is_ipv6() => {
                // IPv6 may be disabled on the host; the IPv4 wildcard still
                // serves the APs.
                warn!("[!] CAPWAP bind {bind} unavailable, continuing without IPv6: {e}");
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        info!("[!] miniac control listening on {bind}");
        logx::system(format!("AC control listening on {bind}"));
        control_tasks.push(tokio::spawn(run_control_socket(
            socket,
            dispatcher_map.clone(),
            peer_profiles.clone(),
            dtls_configs.clone(),
            devices.clone(),
            radios.clone(),
            stations.clone(),
            fw.clone(),
            fw_policy.clone(),
            upgrade_reg.clone(),
            cfg_update_reg.clone(),
            wtp_cmd_reg.clone(),
            wcfg.clone(),
            source.clone(),
            settings.h3c,
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
    dtls_configs: Arc<
        HashMap<vendor::profile::VendorProfile, Arc<rtc_dtls::config::HandshakeConfig>>,
    >,
    devices: Arc<device::DeviceStore>,
    radios: Arc<radio::RadioStore>,
    stations: Arc<station::StationStore>,
    fw: Arc<firmware::FirmwareStore>,
    fw_policy: Arc<firmware::FirmwarePolicy>,
    upgrade_reg: Arc<firmware::UpgradeRegistry>,
    cfg_update_reg: Arc<config::ConfigUpdateRegistry>,
    wtp_cmd_reg: Arc<wtpcmd::WtpCmdRegistry>,
    wcfg: Arc<wcfg::WirelessConfigStore>,
    source: Arc<settings::SourceFilter>,
    h3c: settings::H3cSettings,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    // Rate-limited log for dropped peers: an exposed AC must not let a remote
    // scanner turn drops into unbounded log/CPU work.
    let mut last_drop_log = Instant::now() - Duration::from_secs(60);
    let mut dropped = 0u64;
    loop {
        let (n, peer, info) = net::recv_from(&socket, &mut buf).await?;
        if !source.permits(peer.ip(), &info) {
            dropped += 1;
            if last_drop_log.elapsed() >= Duration::from_secs(5) {
                warn!(
                    "[?] {} CAPWAP packet(s) from disallowed source(s) dropped (last {})",
                    dropped, peer
                );
                dropped = 0;
                last_drop_log = Instant::now();
            }
            continue;
        }
        let pkt = buf[..n].to_vec();
        // AC address(es) for this datagram: the destination for unicast, the
        // ingress interface's addresses for broadcast/multicast. This lets a
        // multihomed AC advertise only addresses the WTP can reach.
        let mut ac_ips = net::ac_ipv4_list(&info, socket.local_addr().ok());
        if ac_ips.is_empty() {
            warn!(
                "[!] from {}: no AC address on ifindex {}, falling back to 192.168.0.2",
                peer, info.ifindex
            );
            ac_ips.push(Ipv4Addr::new(192, 168, 0, 2));
        }
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
                info!(
                    "[<] from {}: Discovery Request on a live address, replacing session",
                    peer
                );
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
                // Request.
                let prof = VendorProfile::detect(&pkt);
                peer_profiles.lock().await.insert(peer.ip(), prof);

                // The AC advertises its own control address (AC IPv4 List) so
                // the WTP knows which destination to start DTLS/Join against.
                match prof.discovery_response(&pkt, &ac_ips, b"My AC") {
                    Some(resp) => {
                        logx::device(format!("Discovery response to {} ({}B)", peer, resp.len()));
                        socket.send_to(&resp, peer).await?;
                    }
                    None => warn!("[?] disc req from {} not {:?}-framed, dropped", peer, prof),
                }
            }
        }

        // A fresh DTLS hello: reuse the profile detected at Discovery for this
        // peer's address (WTPs often start DTLS from a new source port). A
        // ClientHello carries no vendor information, so an unknown peer falls
        // back to the vendor-neutral RFC profile until a Discovery refines it.
        let prof = known_profile.unwrap_or_default();
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
                fw_policy.clone(),
                upgrade_reg.clone(),
                cfg_update_reg.clone(),
                wtp_cmd_reg.clone(),
                wcfg.clone(),
                ac_ips[0],
                h3c,
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
    match elems
        .get(&MsgElemType::WTP_BOARD_DATA)
        .and_then(|v| v.first())
    {
        Some(CwElem::Unknown(_, body)) => elements::WtpBoardData::decode(body)?.base_mac(),
        _ => None,
    }
}

/// WTP model string from the WTP Board Data model number (RFC 5415 §4.6.40
/// sub-element 0). WTPs report it either as a NUL-padded text name (H3C
/// "SWBA1B0") or as a binary model code, which is rendered as hex.
fn wtp_model_from_elems(elems: &HashMap<u16, Vec<CwElem>>) -> Option<String> {
    let Some(CwElem::Unknown(_, body)) = elems
        .get(&MsgElemType::WTP_BOARD_DATA)
        .and_then(|v| v.first())
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
    fw_policy: Arc<firmware::FirmwarePolicy>,
    upgrade: Arc<firmware::UpgradeRegistry>,
    cfg_update: Arc<config::ConfigUpdateRegistry>,
    wtp_cmd: Arc<wtpcmd::WtpCmdRegistry>,
    wcfg: Arc<wcfg::WirelessConfigStore>,
    ac_ip: Ipv4Addr,
    h3c: settings::H3cSettings,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel(100);
    map.lock().await.insert(peer, tx.clone());

    let sock_clone = Arc::clone(socket);
    let conf_clone = Arc::clone(config);

    tokio::spawn(async move {
        info!("[*] with {}: session thread spawned ({:?})", peer, profile);
        if let Err(e) = handle_session(
            peer, profile, rx, sock_clone, conf_clone, devices, radios, stations, fw, fw_policy,
            upgrade, cfg_update, wtp_cmd, wcfg, ac_ip, h3c,
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

/// Resolve the image a WTP asked for in the Image Identifier of its Image Data
/// Request: an exact catalogue match wins, otherwise the newest image for the
/// device's vendor / model / hardware version is selected.
fn requested_image(
    fw: &firmware::FirmwareStore,
    devices: &device::DeviceStore,
    mac: Option<device::Mac>,
    elems: &HashMap<u16, Vec<CwElem>>,
) -> Option<(firmware::FirmwareImage, firmware::ImageIdentifier)> {
    // Image Identifier body: vendor id (u32 BE) followed by the image name.
    let raw = match elems.get(&MsgElemType::IMAGE_ID)?.first()? {
        CwElem::Unknown(_, data) => data,
        _ => return None,
    };
    if raw.len() < 4 {
        return None;
    }
    let vendor_id = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let id = firmware::ImageIdentifier {
        vendor_id,
        name: raw[4..].to_vec(),
    };
    let dev = mac.and_then(|m| devices.get(m).ok().flatten());
    let vendor = dev
        .as_ref()
        .and_then(|d| d.vendor.clone())
        .unwrap_or_default();
    let model = dev
        .as_ref()
        .and_then(|d| d.model.clone())
        .unwrap_or_default();
    let hw = dev
        .as_ref()
        .and_then(|d| d.hw_version.clone())
        .unwrap_or_default();
    // The identifier payload is a UTF-8 name under RFC or H3C and a binary
    // version under TP-Link; only the catalogue hint is textual either way.
    let requested = String::from_utf8_lossy(&id.name);
    let requested = requested.trim_matches('\0');
    match fw.select_for_wtp(requested, &vendor, &model, &hw) {
        Ok(Some(img)) => Some((img, id)),
        Ok(None) => None,
        Err(e) => {
            warn!("[!] firmware catalogue lookup failed: {}", e);
            None
        }
    }
}

/// Image Data Response (RFC 5415 9.1.2): Result Code is mandatory, Image
/// Information (size + MD5 of the whole image) is AC-side and optional.
fn image_data_response(seq: u32, result: u8, info: Option<&firmware::ImageInfo>) -> CtrlMsg {
    let mut msg =
        CtrlMsg::new(MsgType::IMAGE_DATA_RESP, seq).add_element(BaseElem::ResultCode(result));
    if let Some(info) = info {
        msg = msg.add_elem(MsgElemType::IMAGE_INFO, &info.encode());
    }
    msg
}

/// Transmit one Image Data block. `pending_seq` records the request sequence so
/// a stale Image Data Response cannot advance the transfer.
async fn send_image_block(
    capdtls: &mut connection::CapwapDtls,
    ctx: &mut WtpContext,
    fw_upgrade: &mut firmware::FirmwareUpgrade,
    profile: vendor::profile::VendorProfile,
    peer: SocketAddr,
    blk: &firmware::ImageDataBlock,
) -> Result<()> {
    let mut dl = CtrlMsg::new(MsgType::IMAGE_DATA_REQ, ctx.next_seq())
        .add_elem(MsgElemType::IMAGE_DATA, &blk.encode());
    // AC100 repeats the size/MD5 in every Image Data Request (its
    // `apupd_image_request_create` 0x538df8 adds element 26 alongside 24). The
    // AX60 rejects any element other than 24 in an Image Data Request
    // (`sub_249A8` -> "Unrecognized Message Element"), so H3C gets only 24.
    if profile != vendor::profile::VendorProfile::H3c {
        if let Some(info) = fw_upgrade.info.as_ref() {
            dl = dl.add_elem(MsgElemType::IMAGE_INFO, &info.encode());
        }
    }
    let buf = dl.encode_for(frame(profile));
    capdtls.write(&buf).await?;
    fw_upgrade.pending_seq = Some(dl.hdr.seq_num);
    ctx.set_last_sent(&dl, buf);
    info!(
        "[>] to {}: image data block ({}B) sent",
        peer,
        blk.data.len()
    );
    Ok(())
}

/// Answer a WTP Image Data Request: the Image Data Response (RFC 5415 9.1.2),
/// then the first block of the transfer.
///
/// The M60 AC answers with the Result Code alone on both upgrade entries
/// (`CWAssembleImageDataResponseByAC` is called with no image information from
/// `ACEnterImageData` and `ACEnterRun`), so H3C gets no Image Information
/// element. Its AX60 then asks for the blocks and flashes the image itself.
async fn start_image_transfer(
    capdtls: &mut connection::CapwapDtls,
    ctx: &mut WtpContext,
    fw_upgrade: &mut firmware::FirmwareUpgrade,
    profile: vendor::profile::VendorProfile,
    peer: SocketAddr,
    seq: u32,
) -> Result<()> {
    let info = if profile == vendor::profile::VendorProfile::H3c {
        None
    } else {
        fw_upgrade.info.clone()
    };
    let resp = image_data_response(seq, 0, info.as_ref());
    let buf = resp.encode_for(frame(profile));
    capdtls.write(&buf).await?;
    ctx.set_last_sent(&resp, buf);
    match &info {
        Some(i) => info!(
            "[>] to {}: image data resp (size {}, MD5 advertised)",
            peer, i.file_size
        ),
        None => info!("[>] to {}: image data resp (result code only)", peer),
    }
    // The AX60 reads datagrams itself while waiting for its request's answer
    // (WTP.dis `sub_15CB0`), so a block written in the same burst is consumed by
    // that wait and never reaches the Image Data state. The M60 AC leaves that
    // gap naturally by sending the first block on its next state tick.
    if profile == vendor::profile::VendorProfile::H3c {
        tokio::time::sleep(Duration::from_millis(FIRST_BLOCK_DELAY_MS)).await;
    }
    if let Some(blk) = fw_upgrade.current().cloned() {
        send_image_block(capdtls, ctx, fw_upgrade, profile, peer, &blk).await?;
    }
    Ok(())
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
    fw_policy: Arc<firmware::FirmwarePolicy>,
    upgrade: Arc<firmware::UpgradeRegistry>,
    cfg_update: Arc<config::ConfigUpdateRegistry>,
    wtp_cmd: Arc<wtpcmd::WtpCmdRegistry>,
    wcfg: Arc<wcfg::WirelessConfigStore>,
    ac_ip: Ipv4Addr,
    h3c: settings::H3cSettings,
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
    // The peer's framing decides the Sequence Number width (and its wrap).
    ctx.frame = frame(profile);
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
    // H3C Run-state upgrade: the Reset Request is deferred and repeated (see
    // RESET_DELAY / RESET_RETRY); a successful reset ends the session.
    let mut reset_due: Option<Instant> = None;
    let mut reset_attempts: u32 = 0;

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
        let next_echo = ctx
            .echo_interval
            .saturating_sub(ctx.last_echo_sent.elapsed());
        // Also wake in time to release the next serialized vendor push frame if
        // the WTP's reply does not arrive.
        let next_push = if ctx.push_queue.is_empty() {
            Duration::from_secs(60)
        } else {
            ctx.push_last_sent.map_or(Duration::ZERO, |t| {
                PUSH_REPLY_TIMEOUT.saturating_sub(t.elapsed())
            })
        };
        // Also wake in time for a deferred H3C Run-state reset.
        let next_reset = reset_due
            .map(|at| at.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_secs(60));
        let mut sleep_duration = std::cmp::min(
            retrans_duration,
            std::cmp::min(
                idle_duration,
                std::cmp::min(next_echo, std::cmp::min(next_push, next_reset)),
            ),
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
                    // Liveness for the management plane: any control traffic from
                    // this WTP counts as online. The in-memory timestamp avoids a
                    // database write per (TP-Link: 2 s) keep-alive.
                    if let Some(mac) = ctx.mac {
                        devices.mark_live(mac);
                    }

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
                    // The AX60 channel-utilization report carries a fixed sequence
                    // on every retransmission (WTP.dis 0x2c5a4), so it is exempt
                    // from the ordering check and handled once per arrival.
                    if MsgType::is_request(m_type) && m_type != vendor::h3c::WTP_CHAN_UTIL_REQ {
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
                            // H3C's descriptor is not the RFC two-u32 form: its
                            // first byte is the hardware revision (AX60: 2, shown
                            // as VER.B), and the human versions ride private
                            // elements 0x40 (release, e.g. SWBA1B0V100R010 ->
                            // R010) and 0x3D (build, SWBA1B0V100D017 -> D017).
                            // The model itself stays the Board Data name
                            // (SWBA1B0). Override the generic 8-hex reading.
                            if profile == vendor::profile::VendorProfile::H3c {
                                if let Some(body) = msg
                                    .find_elems(MsgElemType::WTP_DESCRIPTOR)
                                    .next()
                                    .map(|e| e.data.as_slice())
                                {
                                    if let Some(hw) = vendor::h3c::descriptor_hardware_version(body) {
                                        hw_ver = Some(hw.to_string());
                                    }
                                }
                                sw_ver = msg
                                    .find_elems(vendor::h3c::ELEM_RELEASE_VERSION)
                                    .next()
                                    .and_then(|e| vendor::h3c::short_version(&e.data))
                                    .or_else(|| {
                                        msg.find_elems(vendor::h3c::ELEM_BUILD_VERSION)
                                            .next()
                                            .and_then(|e| vendor::h3c::short_version(&e.data))
                                    })
                                    .or(sw_ver);
                                info!(
                                    "[*] h3c versions: hw {}, sw {}",
                                    hw_ver.as_deref().unwrap_or("-"),
                                    sw_ver.as_deref().unwrap_or("-")
                                );
                            }
                            // TP-Link reports the binary codes in the RFC-shaped
                            // descriptor; the vendor records inside the same
                            // element carry the human versions AC100 displays
                            // (hardware "2.0", software "1.0.4"), and the model
                            // record (private 81) carries the model name.
                            let mut model: Option<String> = None;
                            if profile == vendor::profile::VendorProfile::TpLink {
                                if let Some(body) = msg
                                    .find_elems(MsgElemType::WTP_DESCRIPTOR)
                                    .next()
                                    .map(|e| e.data.as_slice())
                                {
                                    if let Some(v) = vendor::tplink::parse_descriptor_versions(body) {
                                        if v.hardware.is_some() {
                                            hw_ver = v.hardware;
                                        }
                                        if v.software.is_some() {
                                            sw_ver = v.software;
                                        }
                                    }
                                }
                                model = msg
                                    .find_elems(MsgElemType::VENDOR_SPECIFIC_PAYLOAD)
                                    .filter_map(|e| vendor::tplink::parse_model_info(&e.data))
                                    .next();
                            }
                            if model.is_none() {
                                model = wtp_model_from_elems(&elems);
                            }
                            // Persist device learned from the join exchange (keyed by MAC).
                            let mut join_image: Option<Vec<u8>> = None;
                            if let Some(mac) = wtp_mac_from_elems(&elems, profile) {
                                ctx.mac = Some(mac);
                                devices.mark_live(mac);
                                let ip = peer.ip().to_string();
                                let created = devices.register(mac, Some(&ip), sw_ver.as_deref(), None, None, "registered")?;
                                devices.set_identity(
                                    mac,
                                    Some(profile.vendor_name()),
                                    model.as_deref(),
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
                                // H3C join-time entry (M60 `ACEnterJoin`): an image
                                // queued for an offline WTP is announced in the
                                // Join Response, so this WTP downloads it before
                                // taking any configuration instead of from the
                                // Run state.
                                if profile == vendor::profile::VendorProfile::H3c {
                                    if !fw_policy.update_on_join() {
                                        // Startup updates are opt-in: a power
                                        // restore must not start every AP's
                                        // download at once.
                                        debug!("[*] join: startup firmware update disabled, no image announced");
                                    } else if let Some(id) = upgrade.take_pending(mac) {
                                        match fw.get_image(id) {
                                            Ok(Some(img)) => match fw.load_image_bytes(id) {
                                                Ok(Some(bytes)) => {
                                                    let name = img.file_name.clone().into_bytes();
                                                    fw_upgrade.announce(
                                                        bytes,
                                                        IMAGE_BLOCK_SIZE,
                                                        firmware::ImageIdentifier {
                                                            vendor_id: vendor::h3c::IMAGE_ID_PREFIX,
                                                            name: name.clone(),
                                                        },
                                                    );
                                                    join_image = Some(name);
                                                    logx::firmware(format!(
                                                        "firmware {} announced to {} in the join response",
                                                        img.stored_path,
                                                        device::mac_to_str(mac)
                                                    ));
                                                }
                                                Ok(None) => warn!(
                                                    "[!] queued image {} missing from disk",
                                                    img.stored_path
                                                ),
                                                Err(e) => warn!(
                                                    "[!] cannot read queued image {}: {}",
                                                    img.stored_path, e
                                                ),
                                            },
                                            Ok(None) => {
                                                warn!("[!] queued image {} no longer catalogued", id)
                                            }
                                            Err(e) => {
                                                warn!("[!] queued image {} lookup failed: {}", id, e)
                                            }
                                        }
                                    }
                                }
                            } else {
                                debug!("[*] join: no WTP Board Data MAC present");
                            }
                            // response
                            // The H3C join form keeps the AX60-specific element
                            // set (the tag-10 value must be the 6-byte AC IPv4
                            // entry; WTP.dis 0x23754 counts entries and re-parses
                            // each at 0x1df5c). The RFC / TP-Link form uses the
                            // standards-shaped builder.
                            let resp_msg = match join_image.as_deref() {
                                Some(name) => {
                                    vendor::h3c::join_response_with_image(seq, ac_ip, name)
                                }
                                None => profile.join_response(seq, ac_ip, b"miniac", true),
                            };
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);

                            ctx.state = WtpState::Configure;
                            info!(
                                "[>] to {}: join resp sent{}, state -> Configure",
                                peer,
                                if join_image.is_some() {
                                    " (image identifier announced)"
                                } else {
                                    ""
                                }
                            );
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
                                let wtp_saved_wlans = elems
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
                            // Advanced radio features (fe28 OFDMA/MU-MIMO, fe31
                            // band navigation): configured in [h3c]; all-zero
                            // omits the element.
                            let fe28 = if h3c.ofdma != 0 || h3c.mumimo != 0 {
                                Some((h3c.ofdma, h3c.mumimo))
                            } else {
                                None
                            };
                            let fe31 = (h3c.band_navigation != 0).then_some(h3c.band_navigation);
                            // LED state is remembered per device: the web toggle
                            // stores it even when the AP is offline, so a WTP that
                            // reboots gets its saved state (typically "off") in
                            // this Configure-stage snapshot, before it enters Run.
                            let led = devices.get(mac)?.and_then(|d| d.led_on);
                            // Effective per-band radio settings (global template
                            // merged with the AP override) are carried by the
                            // H3C 0xfde8 band headers; H3C only.
                            let radio_headers = [
                                wcfg.effective_radio(mac, 1)?,
                                wcfg.effective_radio(mac, 2)?,
                            ];
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
                                        radios: radio_headers,
                                        fe28,
                                        fe31,
                                        led,
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
                                    let hdr = wcfg.effective_radio(mac, radio_id)?;
                                    // A disabled radio stays administratively down:
                                    // only the bare state element goes out, with no
                                    // channel record that would bring it up.
                                    if !hdr.enable {
                                        let msg = vendor::tplink::radio_admin_state_request(
                                            ctx.next_seq(),
                                            radio_id,
                                            2,
                                        );
                                        ctx.push_msg(msg.encode_for(frame(profile)));
                                        continue;
                                    }
                                    let channel = vendor::tplink::channel_field(hdr.channel);
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
                                            hdr.power,
                                            hdr.mode,
                                            hdr.bandwidth,
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
                                // Re-apply the remembered LED setting: an AP
                                // restart resets its LED, so the last state the
                                // operator chose (or the WTP reported) is pushed
                                // again. Unknown (never reported) pushes nothing.
                                if let Some(on) = devices.get(mac)?.and_then(|d| d.led_on) {
                                    let seq = ctx.next_seq();
                                    ctx.burst_msg(
                                        profile
                                            .led_update_request(seq, on)
                                            .encode_for(frame(profile)),
                                    );
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

                        (WtpState::Run | WtpState::ImageData, MsgType::ECHO_REQ) => {
                            debug!("[<] from {}: echo req (seq {})", peer, seq);
                            // TP-Link repeats its private records in every Echo
                            // Request, including private 56 (LED status): the
                            // WTP's current LED state is authoritative, so a
                            // change (operator push or autonomous) is recorded
                            // and persisted for the management plane.
                            if profile == vendor::profile::VendorProfile::TpLink {
                                let reported = elems
                                    .get(&MsgElemType::VENDOR_SPECIFIC_PAYLOAD)
                                    .and_then(|items| {
                                        items.iter().find_map(|item| match item {
                                            CwElem::Unknown(_, v) => {
                                                vendor::tplink::parse_led_status(v)
                                            }
                                            _ => None,
                                        })
                                    });
                                if let Some(on) = reported {
                                    if ctx.led_on != Some(on) {
                                        ctx.led_on = Some(on);
                                        if let Some(mac) = ctx.mac {
                                            match devices.set_led_on(mac, on) {
                                                Ok(()) => logx::device(format!(
                                                    "WTP {} LED is {}",
                                                    device::mac_to_str(mac),
                                                    if on { "on" } else { "off" }
                                                )),
                                                Err(e) => {
                                                    warn!("[!] LED state persist failed: {}", e)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            let resp_msg = CtrlMsg::new(MsgType::ECHO_RESP, seq);
                            let resp_buf = resp_msg.encode_for(frame(profile));
                            capdtls.write(&resp_buf).await?;
                            ctx.set_last_sent(&resp_msg, resp_buf);
                            debug!("[>] to {}: echo resp", peer);
                        }
                        (WtpState::Run | WtpState::ImageData, MsgType::ECHO_RESP) => {
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

                        (_, t) if t == vendor::h3c::WTP_CHAN_UTIL_REQ => {
                            // AX60 channel-utilization report (element 0xfe20,
                            // [2G%, 5G%]); ack with mtype 146 + zero Result Code
                            // so the WTP drops its pending copy instead of
                            // retransmitting every 10s. The AX60 also reports
                            // while it is in Configure or Image Data state.
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
                                // This traffic also proves the WTP is alive;
                                // `last_seen` stays in memory and only reaches
                                // the DB when the AC exits normally.
                                if let Some(mac) = ctx.mac {
                                    devices.mark_live(mac);
                                }
                            }
                            // Periodic event reports carry no auditable state
                            // change (station changes are logged above only when
                            // they alter the set), so they are not written to
                            // the management log ring.
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
                                    // H3C M60: Result 17 "Image Already Present"
                                    // makes the AC reset the WTP at once instead
                                    // of downloading (`CWSaveConfigurationUpdate-
                                    // ResponseMessage` 0x1002c6bc -> `sub_100315b0`).
                                    if profile == vendor::profile::VendorProfile::H3c
                                        && resp.result_code == 17
                                        && fw_upgrade.state == firmware::UpgradeState::Announced
                                    {
                                        let name = match fw_upgrade.image_id.as_ref() {
                                            Some(id) => id.name.clone(),
                                            None => RESET_IMAGE_NAME.to_vec(),
                                        };
                                        let req = profile.reset_request(ctx.next_seq(), &name);
                                        let buf = req.encode_for(frame(profile));
                                        capdtls.write(&buf).await?;
                                        ctx.set_last_sent(&req, buf);
                                        fw_upgrade.reset_sent();
                                        logx::firmware(format!(
                                            "image already present on {}; reset requested",
                                            peer
                                        ));
                                    }
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

                        // RFC 5415 9.1, Image Data state: a WTP that joined
                        // without the expected image asks for a download before
                        // configuration. The AC enters Image Data, advertises the
                        // image (size, MD5) and streams the blocks; the WTP resets
                        // itself once the transfer completes.
                        (WtpState::Join | WtpState::Configure | WtpState::ImageData, MsgType::IMAGE_DATA_REQ) => {
                            info!("[<] from {}: image data req (seq {})", peer, seq);
                            let wants = elems.contains_key(&MsgElemType::INIT_DOWNLOAD)
                                || elems.contains_key(&MsgElemType::IMAGE_ID);
                            if !wants {
                                debug!("[<] from {}: image data req carries no download request", peer);
                                continue;
                            }
                            if fw_upgrade.session.is_none() {
                                let (img, bytes, id) = match requested_image(&fw, &devices, ctx.mac, &elems) {
                                    Some((img, id)) => match fw.load_image_bytes(img.id) {
                                        Ok(Some(bytes)) => (img, bytes, id),
                                        Ok(None) => {
                                            warn!("[!] image {} missing from disk", img.stored_path);
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!("[!] cannot read image {}: {}", img.stored_path, e);
                                            continue;
                                        }
                                    },
                                    None => {
                                        warn!("[!] from {}: no catalogued image for the requested identifier", peer);
                                        let resp = image_data_response(seq, 1, None);
                                        let buf = resp.encode_for(frame(profile));
                                        capdtls.write(&buf).await?;
                                        ctx.set_last_sent(&resp, buf);
                                        continue;
                                    }
                                };
                                let mac = ctx.mac.unwrap_or([0; 6]);
                                match fw.record_start(&mac, &img.stored_path, img.size as u32, &img.hash) {
                                    Ok(rid) => fw_record_id = Some(rid),
                                    Err(e) => warn!("[!] firmware record start failed: {}", e),
                                }
                                logx::firmware(format!(
                                    "firmware {} download started for {} (Image Data state)",
                                    img.stored_path,
                                    device::mac_to_str(mac)
                                ));
                                fw_upgrade.begin(bytes, IMAGE_BLOCK_SIZE, id);
                            }
                            // The image may already be loaded and announced (the
                            // Join Response carried its identifier): start the
                            // transfer without re-reading the catalogue.
                            if fw_upgrade.state == firmware::UpgradeState::Announced {
                                fw_upgrade.start_download();
                            }
                            if fw_upgrade.session.is_some() && ctx.state != WtpState::ImageData {
                                // The WTP asked for the image before configuration,
                                // so it is in Image Data state; mirror it here so
                                // its Image Data Responses advance the transfer.
                                ctx.state = WtpState::ImageData;
                                info!("[>] to {}: state -> ImageData", peer);
                            }
                            start_image_transfer(
                                &mut capdtls,
                                &mut ctx,
                                &mut fw_upgrade,
                                profile,
                                peer,
                                seq,
                            )
                            .await?;
                        }

                        // RFC 5415 9.1, Run state: the WTP was told the image in
                        // a Configuration Update Request and answers with its own
                        // Image Data Request / Initiate Download. The transfer
                        // then runs in the Run state and the WTP resets only when
                        // the AC sends a Reset Request.
                        (WtpState::Run, MsgType::IMAGE_DATA_REQ) => {
                            info!("[<] from {}: image data req (seq {})", peer, seq);
                            let wants = elems.contains_key(&MsgElemType::INIT_DOWNLOAD)
                                || elems.contains_key(&MsgElemType::IMAGE_ID);
                            if !wants {
                                debug!("[<] from {}: image data req carries no download request", peer);
                                continue;
                            }
                            if fw_upgrade.session.is_none() {
                                if let Some((img, id)) = requested_image(&fw, &devices, ctx.mac, &elems) {
                                    match fw.load_image_bytes(img.id) {
                                        Ok(Some(bytes)) => {
                                            let mac = ctx.mac.unwrap_or([0; 6]);
                                            match fw.record_start(&mac, &img.stored_path, img.size as u32, &img.hash) {
                                                Ok(rid) => fw_record_id = Some(rid),
                                                Err(e) => warn!("[!] firmware record start failed: {}", e),
                                            }
                                            logx::firmware(format!(
                                                "firmware {} download started for {} (Run state)",
                                                img.stored_path,
                                                device::mac_to_str(mac)
                                            ));
                                            fw_upgrade.begin(bytes, IMAGE_BLOCK_SIZE, id);
                                        }
                                        Ok(None) => warn!("[!] image {} missing from disk", img.stored_path),
                                        Err(e) => warn!("[!] cannot read image {}: {}", img.stored_path, e),
                                    }
                                }
                            }
                            if fw_upgrade.session.is_some() {
                                if fw_upgrade.state == firmware::UpgradeState::Announced {
                                    fw_upgrade.start_download();
                                }
                                start_image_transfer(
                                    &mut capdtls,
                                    &mut ctx,
                                    &mut fw_upgrade,
                                    profile,
                                    peer,
                                    seq,
                                )
                                .await?;
                            } else {
                                warn!("[!] from {}: no image available for the download request", peer);
                                let resp = image_data_response(seq, 1, None);
                                let buf = resp.encode_for(frame(profile));
                                capdtls.write(&buf).await?;
                                ctx.set_last_sent(&resp, buf);
                            }
                        }

                        (WtpState::Run | WtpState::ImageData, MsgType::IMAGE_DATA_RESP) => {
                            info!("[<] from {}: image data resp (seq {})", peer, seq);
                            if fw_upgrade.pending_seq != Some(seq) || fw_upgrade.inflight.is_none() {
                                debug!("[<] from {}: image data resp does not ack the in-flight block", peer);
                                continue;
                            }
                            let code = vendor::h3c::result_code(&msg).unwrap_or(0);
                            if code != 0 {
                                warn!("[!] from {}: image data rejected (result {})", peer, code);
                                logx::firmware(format!("firmware transfer to {} aborted (result {})", peer, code));
                                fw_upgrade.abort();
                                continue;
                            }
                            fw_upgrade.pending_seq = None;
                            fw_upgrade.complete_block();
                            if let Some(blk) = fw_upgrade.current().cloned() {
                                send_image_block(&mut capdtls, &mut ctx, &mut fw_upgrade, profile, peer, &blk).await?;
                            } else if fw_upgrade.state == firmware::UpgradeState::AwaitReset {
                                if let Some(id) = fw_record_id.take() {
                                    let _ = fw.mark_done(id);
                                }
                                if ctx.state == WtpState::Run
                                    && profile == vendor::profile::VendorProfile::H3c
                                {
                                    // The AX60 acknowledges a Reset Request that
                                    // lands in the same burst as the last Image
                                    // Data Response but does not act on it, so
                                    // defer it and retry while the session lives.
                                    reset_due = Some(Instant::now() + RESET_DELAY);
                                    reset_attempts = 0;
                                    logx::firmware(format!(
                                        "firmware transfer complete; reset scheduled for {}",
                                        peer
                                    ));
                                    fw_upgrade.reset_sent();
                                } else if ctx.state == WtpState::Run
                                    && profile != vendor::profile::VendorProfile::TpLink
                                {
                                    // Run-state download: the WTP holds the image
                                    // until the administrative Reset Request.
                                    let name = match fw_upgrade.image_id.as_ref() {
                                        Some(id) => id.name.clone(),
                                        None => RESET_IMAGE_NAME.to_vec(),
                                    };
                                    let reset = profile.reset_request(ctx.next_seq(), &name);
                                    let buf = reset.encode_for(frame(profile));
                                    capdtls.write(&buf).await?;
                                    ctx.set_last_sent(&reset, buf);
                                    logx::firmware(format!("firmware transfer complete; reset requested for {}", peer));
                                    fw_upgrade.reset_sent();
                                } else if ctx.state == WtpState::Run {
                                    // TP-Link APs verify, write and reboot on their
                                    // own once the EOF block is acknowledged; a
                                    // Reset Request now could interrupt the flash
                                    // write, so none is sent.
                                    logx::firmware(format!(
                                        "firmware transfer complete for {}; TP-Link AP writes and reboots into the new image",
                                        peer
                                    ));
                                    fw_upgrade.finish();
                                } else {
                                    // Image Data state: the WTP enters Reset itself
                                    // after acknowledging the EOF block.
                                    logx::firmware(format!(
                                        "firmware transfer complete for {}; WTP resets into the new image",
                                        peer
                                    ));
                                    fw_upgrade.finish();
                                }
                            }
                        }

                        // RFC 5415 9.1 (Run state): the Configuration Update
                        // Response confirms the announced image or reports that
                        // the WTP already holds it.
                        (WtpState::Run, MsgType::CONFIG_UPDATE_RESP) => {
                            if fw_upgrade.state != firmware::UpgradeState::Announced {
                                debug!("[<] from {}: config update resp (seq {})", peer, seq);
                                continue;
                            }
                            let code = vendor::h3c::result_code(&msg).unwrap_or(0);
                            if code == 0 {
                                info!("[>] to {}: image announced; awaiting Initiate Download", peer);
                                continue;
                            }
                            let name = match fw_upgrade.image_id.as_ref() {
                                Some(id) => id.name.clone(),
                                None => RESET_IMAGE_NAME.to_vec(),
                            };
                            fw_upgrade.abort();
                            if code == 17 {
                                // Image Already Present: skip the transfer and
                                // reset the WTP into that image.
                                logx::firmware(format!(
                                    "WTP {} already holds the announced image; reset requested",
                                    peer
                                ));
                                if let Some(id) = fw_record_id.take() {
                                    let _ = fw.mark_done(id);
                                }
                                let reset = profile.reset_request(ctx.next_seq(), &name);
                                let buf = reset.encode_for(frame(profile));
                                capdtls.write(&buf).await?;
                                ctx.set_last_sent(&reset, buf);
                            } else {
                                warn!("[!] from {}: image announcement rejected (result {})", peer, code);
                                logx::firmware(format!(
                                    "firmware download to {} refused by the WTP (result {})",
                                    peer, code
                                ));
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

                // H3C Run-state upgrade: send (or repeat) the Reset Request once
                // the deferred deadline passes. A reset that flashes the image
                // reboots the WTP, so a surviving session means the previous one
                // was not acted on (see RESET_DELAY).
                if let Some(at) = reset_due {
                    if now >= at {
                        let name = fw_upgrade
                            .image_id
                            .as_ref()
                            .map(|id| id.name.clone())
                            .unwrap_or_else(|| RESET_IMAGE_NAME.to_vec());
                        let reset = profile.reset_request(ctx.next_seq(), &name);
                        let buf = reset.encode_for(frame(profile));
                        capdtls.write(&buf).await?;
                        ctx.set_last_sent(&reset, buf);
                        reset_attempts += 1;
                        if reset_attempts < RESET_ATTEMPTS {
                            reset_due = Some(now + RESET_RETRY);
                            logx::firmware(format!(
                                "reset sent to {} (attempt {}, seq {}); retrying in {}s if the WTP keeps the session",
                                peer,
                                reset_attempts,
                                reset.hdr.seq_num,
                                RESET_RETRY.as_secs()
                            ));
                        } else {
                            reset_due = None;
                            logx::firmware(format!(
                                "reset sent to {} (attempt {}, seq {}); no more retries",
                                peer, reset_attempts, reset.hdr.seq_num
                            ));
                        }
                    }
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
                // An announced image may keep the WTP quiet for a while: the AX60
                // sleeps 45s on its first entry into the Image Data state before
                // it sends its Initiate Download.
                let allow = if fw_upgrade.state == firmware::UpgradeState::Announced {
                    ctx.echo_interval * 4
                } else {
                    ctx.echo_interval
                };
                if matches!(ctx.state, WtpState::Run | WtpState::ImageData)
                    && now >= ctx.last_seen + allow
                {
                    error!("[!] with {}: echo timeout (no traffic for {}s)", peer, allow.as_secs());
                    return Err(anyhow::anyhow!("echo timeout"));
                }
            }

            cmd = upgrade_rx.recv(), if !outstanding && ctx.state == WtpState::Run => {
                match cmd {
                    Some(firmware::UpgradeCmd::Start { image, name }) => {
                        info!("[>] to {}: firmware download announced via management plane", peer);
                        let name_bytes = name.as_bytes().to_vec();
                        // TP-Link identifies an image by the 14-byte binary
                        // version AC100 extracts from the image, not by its
                        // file name; other profiles keep the textual name.
                        let (vendor_id, payload) = match profile {
                            vendor::profile::VendorProfile::TpLink => (
                                vendor::tplink::VENDOR_ID,
                                vendor::tplink::image_version(&name).to_vec(),
                            ),
                            _ => (0, name_bytes.clone()),
                        };
                        let image_id = firmware::ImageIdentifier { vendor_id, name: payload };
                        fw_upgrade.announce(image, IMAGE_BLOCK_SIZE, image_id.clone());
                        // RFC 5415 9.1 (Run state): announce the image in a
                        // Configuration Update Request; the WTP replies and
                        // then asks for the data with Initiate Download.
                        let req = match profile {
                            vendor::profile::VendorProfile::H3c => {
                                config::config_update(
                                    ctx.next_seq(),
                                    &[],
                                    &[vendor::h3c::ConfigUpdateElem::ImageIdentifier {
                                        vendor_id: vendor::h3c::IMAGE_ID_PREFIX,
                                        name: name_bytes,
                                    }],
                                )
                            }
                            vendor::profile::VendorProfile::TpLink => {
                                vendor::tplink::image_update_request(ctx.next_seq(), &image_id.name)
                            }
                            vendor::profile::VendorProfile::Rfc => config::config_update(
                                ctx.next_seq(),
                                &[BaseElem::ImageIdentifier(
                                    crate::elements::ImageIdentifier::new(0, name_bytes),
                                )],
                                &[],
                            ),
                        };
                        let buf = req.encode_for(frame(profile));
                        capdtls.write(&buf).await?;
                        ctx.set_last_sent(&req, buf);
                        logx::firmware(format!("image {} announced to {} for download", name, peer));
                    }
                    None => {}
                }
            }

            cmd = cfg_update_rx.recv(), if !outstanding && ctx.state == WtpState::Run => {
                match cmd {
                    Some(config::ConfigUpdateCmd::Push { elems }) => {
                        info!("[>] to {}: configuration update triggered via management plane", peer);
                        // The LED element has a vendor-specific wire form (H3C tag
                        // 0xfdf4, TP-Link private 57 inside element 37); every
                        // other push keeps the vendor-neutral builder.
                        let req = match elems.as_slice() {
                            [crate::vendor::h3c::ConfigUpdateElem::Led(v)] => {
                                profile.led_update_request(ctx.next_seq(), *v != 0)
                            }
                            _ => config::config_update(ctx.next_seq(), &[], &elems),
                        };
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

            cmd = wtp_cmd_rx.recv(), if !outstanding && ctx.state == WtpState::Run => {
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

/// Directory with pre-generated, redistributable identities shared by all vendors.
const DEFAULT_CERT_DIR: &str = "certs/default";

/// Resolves the DTLS identity for a profile: a vendor override under
/// `certs/<vendor>/server.pem` first, then the shared default identity.
fn dtls_identity_path(prof: vendor::profile::VendorProfile) -> std::path::PathBuf {
    let vendor = prof.cert_dir().join("server.pem");
    if vendor.exists() {
        return vendor;
    }
    std::path::Path::new(DEFAULT_CERT_DIR).join("server.pem")
}

/// Builds the DTLS handshake configuration.
///
/// The server identity is resolved as vendor override (`certs/<vendor>/server.pem`),
/// then the shared `certs/default/server.pem`. Every profile
/// uses server-only authentication: neither the tested TP-Link nor H3C WTPs verify the
/// AC certificate, and none require the AC to ask for a client certificate. If no
/// identity exists at all, a self-signed Ed25519 certificate is used.
fn generate_dtls_config(
    prof: vendor::profile::VendorProfile,
) -> Result<Arc<rtc_dtls::config::HandshakeConfig>> {
    use rtc_dtls::config::ConfigBuilder;
    use rtc_dtls::crypto::Certificate;
    use rtc_dtls::crypto_provider;
    use rtc_dtls::signature_hash_algorithm::SignatureScheme;

    let provider =
        crypto_provider::default_provider().map_err(|e| anyhow!("crypto provider: {e}"))?;

    let identity_path = dtls_identity_path(prof);
    if identity_path.exists() {
        let identity = dtls_local::load_identity_file(&identity_path)?;
        let cert = Certificate::from_signing_key(identity.certificate_chain, identity.signing_key);
        let config = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![cert])
            .with_cipher_suites(vec![
                rtc_dtls::cipher_suite::CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha,
                rtc_dtls::cipher_suite::CipherSuiteId::Tls_Rsa_With_Aes_256_Cbc_Sha,
            ])
            .with_signature_schemes(vec![
                SignatureScheme::Pkcs1WithSha256,
                SignatureScheme::Pkcs1WithSha1,
            ])
            .with_insecure_hashes(true)
            .with_insecure_verification(true)
            .build(false, None)
            .map_err(|e| anyhow!("DTLS config: {e}"))?;
        info!(
            "DTLS identity for {}: {}",
            prof.vendor_name(),
            identity_path.display()
        );
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
        identity_path.display(),
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
