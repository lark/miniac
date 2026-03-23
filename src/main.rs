mod capwap;
mod connection;

use anyhow::{anyhow, Result};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tracing::{info, warn, error, debug};

use capwap::{WtpState, WtpContext, CtrlMsg, MsgType, MsgElemType, CwElem};

const CTRL_PORT: u16 = 5246;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = format!("0.0.0.0:{}", CTRL_PORT);
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let dtls_config = Arc::new(generate_dtls_config()?);
    info!("[!] miniac started on {}", addr);

    let dispatcher_map: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();

        /*
        if let Some(dispatcher) = dispatcher_map.lock().await.get(&peer).cloned() {
            if dispatcher.send(pkt).await.is_err() {
                dispatcher_map.lock().await.remove(&peer);
            }
            continue;
        }*/

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
            if pkt.get(11) == Some(&1) { // MsgType: 1 (Discovery Request)
                info!("[<] from {}: disc req", peer);

                let mut resp = Vec::with_capacity(21);
                resp.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

                // [MsgType:4][Seq:1][Len:2][Flags:1]
                resp.extend_from_slice(&[0, 0, 0, 2]); // Type: Discovery Response
                resp.push(0);                         // Seq: 0
                resp.extend_from_slice(&[0, 5]);      // Len: 5 (4-byte TLV header + 1 value)
                resp.push(0);                         // Flags: 0

                // 3. 5-byte Discovery Type Element
                resp.extend_from_slice(&[0, 20]);     // Type: 20
                resp.extend_from_slice(&[0, 1]);      // Len: 1
                resp.push(1);                         // Value: 1 (Broadcast)

                socket.send_to(&resp, peer).await?;
            }
        }

        if pkt.get(0) == Some(&1) {
            info!("[<] from {}: direct dtls hello", peer);
            let tx = start_new_session(peer, &dispatcher_map, &socket, &dtls_config).await;
            let _ = tx.send(pkt).await;
            continue;
        }
    }
}

async fn start_new_session(
    peer: SocketAddr,
    map: &Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    socket: &Arc<UdpSocket>,
    config: &Arc<dtls::config::Config>
) -> mpsc::Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel(100);
    map.lock().await.insert(peer, tx.clone());

    let sock_clone = Arc::clone(socket);
    let conf_clone = Arc::clone(config);

    tokio::spawn(async move {
        info!("[*] with {}: session thread spawned", peer);
        if let Err(e) = handle_session(peer, rx, sock_clone, conf_clone).await {
            warn!("[!] with {}: session end: {}", peer, e);
        }
    });

    tx
}

async fn handle_session(
    peer: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    config: Arc<dtls::config::Config>
) -> Result<()> {
    let mut dtls_conn = connection::CapwapConnection::handshake(peer, rx, socket, config.as_ref().clone()).await?;
    info!("[!] with {}: dtls handshake done", peer);

    let mut ctx = WtpContext::new(peer);
    let mut app_buf = [0u8; 2048];

    loop {
        let retrans_duration = ctx.last_sent
            .as_ref()
            .filter(|last| MsgType::is_request(last.msg_type))
            .map(|last| ctx.retrans_interval.saturating_sub(last.send_time.elapsed()))
            .unwrap_or(Duration::from_secs(60));
        let idle_duration = ctx.echo_interval.saturating_sub(ctx.last_seen.elapsed());
        let sleep_duration = std::cmp::min(retrans_duration, idle_duration);

        tokio::select! {
            res = dtls_conn.read(&mut app_buf) => {
                let n = res?;
                if n < 16 { continue }
                ctx.keep_alive();

                let msg = CtrlMsg::decode(&app_buf[8..n])?;
                println!("ctrl msg\n{:?}", &app_buf[8..n]);
                let seq = msg.hdr.seq_num;
                let m_type = msg.hdr.msg_type;

                let elems = if let Some(schema) = capwap::MSG_SCHEMAS.get(&m_type) {
                    match schema.validate(m_type, &app_buf[16..n]) { // offset 8 skips the CtrlHdr
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
                            dtls_conn.write(&last.buf).await?;
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
                        // response
                        let resp_msg = CtrlMsg::new(MsgType::JOIN_RESP, seq)
                            .with_result_success()
                            .add_elem(MsgElemType::AC_DESCRIPTOR, &[0, 0, 1, 0, 0, 1, 0, 100, 4, 4, 0, 0])
                            .add_elem(MsgElemType::AC_NAME, b"miniac")
                            //.add_elem(MsgElemType::WTP_RADIO_INFO, &radio1_info)
                            //.add_elem(MsgElemType::WTP_RADIO_INFO, &radio2_info)
                            .add_elem(MsgElemType::ECN_SUPPORT, &[1])
                            .add_elem(MsgElemType::CAPWAP_CTRL_IPV4_ADDR, &[127, 0, 0, 1])
                            .add_elem(MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, &[127, 0, 0, 1]);
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);

                        ctx.state = WtpState::Configure;
                        info!("[>] to {}: join resp sent, state -> Configure", peer);
                    }

                    (WtpState::Configure, MsgType::CONFIG_STATUS_REQ) => {
                        info!("[<] from {}: config status req (seq {})", peer, seq);
                        // Capture the WTP's reported name.
                        if let Some(CwElem::WtpName(name)) = elems.get(&MsgElemType::WTP_NAME).and_then(|v| v.first()) {
                            ctx.name = name.clone();
                            info!("[*] WTP Name updated: {}", ctx.name);
                        }

                        // Capture radio operational states.
                        if let Some(radio_elems) = elems.get(&MsgElemType::RADIO_OP_STATE) {
                            for elem in radio_elems {
                                if let CwElem::RadioOp { radio_id, state } = elem {
                                    info!("[*] Radio ID: {}, Operational State: {}", radio_id, state);
                                    // ctx.radios could be updated from these states.
                                }
                            }
                        }

                        let resp_msg = CtrlMsg::new(MsgType::CONFIG_STATUS_RESP, seq)
                            .add_elem(MsgElemType::CAPWAP_TIMERS, &[20, 60])  // disc 20s, echo 60s
                            .add_elem(MsgElemType::DECRYPT_ERR_REPORT_PERIOD, &[1, 0, 120]) // radio 1, 120s
                            .add_elem(MsgElemType::DECRYPT_ERR_REPORT_PERIOD, &[2, 0, 120]) // radio 2, 120s
                            .add_elem(MsgElemType::IDLE_TIMEOUT, &[0, 0, 1, 44]) // 300s
                            .add_elem(MsgElemType::WTP_FALLBACK, &[2]); // 1-enable 2-disable
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);

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
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);

                        ctx.state = WtpState::Run;
                        info!("[>] to {}: change state event resp sent, state -> Run", peer);
                    }

                    (WtpState::Run, MsgType::ECHO_REQ) => {
                        info!("[<] from {}: echo req (seq {})", peer, seq);
                        let resp_msg = CtrlMsg::new(MsgType::ECHO_RESP, seq);
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);
                        info!("[>] to {}: echo resp", peer);
                    }

                    _ => debug!("[?] from {}: unhandled state/msg", peer),
                }
            }

            _ = tokio::time::sleep(sleep_duration) => {
                let now = Instant::now();

                if let Some(ref mut last) = ctx.last_sent {
                    if MsgType::is_request(last.msg_type) && now >= last.send_time + ctx.retrans_interval {
                        if last.retry_count < ctx.max_retries {
                            last.retry_count += 1;
                            last.send_time = now;
                            warn!("[>] to {}: retransmitting {:?} (seq {}, attempt {})",
                                peer, last.msg_type, last.seq, last.retry_count);
                            dtls_conn.write(&last.buf).await?;
                        } else {
                            error!("[!] with {}: max retries reached", peer);
                            return Err(anyhow::anyhow!("retransmit timeout"));
                        }
                    }
                }
                if ctx.state == WtpState::Run && now >= ctx.last_seen + ctx.echo_interval {
                    error!("[!] with {}: echo timeout (no traffic for {}s)", peer, ctx.echo_interval.as_secs());
                    return Err(anyhow::anyhow!("echo timeout"));
                }
            }
        }
    }
}

fn generate_dtls_config() -> Result<dtls::config::Config> {
    let cert = rcgen::generate_simple_self_signed(vec!["miniac.local".into()])?;
    let dtls_cert = dtls::crypto::Certificate {
        certificate: vec![cert.cert.der().to_vec().into()],
        private_key: dtls::crypto::CryptoPrivateKey::from_key_pair(&cert.key_pair)
            .map_err(|e| anyhow!("{}", e))?,
    };
    Ok(dtls::config::Config {
            certificates: vec![dtls_cert],
            extended_master_secret: dtls::config::ExtendedMasterSecretType::Require,
            ..Default::default()
    })
}
