mod capwap;
mod session;

use anyhow::Result;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tracing::{info, warn, error, debug};

use capwap::{WtpState, WtpContext, CtrlMsg, MsgType, MsgElemType};

const CTRL_PORT: u16 = 5246;

struct DiscState {
    timestamp: Instant
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = format!("0.0.0.0:{}", CTRL_PORT);
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    info!("[!] miniac started on {}", addr);

    let manager = Arc::new(session::DtlsManager::new().await?);
    let session_map = Arc::new(Mutex::new(HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new()));
    let pending_discs = Arc::new(Mutex::new(HashMap::<SocketAddr, DiscState>::new()));

    let pending_discs_inner = Arc::clone(&pending_discs);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            pending_discs_inner.lock().await.retain(|peer, v| {
                if v.timestamp.elapsed() >= Duration::from_secs(30) {
                    debug!("[!] from {}: disc req timeout, cleaning up", peer);
                    false
                } else {
                    true
                }
            });
        }
    });

    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();

        // 1. Idiomatic Dispatch: lock is dropped immediately after if-let condition
        if let Some(sender) = session_map.lock().await.get(&peer).cloned() {
            if sender.send(pkt).await.is_err() {
                session_map.lock().await.remove(&peer);
            }
            continue;
        }

        // 2. State Transition
        if pending_discs.lock().await.remove(&peer).is_some() {
            let (tx, rx) = mpsc::channel(100);
            session_map.lock().await.insert(peer, tx.clone());

            let (mgr, sock) = (Arc::clone(&manager), Arc::clone(&socket));
            info!("[*] with {}: verified, starting dtls", peer);

            tokio::spawn(async move {
                if let Err(e) = handle_session(mgr, sock, peer, rx).await {
                    debug!("[!] with {}: session end: {}", peer, e);
                }
            });
            let _ = tx.send(pkt).await;
            continue;
        }

        // 3. New Discovery
        if pkt.get(..4) == Some(&[0, 0, 0, 1]) {
            info!("[<] from {}: disc req", peer);
            pending_discs.lock().await.insert(peer, DiscState { timestamp: Instant::now() });
            socket.send_to(&[0, 0, 0, 2, 0, 0, 0, 0], peer).await?;
        }
    }
}

async fn handle_session(
    mgr: Arc<session::DtlsManager>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let vconn = Arc::new(session::VirtualConn {
        local_addr: sock.local_addr()?,
        remote_addr: peer,
        socket: Arc::clone(&sock),
        rx: Mutex::new(rx),
    });

    let dtls_conn = dtls::conn::DTLSConn::new(vconn, mgr.config.clone(), false, None).await?;
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
            res = dtls_conn.read(&mut app_buf, None) => {
                let n = res?;
                ctx.keep_alive();

                let msg = CtrlMsg::decode(&app_buf[..n])?;
                let seq = msg.hdr.seq_num;
                let m_type = msg.hdr.msg_type;

                if let Some(ref last) = ctx.last_sent {
                    if seq == last.seq && m_type == last.msg_type {
                        if MsgType::is_response(last.msg_type) {
                            warn!("[!] from {}: dup req (seq {}), resending response", peer, seq);
                            dtls_conn.write(&last.buf, None).await?;
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
                        let resp_msg = CtrlMsg::new(MsgType::JOIN_RESP, seq)
                            .with_result_success()
                            .add_elem(MsgElemType::AC_DESCRIPTOR, &[0u8, 0u8, 1u8, 0u8, 0u8, 1u8, 0u8, 100u8, 4u8, 4u8, 0u8, 0u8])
                            .add_elem(MsgElemType::AC_NAME, b"miniac")
                            //.add_elem(MsgElemType::WTP_RADIO_INFO, &radio1_info)
                            //.add_elem(MsgElemType::WTP_RADIO_INFO, &radio2_info)
                            .add_elem(MsgElemType::ECN_SUPPORT, &[1u8])
                            .add_elem(MsgElemType::CAPWAP_CTRL_V4_ADDR, &[127u8, 0u8, 0u8, 1u8])
                            .add_elem(MsgElemType::CAPWAP_LOCAL_V4_ADDR, &[127u8, 0u8, 0u8, 1u8]);
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf, None).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);

                        ctx.state = WtpState::Configure;
                        info!("[>] to {}: join resp sent, state -> Configure", peer);

                    }

                    (WtpState::Configure, MsgType::CONF_STATUS_REQ) => {
                        info!("[<] from {}: config status req (seq {})", peer, seq);
                        let resp_msg = CtrlMsg::new(MsgType::CONF_STATUS_RESP, seq)
                            .add_elem(MsgElemType::CAPWAP_TIMERS, &[20u8, 60u8])  // disc 20s, echo 60s
                            .add_elem(MsgElemType::DEC_ERR_REPORT_PERIOD, &[1u8, 0u8, 120u8]) // radio 1, 120s
                            .add_elem(MsgElemType::DEC_ERR_REPORT_PERIOD, &[2u8, 0u8, 120u8]) // radio 2, 120s
                            .add_elem(MsgElemType::IDLE_TIMEOUT, &[0u8, 0u8, 1u8, 44u8]) // 300s
                            .add_elem(MsgElemType::WTP_FALLBACK, &[2u8]); // 1-enable 2-disable
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf, None).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);
                        info!("[>] to {}: config resp sent", peer);
                    }

                    (WtpState::Configure, MsgType::CH_STATE_EV_REQ) => {
                        info!("[<] from {}: change status event req (seq {})", peer, seq);
                        let resp_msg = CtrlMsg::new(MsgType::CH_STATE_EV_RESP, seq);
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf, None).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);

                        ctx.state = WtpState::Run;
                        info!("[>] to {}: change status event resp sent, state -> Run", peer);
                    }

                    (WtpState::Run, MsgType::ECHO_REQ) => {
                        info!("[<] from {}: echo req (seq {})", peer, seq);
                        let resp_msg = CtrlMsg::new(MsgType::ECHO_RESP, seq);
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf, None).await?;
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
                            dtls_conn.write(&last.buf, None).await?;
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
