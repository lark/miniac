mod capwap;
mod session;

use anyhow::Result;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tracing::{info, warn, error, debug};

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

    let mut ctx = capwap::WtpContext::new(peer);
    let mut app_buf = [0u8; 2048];

    loop {
        let now = Instant::now();

        let retrans_duration = if let Some(ref last) = ctx.last_sent {
            if last.msg_type.is_request() {
                let elapsed = last.send_time.elapsed();
                if elapsed >= ctx.retrans_interval {
                    Duration::from_millis(0)
                } else {
                    ctx.retrans_interval - elapsed
                }
            } else {
                Duration::from_secs(60)
            }
        } else {
            Duration::from_secs(60)
        };

        let idle_deadline = ctx.last_recv_time + ctx.echo_interval;
        let idle_duration = if idle_deadline > now {
            idle_deadline - now
        } else {
            Duration::from_millis(0)
        };

        let sleep_duration = std::cmp::min(retrans_duration, idle_duration);

        tokio::select! {
            res = dtls_conn.read(&mut app_buf, None) => {
                let n = res?;
                ctx.last_recv_time = Instant::now();

                let msg = capwap::CtrlMsg::decode(&app_buf[..n])?;
                let seq = msg.hdr.seq_num;
                let m_type = msg.hdr.msg_type();

                if let Some(ref last) = ctx.last_sent {
                    if seq == last.seq && m_type == last.msg_type {
                        if last.msg_type.is_response() {
                            warn!("[!] from {}: dup req (seq {}), resending response", peer, seq);
                            dtls_conn.write(&last.buf, None).await?;
                            continue;
                        }
                    }
                }

                if m_type.is_response() {
                    if let Some(last) = ctx.last_sent.as_ref().filter(|l| l.seq == seq && l.msg_type.is_request()) {
                        info!("[<] from {}: received response for {:?} (seq {})", peer, last.msg_type, seq);
                        ctx.last_sent = None;
                    }
                }

                match (ctx.state, m_type) {
                    (capwap::WtpState::Join, capwap::MsgType::JoinReq) => {
                        info!("[<] from {}: join req (seq {})", peer, seq);
                        let resp_msg = capwap::CtrlMsg::new(capwap::MsgType::JoinResp, seq).with_result_success();
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf, None).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);
                        info!("[>] to {}: join resp sent", peer);

                        ctx.state = capwap::WtpState::Configure;
                        let config_req = capwap::CtrlMsg::new(capwap::MsgType::ConfigReq, ctx.next_seq())
                            .add_elem(1025, &[1, 1]);
                        let config_buf = config_req.encode();
                        dtls_conn.write(&config_buf, None).await?;
                        ctx.set_last_sent(&config_req, config_buf);
                        info!("[>] to {}: config req sent, state -> Configure", peer);
                    }

                    (capwap::WtpState::Configure, capwap::MsgType::ConfigResp) => {
                        info!("[<] from {}: config resp (seq {})", peer, seq);
                        ctx.state = capwap::WtpState::Run;
                        info!("[!] with {}: state -> RUN", peer);
                    }

                    (capwap::WtpState::Run, capwap::MsgType::EchoReq) => {
                        let resp_msg = capwap::CtrlMsg::new(capwap::MsgType::EchoResp, seq);
                        let resp_buf = resp_msg.encode();
                        dtls_conn.write(&resp_buf, None).await?;
                        ctx.set_last_sent(&resp_msg, resp_buf);
                    }

                    _ => debug!("[?] from {}: unhandled state/msg", peer),
                }
            }

            _ = tokio::time::sleep(sleep_duration) => {
                let now = Instant::now();

                if let Some(ref mut last) = ctx.last_sent {
                    if last.msg_type.is_request() && now >= last.send_time + ctx.retrans_interval {
                        if last.retry_count < ctx.max_retries {
                            last.retry_count += 1;
                            last.send_time = Instant::now();
                            warn!("[>] to {}: retransmitting {:?} (seq {}, attempt {})",
                                peer, last.msg_type, last.seq, last.retry_count);
                            dtls_conn.write(&last.buf, None).await?;
                        } else {
                            error!("[!] with {}: max retries reached", peer);
                            return Err(anyhow::anyhow!("retransmit timeout"));
                        }
                    }
                }
                else if now >= ctx.last_recv_time + ctx.echo_interval {
                    if ctx.state == capwap::WtpState::Run {
                        let seq = ctx.next_seq();
                        let echo_req = capwap::CtrlMsg::new(capwap::MsgType::EchoReq, seq);
                        let buf = echo_req.encode();
                        dtls_conn.write(&buf, None).await?;
                        ctx.set_last_sent(&echo_req, buf);
                        info!("[>] to {}: idle timeout, sending echo request (seq {})", peer, seq);
                    }
                }
            }
        }
    }
}
