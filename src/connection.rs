use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::any::Any;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use async_trait::async_trait;
use dtls::conn::DTLSConn;
use webrtc_util::Conn;
#[allow(unused)]
use tracing::{info, warn, error, debug};

pub struct VirtualConn {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
    pub rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

#[async_trait]
impl Conn for VirtualConn {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, webrtc_util::Error> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(pkt) if pkt.len() >= 4 && pkt[0] == 1 => {
                    let body = &pkt[4..];
                    let n = body.len().min(buf.len());
                    buf[..n].copy_from_slice(&body[..n]);
                    return Ok(n);
                }
                Some(_) => {
                    continue;
                }
                None => return Err(webrtc_util::Error::Other("channel closed".into()))
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, webrtc_util::Error> {
        if buf.len() > 1460 {
            warn!("[!] outgoing dtls packet might be too large: {}", buf.len());
        }
        let mut pkt = Vec::with_capacity(buf.len() + 4);
        pkt.extend_from_slice(&[1, 0, 0, 0]);
        pkt.extend_from_slice(buf);
        self.socket.send_to(&pkt, self.remote_addr).await.map_err(|e| webrtc_util::Error::Other(e.to_string()))
    }

    fn local_addr(&self) -> Result<SocketAddr, webrtc_util::Error> { Ok(self.local_addr) }
    fn remote_addr(&self) -> Option<SocketAddr> { Some(self.remote_addr) }
    fn as_any(&self) -> &(dyn Any + Send + Sync) { self }


    // not used, implemented as placeholder.
    async fn close(&self) -> Result<(), webrtc_util::Error> { Ok(()) }
    async fn connect(&self, _addr: SocketAddr) -> Result<(), webrtc_util::Error> { Ok(()) }
    async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr), webrtc_util::Error> {
        Err(webrtc_util::Error::Other("Not implemented".into()))
    }
    async fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> Result<usize, webrtc_util::Error> {
        Err(webrtc_util::Error::Other("Use send instead".into()))
    }
}

pub struct CapwapConnection {
    pub peer: SocketAddr,
    pub dtls: DTLSConn,
}

impl CapwapConnection {
    pub async fn handshake(
        peer: SocketAddr,
        rx: mpsc::Receiver<Vec<u8>>,
        socket: Arc<UdpSocket>,
        config: dtls::config::Config,
    ) -> Result<Self> {
        let local_addr = socket.local_addr()?;
        let vconn = Arc::new(VirtualConn {
            local_addr,
            remote_addr: peer,
            socket,
            rx: Mutex::new(rx),
        });

        let conn_ext = vconn as Arc<dyn Conn + Send + Sync>;
        let dtls_conn = DTLSConn::new(conn_ext, config, false, None).await.context("DTLS Handshake Failed")?;

        Ok(Self { peer, dtls: dtls_conn })
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.dtls.read(buf, None).await.context("DTLS read error")
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.dtls.write(buf, None).await.context("DTLS write error")
    }
}
