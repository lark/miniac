use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use webrtc_util::Conn;

pub struct DtlsManager {
    pub config: dtls::config::Config,
}

impl DtlsManager {
    pub async fn new() -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["miniac.local".into()])?;
        let dtls_cert = dtls::crypto::Certificate {
            certificate: vec![cert.cert.der().to_vec().into()],
            private_key: dtls::crypto::CryptoPrivateKey::from_key_pair(&cert.key_pair)
                .map_err(|e| anyhow!("{}", e))?,
        };
        Ok(Self {
            config: dtls::config::Config {
                certificates: vec![dtls_cert],
                extended_master_secret: dtls::config::ExtendedMasterSecretType::Require,
                ..Default::default()
            },
        })
    }
}

pub struct VirtualConn {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
    pub rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

#[async_trait]
impl Conn for VirtualConn {
    async fn connect(&self, _: SocketAddr) -> Result<(), webrtc_util::Error> { Ok(()) }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, webrtc_util::Error> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(pkt) if pkt.len() >= 4 && pkt[0..2] == [0, 1] => {
                let body = &pkt[4..];
                let n = body.len().min(buf.len());
                buf[..n].copy_from_slice(&body[..n]);
                Ok(n)
            }
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(webrtc_util::Error::Other("closed".into())),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), webrtc_util::Error> {
        Ok((self.recv(buf).await?, self.remote_addr))
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, webrtc_util::Error> {
        let mut pkt = Vec::with_capacity(buf.len() + 4);
        pkt.extend_from_slice(&[0, 1, 0, 0]);
        pkt.extend_from_slice(buf);
        self.socket.send_to(&pkt, self.remote_addr).await.map_err(|e| e.into())
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, webrtc_util::Error> {
        self.socket.send_to(buf, target).await.map_err(|e| e.into())
    }

    fn local_addr(&self) -> Result<SocketAddr, webrtc_util::Error> { Ok(self.local_addr) }
    fn remote_addr(&self) -> Option<SocketAddr> { Some(self.remote_addr) }
    async fn close(&self) -> Result<(), webrtc_util::Error> { Ok(()) }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) { self }
}
