//! Sans-I/O DTLS transport bridge: rtc-dtls Endpoint pumped over CAPWAP UDP framing.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! CAPWAP carries DTLS on the control port inside a 4-byte framing header whose
//! first byte is 1. Inbound frames are stripped of that header before being fed
//! to the Endpoint; outbound DTLS records are prefixed with [1,0,0,0].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::BytesMut;
use rtc_dtls::config::HandshakeConfig;
use rtc_dtls::endpoint::{Endpoint, EndpointEvent};
use rtc_shared::TransportProtocol;
use tokio::net::UdpSocket;
use tracing::warn;

/// Framing header byte identifying a DTLS packet inside the CAPWAP control stream.
const DTLS_FRAME_MARKER: u8 = 1;

pub struct CapwapDtls {
    endpoint: Endpoint,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    handshake_complete: bool,
}

impl CapwapDtls {
    /// Creates the server-side association for `peer` over `socket`.
    pub fn new(
        local_addr: SocketAddr,
        peer: SocketAddr,
        socket: Arc<UdpSocket>,
        config: Arc<HandshakeConfig>,
    ) -> Self {
        let endpoint = Endpoint::new(local_addr, TransportProtocol::UDP, Some(config));
        Self {
            endpoint,
            socket,
            peer,
            handshake_complete: false,
        }
    }

    /// Drains the Endpoint transmit queue to `peer`, framed as CAPWAP DTLS packets.
    async fn flush(&mut self) -> Result<()> {
        while let Some(transmit) = self.endpoint.poll_transmit() {
            let msg = transmit.message;
            if msg.len() > 1460 {
                warn!("outgoing DTLS record too large: {} bytes", msg.len());
            }
            let mut pkt = Vec::with_capacity(msg.len() + 4);
            pkt.extend_from_slice(&[DTLS_FRAME_MARKER, 0, 0, 0]);
            pkt.extend_from_slice(&msg);
            self.socket
                .send_to(&pkt, self.peer)
                .await
                .context("DTLS send")?;
        }
        Ok(())
    }

    /// Feeds one inbound CAPWAP frame into the DTLS state machine and returns
    /// any decrypted application data it produced.
    pub async fn feed(&mut self, pkt: &[u8]) -> Result<Vec<BytesMut>> {
        let body = if pkt.len() >= 4 && pkt[0] == DTLS_FRAME_MARKER {
            &pkt[4..]
        } else {
            pkt
        };
        let events = self.endpoint.read(
            Instant::now(),
            self.peer,
            None,
            BytesMut::from(body),
        ).map_err(|e| {
            warn!("DTLS read error from {}: {:#?}", self.peer, e);
            e
        }).context("DTLS read")?;
        let mut app_data = Vec::new();
        for event in events {
            match event {
                EndpointEvent::HandshakeComplete => self.handshake_complete = true,
                EndpointEvent::ApplicationData(data) => app_data.push(data),
                _ => {}
            }
        }
        self.flush().await?;
        Ok(app_data)
    }

    /// Sends one application-data message over the DTLS association.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.endpoint
            .write(Instant::now(), self.peer, data)
            .context("DTLS write")?;
        self.flush().await
    }

    /// Advances the association's retransmit timer, resending lost handshake flights.
    pub async fn on_timeout(&mut self, now: Instant) -> Result<()> {
        self.endpoint
            .handle_timeout(self.peer, now)
            .context("DTLS timeout")?;
        self.flush().await
    }

    /// When the DTLS retransmit timer next fires, if one is pending.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.endpoint.poll_timeout(&self.peer)
    }

    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }
}
