//! Sans-I/O DTLS transport bridge: rtc-dtls Endpoint pumped over CAPWAP UDP framing.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! CAPWAP carries DTLS on the control port. RFC 5415 §4.1/§4.2 prefix every
//! DTLS-carried datagram with the 4-byte CAPWAP DTLS Header: the CAPWAP Preamble
//! (Version 0, Type 1 = "CAPWAP DTLS Header") followed by 24 reserved zero bits,
//! i.e. [1,0,0,0]. Inbound datagrams are stripped of it before being fed to the
//! Endpoint, and outbound DTLS records are prefixed with it. This framing is
//! standard and uniform across vendors and profiles.

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

/// First byte of the CAPWAP DTLS Header (RFC 5415 §4.1 CAPWAP Preamble): Version
/// 0 in the high nibble, Type 1 in the low nibble ("CAPWAP DTLS Header follows
/// the UDP header"). The trailing 3 bytes are the zeroed 24-bit Reserved field.
const CAPWAP_DTLS_PREAMBLE: u8 = 1;

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
            pkt.extend_from_slice(&[CAPWAP_DTLS_PREAMBLE, 0, 0, 0]);
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
        let body = if pkt.len() >= 4 && pkt[0] == CAPWAP_DTLS_PREAMBLE {
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
                EndpointEvent::ApplicationData(data) => {
                    crate::dump::write("RX", &data);
                    app_data.push(data)
                }
                _ => {}
            }
        }
        self.flush().await?;
        Ok(app_data)
    }

    /// Sends one application-data message over the DTLS association.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        crate::dump::write("TX", data);
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
