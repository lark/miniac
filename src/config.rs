//! WTP configuration push-down: Add WLAN element codec, Configuration Update
//! builder and AC-side acknowledgement tracking.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Encodes the RFC 5416 IEEE 802.11 Add WLAN element and the RFC 5415 8.4
//! Configuration Update message, and tracks Configuration Acknowledgment from
//! WTPs to detect out-of-sync devices.

#![allow(dead_code, unused_imports)] // config models; wired into the Configure/Run session paths

use std::collections::HashSet;

use crate::capwap::{CtrlMsg, MsgElemType, MsgType};
use crate::elements::BaseElem;

/// IEEE 802.11 binding: IEEE 802.11 Add WLAN message element (RFC 5416 3.x).
pub const ADD_WLAN: u16 = 1024;

/// 802.11 WLAN authentication/security type carried in the Add WLAN element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum AuthType {
    /// RSN (WPA2/WPA3 802.1X or PSK), the modern default.
    Rsn = 0,
    /// Reserved / pre-RSN open-authentication behaviour.
    Open = 1,
}

impl AuthType {
    fn byte(self) -> u8 {
        match self {
            AuthType::Rsn => 0,
            AuthType::Open => 1,
        }
    }
}

/// A WLAN the AC pushes to a WTP through Configuration Update. The fixed
/// header mirrors RFC 5416 (Add WLAN); WEP keying fields are omitted (the
/// security policy rides in the referenced profile instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WlanConfig {
    pub radio_id: u8,
    pub wlan_id: u8,
    pub capability: u16, // 802.11 Capability Information bits, ESS must be set
    pub qos: u8,
    pub auth_type: AuthType,
    pub mac_mode: u8,
    pub tunnel_mode: u8,
    pub suppress_ssid: bool,
    pub ssid: Vec<u8>,
}

impl WlanConfig {
    /// Encode the element body. Layout follows RFC 5416 3.x (Add WLAN).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(18 + self.ssid.len());
        v.push(self.radio_id);
        v.push(self.wlan_id);
        v.extend_from_slice(&self.capability.to_be_bytes());
        // Key Index / Key Status / Key Length / Group TSC / QoS / Auth omitted:
        // use a fixed 0 group TSC and no WEP key (len 0).
        v.extend_from_slice(&[0, 0]); // key index / status
        v.extend_from_slice(&0u16.to_be_bytes()); // key length
        v.extend_from_slice(&[0u8; 6]); // group TSC
        v.push(0); // QoS
        v.push(self.auth_type.byte());
        v.push(self.mac_mode);
        v.push(self.tunnel_mode);
        v.push(u8::from(self.suppress_ssid));
        v.extend_from_slice(&self.ssid);
        v
    }

    /// Parse an Add WLAN element body.
    pub fn decode(body: &[u8]) -> anyhow::Result<Self> {
        if body.len() < 18 {
            anyhow::bail!("Add WLAN element too short");
        }
        let radio_id = body[0];
        let wlan_id = body[1];
        let capability = u16::from_be_bytes([body[2], body[3]]);
        let key_len = u16::from_be_bytes([body[6], body[7]]) as usize;
        // Fixed header ends after WEP key + group TSC (8 + key_len + 6 leftover
        // references are mapped by the byte offsets in RFC 5416).
        let tsc_at = 8 + key_len;
        // Group TSC (6) + QoS + Auth + MAC Mode + Tunnel Mode + Suppress SSID.
        let auth_at = tsc_at + 6 + 1;
        let mac_mode_at = auth_at + 1;
        let tunnel_mode_at = mac_mode_at + 1;
        let suppress_at = tunnel_mode_at + 1;
        if body.len() < suppress_at + 1 {
            anyhow::bail!("Add WLAN header truncated");
        }
        let auth_type = if body[auth_at] == 0 {
            AuthType::Rsn
        } else {
            AuthType::Open
        };
        let ssid = body[suppress_at + 1..].to_vec();
        Ok(WlanConfig {
            radio_id,
            wlan_id,
            capability,
            qos: body[tsc_at + 6],
            auth_type,
            mac_mode: body[mac_mode_at],
            tunnel_mode: body[tunnel_mode_at],
            suppress_ssid: body[suppress_at] != 0,
            ssid,
        })
    }
}

/// Build a Configuration Update Request carrying arbitrary base elements plus
/// the given WLAN(s). WLAN push-down is the forward direction (AC -> WTP).
pub fn config_update(seq: u32, base: &[BaseElem], wlans: &[WlanConfig]) -> CtrlMsg {
    let mut msg = CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq);
    for b in base {
        msg = msg.add_element(b.clone());
    }
    for w in wlans {
        let body = w.encode();
        msg = msg.add_elem(ADD_WLAN, &body);
    }
    msg
}

/// Tracks which configuration tags the AC has pushed and whether the WTP has
/// acknowledged them, so a Join/Config-status exchange can decide to re-send.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigStatus {
    pending: HashSet<u16>,
}

impl ConfigStatus {
    pub fn new() -> Self {
        ConfigStatus {
            pending: HashSet::new(),
        }
    }

    /// Mark the given element tags as pushed and unacknowledged.
    pub fn mark_pushed<I: IntoIterator<Item = u16>>(&mut self, tags: I) {
        self.pending.extend(tags);
    }

    /// The WTP acknowledged these tags (Configuration Status Update /
    /// Configuration Update Response included them).
    pub fn mark_acked<I: IntoIterator<Item = u16>>(&mut self, tags: I) {
        for t in tags {
            self.pending.remove(&t);
        }
    }

    /// True when no configuration is outstanding against the WTP.
    pub fn is_synced(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn pending(&self) -> impl Iterator<Item = u16> + '_ {
        self.pending.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wlan_roundtrip() {
        let w = WlanConfig {
            radio_id: 1,
            wlan_id: 3,
            capability: 0x0101,
            qos: 0,
            auth_type: AuthType::Rsn,
            mac_mode: 0,
            tunnel_mode: 0,
            suppress_ssid: false,
            ssid: b"miniac".to_vec(),
        };
        let enc = w.encode();
        assert_eq!(WlanConfig::decode(&enc).unwrap(), w);
    }

    #[test]
    fn config_update_message() {
        let msg = config_update(
            5,
            &[BaseElem::CapwapTimers {
                disc_interval_secs: 20,
                echo_interval_secs: 60,
            }],
            &[WlanConfig {
                radio_id: 1,
                wlan_id: 1,
                capability: 0x0001,
                qos: 0,
                auth_type: AuthType::Rsn,
                mac_mode: 0,
                tunnel_mode: 0,
                suppress_ssid: false,
                ssid: b"corp".to_vec(),
            }],
        );
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        assert!(msg.elems.iter().any(|e| e.tag == ADD_WLAN));
        assert!(msg
            .elems
            .iter()
            .any(|e| e.tag == MsgElemType::CAPWAP_TIMERS));
    }

    #[test]
    fn config_status_tracking() {
        let mut s = ConfigStatus::new();
        assert!(s.is_synced());
        s.mark_pushed([MsgElemType::WTP_NAME, MsgElemType::RADIO_ADMIN_STATE]);
        assert!(!s.is_synced());
        s.mark_acked([MsgElemType::WTP_NAME]);
        assert!(!s.is_synced());
        s.mark_acked([MsgElemType::RADIO_ADMIN_STATE]);
        assert!(s.is_synced());
    }
}
