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
use crate::radio::H3cRadioHeader;

/// IEEE 802.11 binding: IEEE 802.11 Add WLAN message element (RFC 5416 3.x).
pub const ADD_WLAN: u16 = 1024;

/// Per-radio WLAN key-management policy. `Wpa2Wpa3` maps to the common
/// "WPA2/WPA3-PSK (mixed)" personal mode (reference M60 `ssid_enc=4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityMethod {
    #[default]
    Open,
    Wpa2Psk,
    Wpa3Sae,
    Wpa2Wpa3,
}

impl SecurityMethod {
    /// Wire byte carried in the private security element.
    fn byte(self) -> u8 {
        match self {
            SecurityMethod::Open => 0u8,
            SecurityMethod::Wpa2Psk => 1,
            SecurityMethod::Wpa3Sae => 2,
            SecurityMethod::Wpa2Wpa3 => 3,
        }
    }

    /// Policy string as stored in the `radio_wlans` table and accepted by the
    /// web API ("open" | "wpa2" | "wpa3" | "wpa2-wpa3").
    pub fn from_policy(s: &str) -> Option<SecurityMethod> {
        match s {
            "open" => Some(SecurityMethod::Open),
            "wpa2" => Some(SecurityMethod::Wpa2Psk),
            "wpa3" => Some(SecurityMethod::Wpa3Sae),
            "wpa2-wpa3" => Some(SecurityMethod::Wpa2Wpa3),
            _ => None,
        }
    }
}

impl std::fmt::Display for SecurityMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SecurityMethod::Open => "open",
            SecurityMethod::Wpa2Psk => "wpa2",
            SecurityMethod::Wpa3Sae => "wpa3",
            SecurityMethod::Wpa2Wpa3 => "wpa2-wpa3",
        };
        f.write_str(s)
    }
}

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

/// Security policy attached to a WLAN: the key-management method plus the WPA
/// passphrase (when the method is PSK).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WlanSecurity {
    pub method: SecurityMethod,
    pub psk: Option<String>,
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
    pub security: WlanSecurity,
    /// H3C 0xfde8 record fields (DB-backed, defaults mirror the stable wire):
    /// record slot up, client isolate, SSID visibility (broadcast 1 / hidden
    /// 0), client limit, VLAN id, WPA cipher (1 TKIP / 2 AES / 3 TKIP+AES) and
    /// WPA rekey period.
    pub wlan_enable: bool,
    pub isolate: bool,
    pub broadcast: bool,
    pub client_count: u32,
    pub vlan_id: u32,
    pub cipher: u32,
    pub rekey_period: u32,
}

impl Default for WlanConfig {
    fn default() -> Self {
        WlanConfig {
            radio_id: 1,
            wlan_id: 1,
            capability: 0x0001,
            qos: 0,
            auth_type: AuthType::Rsn,
            mac_mode: 0,
            tunnel_mode: 0,
            suppress_ssid: false,
            ssid: Vec::new(),
            security: WlanSecurity::default(),
            wlan_enable: true,
            isolate: false,
            broadcast: true,
            client_count: 0,
            vlan_id: 0,
            cipher: 2,
            rekey_period: 0,
        }
    }
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
        // The private security element carries the PSK; a plain Add WLAN with no
        // such element is treated as an open network.
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
            security: WlanSecurity {
                method: SecurityMethod::from_policy("open").unwrap(),
                psk: None,
            },
            ..WlanConfig::default()
        })
    }

    /// Encode the private security element body described at `WLAN_SECURITY_ELEM`.
    /// `psk` is carried verbatim (passphrases are 8..63 ASCII/UTF-8 chars).
    pub fn security_element(&self) -> Vec<u8> {
        let psk = self.security.psk.as_deref().unwrap_or("");
        let mut v = Vec::with_capacity(2 + 1 + 2 + psk.len());
        v.push(self.radio_id);
        v.push(self.wlan_id);
        v.push(self.security.method.byte());
        v.extend_from_slice(&(psk.len() as u16).to_be_bytes());
        v.extend_from_slice(psk.as_bytes());
        v
    }

    /// Parse a private security element body back into a `WlanSecurity`.
    pub fn decode_security(body: &[u8]) -> anyhow::Result<WlanSecurity> {
        if body.len() < 5 {
            anyhow::bail!("security element too short");
        }
        let method = match body[2] {
            0 => SecurityMethod::Open,
            1 => SecurityMethod::Wpa2Psk,
            2 => SecurityMethod::Wpa3Sae,
            3 => SecurityMethod::Wpa2Wpa3,
            other => anyhow::bail!("unsupported security method byte {other}"),
        };
        let psk_len = u16::from_be_bytes([body[3], body[4]]) as usize;
        if body.len() < 5 + psk_len {
            anyhow::bail!("security element PSK truncated");
        }
        let psk = if psk_len == 0 {
            None
        } else {
            Some(String::from_utf8(body[5..5 + psk_len].to_vec())?)
        };
        Ok(WlanSecurity { method, psk })
    }
}

/// Build a Configuration Update Request carrying arbitrary base elements plus
/// the given WLAN(s) and a per-radio administrative-state element. WLAN push
/// is the forward direction (AC -> WTP).
///
/// The AX60 applies 0xfde8 records only when its WLAN-interface commit hook
/// fires (create_wlan_intf / CFG_SetWifiSsidEnable); sending a Radio
/// Administrative State element per radio drives that interface-state
/// transition so the stored SSID/security actually take effect.
pub fn config_update(
    seq: u32,
    base: &[BaseElem],
    wlans: &[WlanConfig],
    g24_hdr: &H3cRadioHeader,
    g5_hdr: &H3cRadioHeader,
) -> CtrlMsg {
    let mut msg = CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq);
    for b in base {
        msg = msg.add_element(b.clone());
    }
    let mut radios_seen = HashSet::new();
    if !wlans.is_empty() {
        // One element carries every radio's WLANs (2.4G + 5G sections), matching
        // the AX60 decoder 0x52ee0's dual-band layout.
        let body = crate::vendor::h3c::encode_h3c(wlans, g24_hdr, g5_hdr);
        msg = msg.add_elem(crate::vendor::h3c::WLAN_CFG_H3C, &body);
    }
    for w in wlans {
        // Drive the AX60 WLAN-interface state-transition commit (create_wlan_intf
        // / CFG_SetWifiSsidEnable) by toggling the radio administrative state:
        // first disabled (1) then enabled (0). A single [radio_id, 0] did NOT
        // trigger apply in the real device, so supply an explicit down/up.
        if radios_seen.insert(w.radio_id) {
            msg = msg.add_elem(MsgElemType::RADIO_ADMIN_STATE, &[w.radio_id, 1]);
            msg = msg.add_elem(MsgElemType::RADIO_ADMIN_STATE, &[w.radio_id, 0]);
        }
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

    fn hdr24() -> H3cRadioHeader {
        H3cRadioHeader::default()
    }

    fn hdr5() -> H3cRadioHeader {
        H3cRadioHeader {
            radio_id: 2,
            channel: 4,
            ..H3cRadioHeader::default()
        }
    }

    #[test]
    fn wlan_roundtrip() {
        // The security policy rides in a separate element, so the Add WLAN
        // codec round-trips an open network only; PSK is covered separately.
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
            security: WlanSecurity {
                method: SecurityMethod::Open,
                psk: None,
            },
            ..WlanConfig::default()
        };
        let enc = w.encode();
        assert_eq!(WlanConfig::decode(&enc).unwrap(), w);
    }

    #[test]
    fn security_element_roundtrip() {
        let w = WlanConfig {
            radio_id: 2,
            wlan_id: 1,
            capability: 0x0001,
            qos: 0,
            auth_type: AuthType::Rsn,
            mac_mode: 0,
            tunnel_mode: 0,
            suppress_ssid: false,
            ssid: b"minimac".to_vec(),
            security: WlanSecurity {
                method: SecurityMethod::Wpa3Sae,
                psk: Some("person0finterest".into()),
            },
            ..WlanConfig::default()
        };
        let body = w.security_element();
        // [radio][wlan][method][len:2][psk]
        assert_eq!(body[0], 2);
        assert_eq!(body[1], 1);
        assert_eq!(body[2], 2); // Wpa3Sae
        assert_eq!(
            u16::from_be_bytes([body[3], body[4]]) as usize,
            "person0finterest".len()
        );
        assert_eq!(
            WlanConfig::decode_security(&body).unwrap(),
            w.security
        );
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
                security: WlanSecurity {
                    method: SecurityMethod::Open,
                    psk: None,
                },
                ..WlanConfig::default()
            }],
            &hdr24(),
            &hdr5(),
        );
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        assert!(msg.elems.iter().any(|e| e.tag == crate::vendor::h3c::WLAN_CFG_H3C));
        assert!(msg
            .elems
            .iter()
            .any(|e| e.tag == MsgElemType::CAPWAP_TIMERS));
    }

    #[test]
    fn config_update_embeds_security_into_h3c_body() {
        let msg = config_update(
            7,
            &[],
            &[WlanConfig {
                radio_id: 1,
                wlan_id: 1,
                capability: 0x0001,
                qos: 0,
                auth_type: AuthType::Rsn,
                mac_mode: 0,
                tunnel_mode: 0,
                suppress_ssid: false,
                ssid: b"minimac".to_vec(),
                security: WlanSecurity {
                    method: SecurityMethod::Wpa2Wpa3,
                    psk: Some("person0finterest".into()),
                },
                ..WlanConfig::default()
            }],
            &hdr24(),
            &hdr5(),
        );
        let cfg_elems: Vec<_> = msg
            .elems
            .iter()
            .filter(|e| e.tag == crate::vendor::h3c::WLAN_CFG_H3C)
            .collect();
        assert_eq!(cfg_elems.len(), 1);
        // The PSK rides inside the 0xfde8 body (after the encrypt u32), not a
        // separate element. Radio 1 -> "SSID-" anchor at offset 28.
        let b = &cfg_elems[0].data;
        assert_eq!(&b[28..33], b"SSID-");
        let enc_at = 28 + 33 + 4 + 33 + 16;
        assert_eq!(&b[enc_at + 4..enc_at + 4 + 16], b"person0finterest");
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
