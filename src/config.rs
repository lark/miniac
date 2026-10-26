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
use std::net::Ipv4Addr;

use tokio::sync::mpsc::Sender;

use crate::capwap::{CtrlMsg, CwResult, MsgElemType, MsgType};
use crate::device::Mac;
use crate::elements::{BaseElem, ImageIdentifier};

/// IEEE 802.11 binding: IEEE 802.11 Add WLAN message element (RFC 5416 3.x).
pub const ADD_WLAN: u16 = 1024;

/// Key-management (AKM) dimension of a WLAN security policy. Orthogonal to
/// [`Cipher`]: `PskSae` is a *transition* mode that stays backwards-compatible
/// with WPA2 clients, not a strictly stronger successor to `Psk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Akm {
    /// No key management (an open network).
    #[default]
    Open,
    /// WPA-PSK / WPA2-PSK; the generation follows the cipher.
    Psk,
    /// WPA2-PSK / WPA3-SAE transition (both offered to clients).
    PskSae,
    /// WPA3-SAE (personal) only.
    Sae,
}

impl Akm {
    /// Policy token stored in the database and accepted by the web API.
    pub fn as_str(self) -> &'static str {
        match self {
            Akm::Open => "open",
            Akm::Psk => "psk",
            Akm::PskSae => "psk-sae",
            Akm::Sae => "sae",
        }
    }

    pub fn from_str(s: &str) -> Option<Akm> {
        match s {
            "open" => Some(Akm::Open),
            "psk" => Some(Akm::Psk),
            "psk-sae" => Some(Akm::PskSae),
            "sae" => Some(Akm::Sae),
            _ => None,
        }
    }

    /// Security rank; a higher rank is strictly stronger. Transition modes sit
    /// between their endpoints (`Open < Psk < PskSae < Sae`).
    pub fn rank(self) -> u8 {
        match self {
            Akm::Open => 0,
            Akm::Psk => 1,
            Akm::PskSae => 2,
            Akm::Sae => 3,
        }
    }

    /// Single-bit capability mask (see [`crate::fleet::ProductCaps`]).
    pub fn bit(self) -> u8 {
        1 << self.rank()
    }

    /// Whether the AKM requires a WPA passphrase.
    pub fn secured(self) -> bool {
        !matches!(self, Akm::Open)
    }
}

/// Cipher-suite dimension of a WLAN security policy. `TkipCcmp` is the
/// WPA/WPA2 mixed mode, where both ciphers are offered to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cipher {
    /// TKIP (WPA-era). Usable but discouraged by the policy layer.
    Tkip,
    /// AES/CCMP, the secure default.
    #[default]
    Ccmp,
    /// TKIP + AES/CCMP (WPA/WPA2 mixed).
    TkipCcmp,
}

impl Cipher {
    pub fn as_str(self) -> &'static str {
        match self {
            Cipher::Tkip => "tkip",
            Cipher::Ccmp => "ccmp",
            Cipher::TkipCcmp => "tkip+ccmp",
        }
    }

    pub fn from_str(s: &str) -> Option<Cipher> {
        match s {
            "tkip" => Some(Cipher::Tkip),
            "ccmp" | "aes" => Some(Cipher::Ccmp),
            "tkip+ccmp" | "ccmp+tkip" => Some(Cipher::TkipCcmp),
            _ => None,
        }
    }

    /// Vendor wire integer shared by the H3C `wpa_key_type` (0xfde8 record) and
    /// private-9 fields: 1 TKIP / 2 AES / 3 TKIP+AES.
    pub fn wire(self) -> u32 {
        match self {
            Cipher::Tkip => 1,
            Cipher::Ccmp => 2,
            Cipher::TkipCcmp => 3,
        }
    }

    pub fn from_wire(v: u32) -> Option<Cipher> {
        match v {
            1 => Some(Cipher::Tkip),
            2 => Some(Cipher::Ccmp),
            3 => Some(Cipher::TkipCcmp),
            _ => None,
        }
    }

    /// Single-bit capability mask.
    pub fn bit(self) -> u8 {
        match self {
            Cipher::Tkip => 0b01,
            Cipher::Ccmp => 0b10,
            Cipher::TkipCcmp => 0b100,
        }
    }
}

/// Management-frame-protection (802.11w / PMF) policy. Kept explicit rather
/// than derived from the AKM: PMF is a prerequisite for 802.11k/r/v and the
/// k/r/v design revisits this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pmf {
    #[default]
    Disabled,
    Capable,
    Required,
}

impl Pmf {
    pub fn as_str(self) -> &'static str {
        match self {
            Pmf::Disabled => "disabled",
            Pmf::Capable => "capable",
            Pmf::Required => "required",
        }
    }

    pub fn from_str(s: &str) -> Option<Pmf> {
        match s {
            "disabled" => Some(Pmf::Disabled),
            "capable" => Some(Pmf::Capable),
            "required" => Some(Pmf::Required),
            _ => None,
        }
    }

    /// Single-bit capability mask.
    pub fn bit(self) -> u8 {
        match self {
            Pmf::Disabled => 0b001,
            Pmf::Capable => 0b010,
            Pmf::Required => 0b100,
        }
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

/// Security policy attached to a WLAN. The key-management ([`Akm`]) and
/// cipher ([`Cipher`]) dimensions stay separate: they are orthogonal, and a
/// transition mode such as `PskSae` is a compatibility choice rather than a
/// stronger cipher.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityPolicy {
    pub akm: Akm,
    pub cipher: Cipher,
    /// WPA passphrase (8..63 chars) when the AKM is secured.
    pub psk: Option<String>,
    pub pmf: Pmf,
}

impl SecurityPolicy {
    /// Whether the policy requires a passphrase.
    pub fn secured(&self) -> bool {
        self.akm.secured()
    }

    /// The Add WLAN authentication-type byte for this policy: RSN once a key
    /// manager is present, legacy open-authentication otherwise.
    pub fn auth_type(&self) -> AuthType {
        if self.secured() {
            AuthType::Rsn
        } else {
            AuthType::Open
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
    pub security: SecurityPolicy,
    /// H3C 0xfde8 record fields (DB-backed, defaults mirror the stable wire):
    /// record slot up, client isolate, SSID visibility (broadcast 1 / hidden
    /// 0), client limit, VLAN id and WPA rekey period. The cipher rides in
    /// [`SecurityPolicy::cipher`]; the vendor layer maps it to its wire field.
    pub wlan_enable: bool,
    pub isolate: bool,
    pub broadcast: bool,
    pub client_count: u32,
    pub vlan_id: u32,
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
            security: SecurityPolicy::default(),
            wlan_enable: true,
            isolate: false,
            broadcast: true,
            client_count: 0,
            vlan_id: 0,
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
            security: SecurityPolicy::default(),
            ..WlanConfig::default()
        })
    }

    /// Encode the private security element body. `psk` is carried verbatim
    /// (passphrases are 8..63 ASCII/UTF-8 chars). Layout:
    /// `[radio][wlan][akm rank][cipher wire][len:2][psk]`.
    pub fn security_element(&self) -> Vec<u8> {
        let psk = self.security.psk.as_deref().unwrap_or("");
        let mut v = Vec::with_capacity(4 + 2 + psk.len());
        v.push(self.radio_id);
        v.push(self.wlan_id);
        v.push(self.security.akm.rank());
        v.push(self.security.cipher.wire() as u8);
        v.extend_from_slice(&(psk.len() as u16).to_be_bytes());
        v.extend_from_slice(psk.as_bytes());
        v
    }

    /// Parse a private security element body back into a [`SecurityPolicy`].
    pub fn decode_security(body: &[u8]) -> anyhow::Result<SecurityPolicy> {
        if body.len() < 6 {
            anyhow::bail!("security element too short");
        }
        let akm = match body[2] {
            0 => Akm::Open,
            1 => Akm::Psk,
            2 => Akm::PskSae,
            3 => Akm::Sae,
            other => anyhow::bail!("unsupported akm rank {other}"),
        };
        let cipher = Cipher::from_wire(body[3] as u32)
            .ok_or_else(|| anyhow::anyhow!("unsupported cipher wire {}", body[3]))?;
        let psk_len = u16::from_be_bytes([body[4], body[5]]) as usize;
        if body.len() < 6 + psk_len {
            anyhow::bail!("security element PSK truncated");
        }
        let psk = if psk_len == 0 {
            None
        } else {
            Some(String::from_utf8(body[6..6 + psk_len].to_vec())?)
        };
        Ok(SecurityPolicy {
            akm,
            cipher,
            psk,
            pmf: Pmf::Disabled,
        })
    }
}

/// Build a Configuration Update Request (mtype 7) carrying arbitrary base
/// elements plus H3C config-update elements.
///
/// The AX60 request parser (`CWParseConfigurationUpdateRequest`, WTP.dis
/// 0x317e4) recognizes only the H3C-private tags in
/// [`crate::vendor::h3c::ConfigUpdateElem`]. A runtime WLAN push uses the opaque
/// 0xfdf1 batch blob, **not** the 0xfde8 element of the Configuration Status
/// Response — the request parser skips 0xfde8 as an unrecognized element.
pub fn config_update(
    seq: u32,
    base: &[BaseElem],
    elems: &[crate::vendor::h3c::ConfigUpdateElem],
) -> CtrlMsg {
    let mut msg = CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq);
    for b in base {
        msg = msg.add_element(b.clone());
    }
    for e in elems {
        let (tag, body) = e.encode();
        msg = msg.add_elem(tag, &body);
    }
    msg
}

/// Generic (RFC 5415 8.5) Reset Request (mtype 17): names the image the WTP
/// should reboot into. Vendor overlays (H3C, TP-Link) add their own image name
/// and private reset mask on top of this.
pub fn reset_request(seq: u32, image: &ImageIdentifier) -> CtrlMsg {
    CtrlMsg::new(MsgType::RESET_REQ, seq).add_element(BaseElem::ImageIdentifier(image.clone()))
}

/// Generic (RFC 5415 8.7) Clear Configuration Request (mtype 23): asks the WTP
/// to clear its configuration and return to defaults. The element set is empty.
///
/// TP-Link AC100 does not implement mtype 23 — it expresses restore-defaults
/// through the reset mask — so this is the vendor-neutral (and H3C) path only.
pub fn clear_config_request(seq: u32) -> CtrlMsg {
    CtrlMsg::new(MsgType::CLEAR_CONFIG_REQ, seq)
}

/// RFC 5415 4.6.1 AC Descriptor value: a 12-byte base field set followed by the
/// two mandatory AC Information sub-elements (Type 4 Hardware Version, Type 5
/// Software Version), both carrying `vendor_id`.
///
/// The base bytes are the values the H3C AX60 WTP accepts (Security R bit set,
/// DTLS clear-text-data policy); they are valid RFC 5415 values and are shared
/// by every vendor form.
pub fn ac_descriptor(hw: &str, sw: &str, vendor_id: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + 20);
    v.extend_from_slice(&[
        0x00, 0x00, 0x04, 0x00, // Stations 0 / Limit 1024
        0x00, 0x00, 0x00, 0x20, // Active WTPs 0 / Max WTPs 32
        0x01, 0x01, 0x00, 0x02, // Security / R-MAC Field / Reserved / DTLS Policy
    ]);
    for (ty, ver) in [(4u16, hw), (5u16, sw)] {
        v.extend_from_slice(&vendor_id.to_be_bytes());
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&(ver.len() as u16).to_be_bytes());
        v.extend_from_slice(ver.as_bytes());
    }
    v
}

/// RFC 5415 4.6.10 CAPWAP Control IPv4 Address entry: `[IPv4 4B][WTP Count 2B]`.
/// The second field is the number of WTPs the interface serves.
pub fn control_ipv4_entry(ip: Ipv4Addr, wtp_count: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(6);
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&wtp_count.to_be_bytes());
    v
}

/// Generic (RFC 5415 8.1) Discovery Response (mtype 2) for the vendor-neutral
/// and TP-Link paths: AC Name (4), AC Descriptor (1), CAPWAP Control IPv4
/// Address (10). H3C keeps its own header-mirroring builder.
///
/// Element 10 may carry several entries, one per AC address, when the AC is
/// multihomed (e.g. a discovery broadcast arrived on an interface with more
/// than one address).
pub fn discovery_response(
    seq: u32,
    ac_ips: &[Ipv4Addr],
    ac_name: &[u8],
    vendor_id: u32,
) -> CtrlMsg {
    let mut list = Vec::with_capacity(ac_ips.len() * 6);
    for ip in ac_ips {
        list.extend_from_slice(&control_ipv4_entry(*ip, 0));
    }
    CtrlMsg::new(MsgType::DISC_RESP, seq)
        .add_element(BaseElem::AcName(ac_name.to_vec()))
        .add_elem(
            MsgElemType::AC_DESCRIPTOR,
            &ac_descriptor("1.0", "1.0", vendor_id),
        )
        .add_elem(MsgElemType::CAPWAP_CTRL_IPV4_ADDR, &list)
}

/// Generic (RFC 5415 8.2) Join Response (mtype 4) for the vendor-neutral and
/// TP-Link paths: Result Code (33), AC Name (4), AC Descriptor (1), ECN Support
/// (53), CAPWAP Local IPv4 Address (30), CAPWAP Control IPv4 Address (10).
///
/// A refused join (unapproved WTP) carries the Result Code plus the AC
/// identity only, so the WTP can retry.
pub fn join_response(
    seq: u32,
    ac_ip: Ipv4Addr,
    ac_name: &[u8],
    vendor_id: u32,
    ok: bool,
) -> CtrlMsg {
    let result = if ok { CwResult::Success } else { CwResult::Failure };
    let mut msg = CtrlMsg::new(MsgType::JOIN_RESP, seq)
        .with_result(result)
        .add_element(BaseElem::AcName(ac_name.to_vec()))
        .add_elem(
            MsgElemType::AC_DESCRIPTOR,
            &ac_descriptor("1.0", "1.0", vendor_id),
        );
    if ok {
        msg = msg
            .add_elem(MsgElemType::ECN_SUPPORT, &[1])
            .add_elem(MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, &ac_ip.octets())
            .add_elem(
                MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
                &control_ipv4_entry(ac_ip, 0),
            );
    } else {
        msg = msg.add_elem(
            MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            &control_ipv4_entry(Ipv4Addr::LOCALHOST, 0),
        );
    }
    msg
}

/// Generic (RFC 5415 8.3) Configuration Status Response (mtype 6).
///
/// The caller supplies the element set to relay back (RFC elements plus any
/// vendor-specific payloads); RFC 5415 requires a Result Code, which is appended
/// when the supplied set does not already carry one.
pub fn config_status_response(seq: u32, elems: &[BaseElem]) -> CtrlMsg {
    let mut msg = CtrlMsg::new(MsgType::CONFIG_STATUS_RESP, seq).add_elements(elems.to_vec());
    if !elems.iter().any(|e| matches!(e, BaseElem::ResultCode(_))) {
        msg = msg.with_result(CwResult::Success);
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

/// Command delivered from the management plane to a live WTP session to push a
/// Configuration Update Request (mtype 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigUpdateCmd {
    Push {
        elems: Vec<crate::vendor::h3c::ConfigUpdateElem>,
    },
}

/// Registry mapping a WTP MAC to its live session's command channel, letting the
/// web/API layer push a Configuration Update Request into the running CAPWAP
/// flow (mirrors `firmware::UpgradeRegistry`).
pub struct ConfigUpdateRegistry {
    inner: std::sync::Mutex<std::collections::HashMap<Mac, Sender<ConfigUpdateCmd>>>,
}

impl ConfigUpdateRegistry {
    pub fn new() -> Self {
        ConfigUpdateRegistry {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Associate a WTP MAC with the channel its session listens on.
    pub fn register(&self, mac: Mac, tx: Sender<ConfigUpdateCmd>) {
        self.inner.lock().unwrap().insert(mac, tx);
    }

    /// Whether a live session for this WTP is currently registered.
    pub fn is_active(&self, mac: Mac) -> bool {
        self.inner.lock().unwrap().contains_key(&mac)
    }

    /// Deliver a command to the WTP's session. Returns false when the session is
    /// absent or its channel closed (e.g. the WTP just went offline).
    pub fn trigger(&self, mac: Mac, cmd: ConfigUpdateCmd) -> bool {
        match self.inner.lock().unwrap().get(&mac).cloned() {
            Some(tx) => tx.try_send(cmd).is_ok(),
            None => false,
        }
    }
}

impl Default for ConfigUpdateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            security: SecurityPolicy {
                akm: Akm::Open,
                cipher: Cipher::Ccmp,
                psk: None,
                pmf: Pmf::Disabled,
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
            security: SecurityPolicy {
                akm: Akm::Sae,
                cipher: Cipher::Ccmp,
                psk: Some("person0finterest".into()),
                pmf: Pmf::Disabled,
            },
            ..WlanConfig::default()
        };
        let body = w.security_element();
        // [radio][wlan][akm rank][cipher wire][len:2][psk]
        assert_eq!(body[0], 2);
        assert_eq!(body[1], 1);
        assert_eq!(body[2], 3); // Akm::Sae rank
        assert_eq!(body[3], 2); // Cipher::Ccmp wire
        assert_eq!(
            u16::from_be_bytes([body[4], body[5]]) as usize,
            "person0finterest".len()
        );
        assert_eq!(WlanConfig::decode_security(&body).unwrap(), w.security);
    }

    #[test]
    fn config_update_message() {
        use crate::vendor::h3c::{ConfigUpdateElem, CFG_LED, CFG_TELNET};
        let msg = config_update(
            5,
            &[BaseElem::CapwapTimers {
                disc_interval_secs: 20,
                echo_interval_secs: 60,
            }],
            &[ConfigUpdateElem::Led(1), ConfigUpdateElem::Telnet(0)],
        );
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        assert!(msg
            .elems
            .iter()
            .any(|e| e.tag == MsgElemType::CAPWAP_TIMERS));
        // Base elements come first, then the H3C config-update elements.
        assert_eq!(msg.elems.first().unwrap().tag, MsgElemType::CAPWAP_TIMERS);
        assert!(msg.elems.iter().any(|e| e.tag == CFG_LED));
        assert_eq!(msg.elems.last().unwrap().tag, CFG_TELNET);
    }

    #[test]
    fn config_update_registry_trigger() {
        use crate::vendor::h3c::ConfigUpdateElem;
        use tokio::sync::mpsc;

        let mac = [1, 2, 3, 4, 5, 6];
        let reg = ConfigUpdateRegistry::new();
        assert!(!reg.trigger(mac, ConfigUpdateCmd::Push { elems: vec![] })); // no live session

        let (tx, mut rx) = mpsc::channel(1);
        reg.register(mac, tx);
        assert!(reg.is_active(mac));
        assert!(reg.trigger(
            mac,
            ConfigUpdateCmd::Push {
                elems: vec![ConfigUpdateElem::Led(1)]
            }
        ));
        match rx.blocking_recv() {
            Some(ConfigUpdateCmd::Push { elems }) => {
                assert_eq!(elems, vec![ConfigUpdateElem::Led(1)])
            }
            _ => panic!("expected Push command"),
        }
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

    #[test]
    fn rfc_discovery_response_layout() {
        let msg = discovery_response(
            7,
            &[Ipv4Addr::new(192, 168, 0, 2)],
            b"miniac",
            0x1234_5678,
        );
        assert_eq!(msg.hdr.msg_type, MsgType::DISC_RESP);
        assert_eq!(msg.hdr.seq_num, 7);
        let tags: Vec<u16> = msg.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                MsgElemType::AC_NAME,
                MsgElemType::AC_DESCRIPTOR,
                MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            ]
        );
        // AC Descriptor: 12-byte base + 2 × (vendor 4 + type 2 + len 2 + "1.0").
        assert_eq!(msg.elems[1].data.len(), 34);
        // The AC Information sub-elements carry the enterprise number.
        assert_eq!(&msg.elems[1].data[12..16], &0x1234_5678u32.to_be_bytes());
        // Control IPv4 entry is [4B IP][2B WTP count].
        assert_eq!(msg.elems[2].data, vec![192, 168, 0, 2, 0, 0]);
    }

    #[test]
    fn rfc_join_response_layout() {
        let ac_ip = Ipv4Addr::new(192, 168, 0, 2);
        let msg = join_response(3, ac_ip, b"miniac", 0x1234_5678, true);
        assert_eq!(msg.hdr.msg_type, MsgType::JOIN_RESP);
        let tags: Vec<u16> = msg.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                MsgElemType::RESULT_CODE,
                MsgElemType::AC_NAME,
                MsgElemType::AC_DESCRIPTOR,
                MsgElemType::ECN_SUPPORT,
                MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
                MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            ]
        );
        assert_eq!(msg.elems[0].data, vec![0]); // Success
        assert_eq!(msg.elems[4].data, vec![192, 168, 0, 2]);
        assert_eq!(msg.elems[5].data, vec![192, 168, 0, 2, 0, 0]);

        // A refused join carries the Result Code and AC identity only.
        let refused = join_response(3, ac_ip, b"miniac", 0, false);
        assert_eq!(refused.elems[0].data, vec![1]); // Failure
        let tags: Vec<u16> = refused.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                MsgElemType::RESULT_CODE,
                MsgElemType::AC_NAME,
                MsgElemType::AC_DESCRIPTOR,
                MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            ]
        );
    }
}
