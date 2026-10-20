//! TP-Link AC100 vendor forms for the four configuration messages.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Unlike H3C,
//! which carries private elements as bare top-level tags, AC100 nests them in
//! the RFC Vendor Specific Payload element (37) as
//! `[vendor id 0x12345678][reserved u16][id u16][len u16][value]`. AC100 also
//! implements only three of the four messages: it has no Clear Configuration
//! Request, and expresses "restore defaults" through the reset mask of a Reset
//! Request instead.
//!
//! The Reset Request, Clear Configuration Request and Configuration Status
//! Response forms are wired into the session through [`crate::vendor::profile`].
//! The two Configuration Update Request producers are built and unit tested here,
//! but stay unwired until miniac holds the configuration sources their AC100
//! fields expect (base parameters, offline behaviour, wired VLAN, AP user
//! record); the management-plane push keeps using the vendor-neutral builder.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use crate::capwap::{CwResult, CtrlMsg, MsgElemType, MsgType};
use crate::config;
use crate::elements::{BaseElem, ImageIdentifier};

/// AC100 enterprise identifier. Used both as the Vendor Specific Payload vendor
/// field and as the Image Identifier vendor field; AC100 assembles it at
/// runtime (`lui 0x1234` + `addiu 0x5678`).
pub const VENDOR_ID: u32 = 0x1234_5678;

/// Private element ids, a subset of AC100's 103-entry table.
pub mod priv_id {
    /// AP base parameters.
    pub const AP_BASE_PARA: u16 = 5;
    /// Private wireless service parameter: the security argument of the WLAN
    /// carried alongside it (WTP `CWParseVendorPayload` handler 0x44ecd0,
    /// AC100 `cw_priv_wsrv_para_*`).
    pub const WSRV_PARA: u16 = 9;
    /// Channel state.
    pub const CH_STATE: u16 = 6;
    /// Clear/statistics counter request.
    pub const CLR_STAT: u16 = 13;
    /// Transparent data request.
    pub const TRANS_DATA_REQUEST: u16 = 20;
    /// AC information.
    pub const AC_INFO: u16 = 27;
    /// WLAN list.
    pub const WLAN_LIST: u16 = 30;
    /// Station list.
    pub const STA_LIST: u16 = 31;
    /// Reset mask (u32).
    pub const RESET_MASK: u16 = 35;
    /// AP resource information.
    pub const AP_RES_INFO: u16 = 37;
    /// Supported special messages bitmap (AC100 sends 0x2f2e).
    pub const SPEC_MSG_SW: u16 = 38;
    /// Configuration type.
    pub const CONFIG_TYPE: u16 = 39;
    /// Wired VLAN (primary form).
    pub const AP_WIRE_VLAN: u16 = 48;
    /// AP LED status.
    pub const AP_LED_STATUS: u16 = 56;
    /// AP LED operation.
    pub const AP_LED_OP: u16 = 57;
    /// Private 58; AC100 sends `0128080a` in the Configuration Status Response
    /// alongside the AP base parameters and offline behaviour records.
    pub const AP_PRIV58: u16 = 58;
    /// AP offline behaviour; value is two u32, AC100 sends `(x, 300)`.
    pub const AP_OFFLINE: u16 = 60;
    /// AP user (AC100 sends 128 bytes).
    pub const AP_USER: u16 = 61;
    /// AP configuration checksum.
    pub const AP_CONFIG_CHECKSUM: u16 = 65;
    /// Wired VLAN (alternate form).
    pub const AP_WIRE_VLAN_ALT: u16 = 67;
    /// AP trunk.
    pub const AP_TRUNK: u16 = 68;
    /// AP firmware id.
    pub const AP_FIRMWARE_ID: u16 = 91;
}

/// Reset mask value AC100 itself sends for a plain restart
/// (`apupd_reset_request_create`, `apmngr_pkt_reset_pkt_send`). AC100 carries a
/// separate "reset type" (2..4) above the mask; no factory-default bit was
/// identified, so callers that need one must pass it explicitly.
pub const RESET_MASK_RESTART: u32 = 0x0000_0001;

/// Private 38 (SPEC_MSG_SW / supported special messages) value: two u32,
/// `[msgMask][swMask]`. The WTP reader for private 38 (0x44dc44) reads exactly
/// two u32 and logs them as `msgMask`/`swMask`; a shorter value over-reads into
/// the next element and fails the reader's total-length check, which makes the
/// WTP drop the entire Configuration Status Response. AC100 sends `0x6e` for
/// both masks, so the wire value is
/// `00 00 00 6e 00 00 00 6e`.
const SPEC_MSG_MASKS: [u8; 8] = [0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x6e];

/// Private payload lengths/values AC100 (TL-AC100) sends in the Configuration
/// Status Response, kept verbatim so the WTP sees exactly its own AC's form.
/// The decrypt-error period is the 3-byte value its parser
/// (`CWParseDecryptErrorReportPeriod` 0x41c964) accepts; the idle timeout is
/// the RFC 23 value AC100 sends.
const DECRYPT_ERR_REPORT_PERIOD: [u8; 3] = [0x01, 0x00, 0x78];
const IDLE_TIMEOUT_SECS: u32 = 3600;

/// Reserved word AC100 writes on the Configuration Status Response's private
/// 38 (SPEC_MSG_SW) and private 61 (AP_USER) payloads.
const SPEC_MSG_RSV: u16 = 0x0026;
const AP_USER_RSV: u16 = 0x003b;

/// Private records AC100 additionally carries in its Configuration Status
/// Response: private 5 (AP base parameters), private 60 (AP
/// offline behaviour) and private 58, with AC100's own reserved words (private
/// 5 uses 0x0000, private 58 uses 0x003a). Values are kept verbatim so the WTP
/// sees exactly the form its own AC sends.
const AP_BASE_PARA_RSV: u16 = 0x0000;
const AP_OFFLINE_RSV: u16 = 0x003b;
const AP_PRIV58_RSV: u16 = 0x003a;
const AP_BASE_PARA_VALUE: [u8; 8] = [0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x05];
const AP_OFFLINE_VALUE: [u8; 24] = [
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const AP_PRIV58_VALUE: [u8; 4] = [0x01, 0x28, 0x08, 0x0a];

/// `[4B vendor id 0x12345678][name]` — AC100 does not NUL-terminate the name.
pub fn image_identifier(name: &[u8]) -> BaseElem {
    BaseElem::ImageIdentifier(ImageIdentifier::new(VENDOR_ID, name.to_vec()))
}

/// Wrap private TLVs in the RFC 37 Vendor Specific Payload element.
pub fn vendor_specific(tlvs: Vec<(u16, Vec<u8>)>) -> BaseElem {
    vendor_specific_rsv(0, tlvs)
}

/// Like [`vendor_specific`] but with an explicit reserved word. AC100 sets the
/// reserved field non-zero on some Configuration Status Response payloads
/// (private 38 → `0x0026`, private 61 → `0x003b`), so it is carried verbatim
/// instead of always zeroed.
pub fn vendor_specific_rsv(reserved: u16, tlvs: Vec<(u16, Vec<u8>)>) -> BaseElem {
    BaseElem::VendorSpecific {
        vendor_id: VENDOR_ID,
        reserved,
        tlvs,
    }
}

/// Reset Request (17): `[RFC25 image id][VSP → private 35 reset mask]`.
pub fn reset_request(seq: u32, image_name: &[u8], mask: u32) -> CtrlMsg {
    CtrlMsg::new(MsgType::RESET_REQ, seq)
        .add_element(image_identifier(image_name))
        .add_element(vendor_specific(vec![(
            priv_id::RESET_MASK,
            mask.to_be_bytes().to_vec(),
        )]))
}

/// Configuration Update Request (7), producer A: an image (re)load carries the
/// image identifier alone.
pub fn image_update_request(seq: u32, image_name: &[u8]) -> CtrlMsg {
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_element(image_identifier(image_name))
}

/// Configuration synchronisation inputs for producer B.
pub struct ConfigSync<'a> {
    /// Private 5 (AP base parameters), opaque vendor payload.
    pub base_para: &'a [u8],
    /// Private 60 (AP offline behaviour): `(first u32, second u32)`; AC100 sends
    /// `(x, 300)`.
    pub offline: (u32, u32),
    /// RFC 12 CAPWAP timers (discovery interval, echo interval), seconds.
    pub timers: (u8, u8),
    /// RFC 23 Idle Timeout, seconds.
    pub idle_timeout: u32,
    /// Wired VLAN: private element id (48 or 67) plus opaque payload.
    pub wire_vlan: (u16, &'a [u8]),
    /// Private 61 (AP user); AC100 sends 128 bytes.
    pub ap_user: &'a [u8],
    /// Optional private 68 (AP trunk) u32.
    pub trunk: Option<u32>,
}

/// Configuration Update Request (7), producer B: configuration synchronisation.
pub fn config_update_request(seq: u32, sync: &ConfigSync<'_>) -> CtrlMsg {
    let mut msg = CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq)
        .add_element(vendor_specific(vec![
            (priv_id::AP_BASE_PARA, sync.base_para.to_vec()),
            (
                priv_id::AP_OFFLINE,
                [sync.offline.0.to_be_bytes(), sync.offline.1.to_be_bytes()].concat(),
            ),
        ]))
        .add_element(BaseElem::CapwapTimers {
            disc_interval_secs: sync.timers.0,
            echo_interval_secs: sync.timers.1,
        })
        .add_element(BaseElem::IdleTimeout(sync.idle_timeout))
        .add_element(vendor_specific(vec![(
            sync.wire_vlan.0,
            sync.wire_vlan.1.to_vec(),
        )]))
        .add_element(vendor_specific(vec![(
            priv_id::AP_USER,
            sync.ap_user.to_vec(),
        )]));
    if let Some(trunk) = sync.trunk {
        msg = msg.add_element(vendor_specific(vec![(
            priv_id::AP_TRUNK,
            trunk.to_be_bytes().to_vec(),
        )]));
    }
    msg
}

/// Configuration Status Response (6) inputs.
pub struct ConfigStatusResp<'a> {
    pub seq: u32,
    /// RFC 12 CAPWAP timers (discovery interval, echo interval), seconds.
    pub timers: (u8, u8),
    /// RFC 2 AC IPv4 list; AC100 sends a single local address.
    pub ac_ip: Ipv4Addr,
    /// Private 61 (AP user) payload; omitted from the message when empty.
    pub ap_user: &'a [u8],
}

/// Configuration Status Response (6).
///
/// The base element types a TP-Link WTP accepts here are narrow: the
/// TL-AP1300GI parser (`CWParseConfigureResponseMessage` 0x427c60) dispatches
/// only 2 AC IPv4 List, 3 AC IPv6 List, 12 CAPWAP Timers, 16 Decrypt Error
/// Report Period, 23 Idle Timeout, 32 Radio Operational State, 37 Vendor
/// Specific Payload and 40 WTP Fallback; any other top-level type (including
/// RFC 33 Result Code and 1024 Add WLAN) makes it drop the whole message as
/// "Unrecognized Message Element". The response also carries no WLAN
/// configuration at all: the save path (`CWSaveConfigureResponseMessage`
/// 0x4271d0) only handles private VSP payloads (SPEC_MSG_SW, USER_PW, band
/// steering, offline behaviour, RSSI threshold, WeChat white IP list, LAN
/// config). Element order mirrors AC100's own response: RFC 12
/// timers, RFC 16 Decrypt Error Report Period (3-byte), RFC 23 Idle Timeout,
/// RFC 40 `1`, RFC 2 address list, then the private VSPs — 38
/// (`SPEC_MSG_MASKS`) and, when set, 61 (`AP_USER`).
///
/// Element 12 (CAPWAP Timers) is not optional in practice: the WTP derives its
/// own tick from the Echo Interval, and miniac drops a Run-state session that
/// goes silent for 30s, so the interval must stay below that — an interval of
/// 60 makes the WTP report every 60s and the session is torn down first.
///
/// Element 16 (Decrypt Error Report Period) is the 3-byte `010078` value AC100
/// sends. The WTP parser (`CWParseDecryptErrorReportPeriod` 0x41c964) reads one
/// 8-bit value and one 16-bit value and then requires the consumed byte count to
/// equal the element length, so only a 3-byte value is accepted; the RFC 4-byte
/// form makes it fail the check and the WTP drops the entire response.
///
/// Element 2 (AC IPv4 List) deviates from RFC 5415: the WTP parser
/// (`CWParseACIPv4List` 0x41d920) requires `len % 4 == 0` and derives the count
/// as `len / 4`, so the value is the bare 4-byte address(es) with no leading
/// count octet. Sending the RFC `[count][addresses]` form makes the parser fail
/// and the WTP drop the entire response.
///
/// Element 40 (WTP Fallback) and the private payloads are length-checked too:
/// `CWParseWTPFallback` 0x41c57c consumes a single byte and
/// `CWCheckVendorElemLen` requires private 38 to be exactly 8 bytes.
pub fn config_status_response(inp: &ConfigStatusResp<'_>) -> CtrlMsg {
    let mut msg = CtrlMsg::new(MsgType::CONFIG_STATUS_RESP, inp.seq);
    msg = msg.add_element(BaseElem::CapwapTimers {
        disc_interval_secs: inp.timers.0,
        echo_interval_secs: inp.timers.1,
    });
    msg = msg.add_element(BaseElem::Unknown(
        MsgElemType::DECRYPT_ERR_REPORT_PERIOD,
        DECRYPT_ERR_REPORT_PERIOD.to_vec(),
    ));
    msg = msg.add_element(BaseElem::IdleTimeout(IDLE_TIMEOUT_SECS));
    msg = msg.add_element(BaseElem::WtpFallback(1));
    // Bare addresses (no RFC count octet), per CWParseACIPv4List.
    msg = msg.add_element(BaseElem::Unknown(
        MsgElemType::AC_IPV4_LIST,
        inp.ac_ip.octets().to_vec(),
    ));
    // Private 38 carries AC100's non-zero reserved word; the private records
    // that follow carry AC100's own reserved words. The WTP's radio-record save
    // rejects the record until the AC has sent this preamble, so all of AC100's
    // records are reproduced verbatim.
    msg = msg.add_element(vendor_specific_rsv(
        SPEC_MSG_RSV,
        vec![(priv_id::SPEC_MSG_SW, SPEC_MSG_MASKS.to_vec())],
    ));
    msg = msg.add_element(vendor_specific_rsv(
        AP_BASE_PARA_RSV,
        vec![(priv_id::AP_BASE_PARA, AP_BASE_PARA_VALUE.to_vec())],
    ));
    msg = msg.add_element(vendor_specific_rsv(
        AP_OFFLINE_RSV,
        vec![(priv_id::AP_OFFLINE, AP_OFFLINE_VALUE.to_vec())],
    ));
    if !inp.ap_user.is_empty() {
        msg = msg.add_element(vendor_specific_rsv(
            AP_USER_RSV,
            vec![(priv_id::AP_USER, inp.ap_user.to_vec())],
        ));
    }
    msg = msg.add_element(vendor_specific_rsv(
        AP_PRIV58_RSV,
        vec![(priv_id::AP_PRIV58, AP_PRIV58_VALUE.to_vec())],
    ));
    msg
}

/// AC100's AC Descriptor in its Join Response (156 bytes),
/// reproduced verbatim. Byte [5] is `0x0002` in AC100's Discovery Response and
/// `0x0003` here, so the two are not interchangeable. The descriptor carries
/// AC100's `0x12345678`-prefixed hardware ("AccessController") and software
/// ("2.0.3 Build 20171123 Rel.59914") sub-TLVs.
const AC_DESCRIPTOR_JOIN: [u8; 156] = [
    0x00, 0x05, 0x07, 0xd0, 0x00, 0x03, 0x00, 0x64, 0x02, 0x02, 0x00, 0x04,
    0x12, 0x34, 0x56, 0x78, 0x00, 0x04, 0x00, 0x40, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x34, 0x56, 0x78, 0x00, 0x05, 0x00, 0x40, 0x32, 0x2e, 0x30, 0x2e,
    0x33, 0x20, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x32, 0x30, 0x31, 0x37,
    0x31, 0x31, 0x32, 0x33, 0x20, 0x52, 0x65, 0x6c, 0x2e, 0x35, 0x39, 0x39,
    0x31, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// CAPWAP Local IPv6 Address (element 50) value in AC100's Join Response: the
/// AC capability word the WTP latches for the session. Its bit 1 is set
/// (`0x1f4b & 2`), which makes the WTP's Vendor Specific Payload validator
/// (`CWCheckVendorElemLen`) expect a 20-byte private 8 — the length the pushed
/// radio-config record carries. Without it the validator demands 16 bytes, the
/// record fails to parse, and the WTP drops the whole Configuration Update
/// Request, leaving the radio on its own defaults instead of the pushed channel.
const AC_CAPABILITIES: [u8; 16] = [
    0x00, 0x20, 0x1f, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Join Response (4) for TP-Link: AC100's element set verbatim — Result Code
/// (33), AC Descriptor (1), AC Name (4), the capability word in CAPWAP Local
/// IPv6 Address (50), CAPWAP Control IPv4 Address (10) and private 39
/// (`CONFIG_TYPE`).
///
/// Unlike the vendor-neutral form this omits ECN Support (53) and CAPWAP Local
/// IPv4 Address (30); AC100 sends neither, and element 50 is what the WTP needs
/// to accept the pushed radio configuration.
pub fn join_response(seq: u32, ac_ip: Ipv4Addr, ac_name: &[u8], ok: bool) -> CtrlMsg {
    let result = if ok {
        CwResult::Success
    } else {
        CwResult::Failure
    };
    let mut msg = CtrlMsg::new(MsgType::JOIN_RESP, seq)
        .with_result(result)
        .add_elem(MsgElemType::AC_DESCRIPTOR, &AC_DESCRIPTOR_JOIN)
        .add_element(BaseElem::AcName(ac_name.to_vec()));
    if ok {
        msg = msg
            .add_elem(MsgElemType::CAPWAP_LOCAL_IPV6_ADDR, &AC_CAPABILITIES)
            .add_elem(
                MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
                &config::control_ipv4_entry(ac_ip, 0),
            )
            .add_element(vendor_specific(vec![(
                priv_id::CONFIG_TYPE,
                vec![0x00, 0x00, 0x00, 0x01],
            )]));
    } else {
        msg = msg.add_elem(
            MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            &config::control_ipv4_entry(Ipv4Addr::LOCALHOST, 0),
        );
    }
    msg
}

/// TP-Link private "WLAN Configuration Update Request/Response"
/// (`0x0033DD01`/`0x0033DD02`, AC100 `CWWTPManageRunAcRequestMessage` and the
/// WTP's `CWWTPEnterRun` dispatcher). Not an RFC 5415 message number: the
/// TL-AP1300GI rejects the RFC Configuration Update Request (7) path for WLANs
/// - `CWParseConfigurationUpdateRequest` 0x42d660 admits only private elements
/// and drops elements 1024/1027 - so WLAN configuration reaches the WTP only
/// through this message, sent while it runs.
pub const WLAN_CONFIG_UPDATE_REQ: u32 = 0x0033_dd01;
pub const WLAN_CONFIG_UPDATE_RESP: u32 = 0x0033_dd02;

/// Private 9 security options. The byte at value offset 8 selects the
/// security section; the WTP handler (0x44ecd0) dispatches on 1..3 and treats
/// anything else as invalid, so an open WLAN must omit the element instead of
/// sending a zero here.
pub mod wlan_sec {
    /// WPA/WPA2/WPA3 personal (PSK), AC100's `wpapsk-*` block.
    pub const PSK: u8 = 1;
}

/// Private 9 (private wireless service parameter) value for a WLAN.
///
/// Layout, from the WTP reader (0x44ecd0, storing value offsets 0..8 into its
/// argument record) and AC100's assembler (0x4e6d8c, which writes them in this
/// order and length-checks via `cw_priv_wsrv_para_len_get` 0x4e6310):
///
/// ```text
///  0  radio id
///  1  WLAN id
///  2  VLAN id              (u16)
///  4  max users            (u16)
///  6  network type          (AC100 sends 1)
///  7  client isolation
///  8  security option      (wlan_sec)
///  9  auth type                                             ┐
/// 10  cipher                                                │ security
/// 11  rekey period         (u32)                            │ option PSK
/// 15  key length           (u16)                            │
/// 17  PSK                                                   ┘
/// ```
///
/// The auth and cipher selectors come from the shared security-policy mapping
/// (`cw_priv_wsrv_para_assemble` writes auth=2 WPA2 / cipher=2 AES for AC100's
/// own WPA2-PSK WLANs, which is what the TL-AP1300GI deploys). The value must
/// consume the element exactly (`CWCheckVendorElemLen` requires private 9 to be
/// `consumed + 9` bytes); a mismatch makes the WTP reject the whole message.
/// Returns `None` for a WLAN without a key, which must then be pushed by its Add
/// WLAN element alone.
pub fn wsrv_para(w: &config::WlanConfig) -> Option<Vec<u8>> {
    let psk = w.security.psk.as_deref().filter(|p| !p.is_empty())?;
    let fields = crate::vendor::profile::VendorProfile::TpLink.security_fields(&w.security);
    let mut v = Vec::with_capacity(17 + psk.len());
    v.push(w.radio_id);
    v.push(w.wlan_id);
    v.extend_from_slice(&(w.vlan_id as u16).to_be_bytes());
    v.extend_from_slice(&(w.client_count as u16).to_be_bytes());
    v.push(1); // network type (AC100 sends 1)
    v.push(u8::from(w.isolate));
    v.push(wlan_sec::PSK);
    v.push(fields.auth);
    v.push(fields.cipher as u8);
    v.extend_from_slice(&w.rekey_period.to_be_bytes());
    v.extend_from_slice(&(psk.len() as u16).to_be_bytes());
    v.extend_from_slice(psk.as_bytes());
    Some(v)
}

/// Private 7 (Add MAC ACL) trailing value AC100 appends to each WLAN push
/// (`00 30`).
const WLAN_CFG_MAC_ACL: [u8; 2] = [0x00, 0x30];

/// Add WLAN element (1024) value in AC100's own form.
///
/// ```text
///  0  radio id
///  1  WLAN id
///  2  capability word                 (AC100 sends 0x8000)
///  4  key index/status + key length   (4 bytes, zero)
///  8  group TSC                       (6 bytes, zero)
/// 14  QoS, auth, MAC mode             (3 bytes, zero)
/// 17  tunnel/broadcast flag           (AC100 sends 0x01)
/// 18  broadcast flag                  (AC100 sends 0x01)
/// 19  SSID                            (to the end of the value)
/// ```
///
/// The trailing `01 01` pair is what enables the WLAN and puts the SSID on the
/// air. With the RFC 5415 flags miniac sent before (capability 0x0001 and both
/// trailing bytes 0) the WTP ACKs the message with 0x0033DD02 but never brings
/// the WLAN up, so no SSID is seen on the air. Only radio id, WLAN id and the
/// SSID vary between WLANs; the fixed 19-byte header is kept byte-identical to
/// AC100's.
fn add_wlan_value(w: &config::WlanConfig) -> Vec<u8> {
    let mut v = Vec::with_capacity(19 + w.ssid.len());
    v.push(w.radio_id);
    v.push(w.wlan_id);
    v.extend_from_slice(&[0x80, 0x00]); // AC100 sends capability 0x8000
    v.extend_from_slice(&[0u8; 13]); // key idx/status, key len, group TSC, QoS, auth, MAC
    v.extend_from_slice(&[0x01, 0x01]); // AC100 sends the tunnel/broadcast flags as 01 01
    v.extend_from_slice(&w.ssid);
    v
}

/// WLAN Configuration Update Request (0x0033DD01) carrying one WLAN.
///
/// Element order mirrors AC100's own push: the IEEE 802.11 Add WLAN element
/// first, the private 9 security payload next, then the private 7 (Add MAC ACL)
/// element. The WTP applies the WLAN when the message carries an Add WLAN
/// element: `CWParseWlanConfigurationUpdateRequest` 0x42e34c remembers the last
/// Add/Delete WLAN element it saw (`s4`, written at 0x42e550/0x42e5d0) and, once
/// the whole message is consumed, routes to the Add path when that was 1024
/// (0x42e494). The security arguments come from the private 9 payload. Both are
/// per-WLAN, so a set of WLANs is pushed as a sequence of messages, one per
/// WLAN.
pub fn wlan_config_update_request(seq: u32, w: &config::WlanConfig) -> CtrlMsg {
    let mut msg = CtrlMsg::new(WLAN_CONFIG_UPDATE_REQ, seq)
        .add_elem(MsgElemType::ADD_WLAN, &add_wlan_value(w));
    if let Some(para) = wsrv_para(w) {
        msg = msg.add_element(vendor_specific(vec![(priv_id::WSRV_PARA, para)]));
    }
    msg.add_element(BaseElem::Unknown(
        MsgElemType::ADD_MAC_ACL_ENTRY,
        WLAN_CFG_MAC_ACL.to_vec(),
    ))
}

/// WLAN slots per radio. The WTP's WLAN-list event names exactly ids 1..=8, and
/// the same message family addresses a WLAN by `{radio, wlan}`.
pub const WLAN_IDS_PER_RADIO: u8 = 8;

/// WLAN Configuration Update Request (0x0033DD01) deleting one WLAN slot.
///
/// Add WLAN only appends to the WTP's own table, so the factory SSIDs it holds
/// (`office1_*`, `Guest_*`) survive a plain push; they go away only through
/// Delete WLAN. A message carrying a Delete WLAN element routes to
/// `CWManageDelWlanValues` (`CWBindingSaveConfigurationUpdateRequest` 0x458e70
/// keys on 1027), which looks the entry up by `{radio, wlan}` exactly as
/// `CWParseDelWlanValue` 0x4543dc and `WlanCmpHandle` 0x450af8 read it, hence
/// the two-byte RFC 5416 6.4 value with no private element.
pub fn wlan_config_del_request(seq: u32, radio_id: u8, wlan_id: u8) -> CtrlMsg {
    CtrlMsg::new(WLAN_CONFIG_UPDATE_REQ, seq).add_elem(MsgElemType::DEL_WLAN, &[radio_id, wlan_id])
}

/// Top-level element 51 carrying the periodic per-radio station report. TP-Link
/// reuses the RFC 5415 element id 51 (CAPWAP Transport Protocol) for its own
/// station state report (AP1300GI `CWAssembleMsgStationStateReport` 0x42f0dc;
/// AC100 `_uac_wsta_pkt_rssi_report` 0x51D80C keys on top-level id 0x33). It
/// rides the WTP Event Request (message type 9) once the AP has been handed its
/// report period by the Configuration Status Response's private 60.
pub const STATION_REPORT_TAG: u16 = 51;

/// One station in a station report: its MAC and the signal strength the radio
/// measured for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationRecord {
    pub mac: [u8; 6],
    /// RSSI in dBm (signed), as the AP reports it.
    pub rssi: i32,
}

/// One radio's entry in a station report: the radio id and the stations
/// currently associated on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationReport {
    pub radio_id: u8,
    pub stations: Vec<StationRecord>,
}

/// Parse a station report value: `[radio u8][count u32]` then `count` records of
/// `[6B MAC][1B RSSI]`. A zero count is the 5-byte value the AP sends while no
/// station is associated. Returns `None` when the value is shorter than the
/// declared record count, so a truncated report is ignored instead of being
/// applied half-read.
pub fn parse_station_report(value: &[u8]) -> Option<StationReport> {
    let radio_id = *value.first()?;
    let count = u32::from_be_bytes(value.get(1..5)?.try_into().ok()?) as usize;
    let recs = value.get(5..)?;
    if recs.len() < count * 7 {
        return None;
    }
    let stations = (0..count)
        .map(|i| {
            let rec = &recs[i * 7..i * 7 + 7];
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&rec[..6]);
            StationRecord {
                mac,
                rssi: rec[6] as i8 as i32,
            }
        })
        .collect();
    Some(StationReport { radio_id, stations })
}

/// One entry of the WLAN list the WTP reports already holding (private 30).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedWlan {
    /// Radio id this entry belongs to. The byte reads 1 and 2 while the WTP holds
    /// WLAN id 1 on both radios, so it is the radio id and not the WLAN id; the
    /// list carries one SSID per radio.
    pub radio_id: u8,
    /// SSID the WTP holds on that radio, NUL-trimmed out of its fixed 32-byte
    /// name field.
    pub ssid: String,
}

/// Parse a private 30 (WLAN list) value: a two-word header followed by
/// `count` records of `[u8 radio_id][32B SSID]`. The WTP carries it in its
/// Configuration Status Request (wire message type 5), so the AC learns what
/// the WTP already holds before deciding whether to push. The header's first
/// word is not understood (observed `1`, then the record count); only the count
/// is used. Returns `None` when the value does not hold the declared records, so
/// a truncated list is ignored instead of half-read.
pub fn parse_wlan_list(value: &[u8]) -> Option<Vec<SavedWlan>> {
    const REC: usize = 33; // [u8 radio_id][32B SSID]
    let count = u32::from_be_bytes(value.get(4..8)?.try_into().ok()?) as usize;
    let recs = value.get(8..)?;
    if recs.len() < count * REC {
        return None;
    }
    Some(
        (0..count)
            .map(|i| {
                let rec = &recs[i * REC..i * REC + REC];
                let name = &rec[1..];
                let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                SavedWlan {
                    radio_id: rec[0],
                    ssid: String::from_utf8_lossy(&name[..end]).into_owned(),
                }
            })
            .collect(),
    )
}

/// Private 37 (AP resource information) value, live wire:
/// `[radio u8][band type u8][channel u8][power u16]`. The band type byte is the
/// same 0x06/0x09 selector `radio_cfg_variant` writes into the private radio
/// record (0x06 = 2.4G, 0x09 = 5G). Instances: radio 1 `01 06 06 00 0d`
/// (2.4G, channel 6, power 13), radio 2 `02 09 95 00 0f` (5G, channel 149,
/// power 15). The AP reports it in the WTP Event Request every ~20 s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApResInfo {
    pub radio_id: u8,
    pub band: Option<&'static str>,
    pub channel: u32,
    pub tx_power: i32,
}

/// Parse a private 37 (AP resource information) value. Returns `None` when the
/// value is too short to hold the fixed five fields.
pub fn parse_ap_res_info(value: &[u8]) -> Option<ApResInfo> {
    if value.len() < 5 {
        return None;
    }
    Some(ApResInfo {
        radio_id: value[0],
        band: match value[1] {
            0x06 => Some("2.4G"),
            0x09 => Some("5G"),
            _ => None,
        },
        channel: value[2] as u32,
        tx_power: u16::from_be_bytes([value[3], value[4]]) as i32,
    })
}

/// Private radio-record base tags AC100 carries in the Configuration Update
/// Request that brings a radio up. 0x0404 and 0x0406 have no RFC 5416 meaning
/// and are TP-Link's own per-radio channel/transmit records; 0x0411 (MAC
/// Operation) and 0x0416 (Station Event Type) are the RFC 5416 names for the
/// same numbers (see [`MsgElemType::MAC_OPERATION`] /
/// [`MsgElemType::STATION_EVENT_TYPE`]).
const RADIO_CFG_CHAN: u16 = 0x0404;
const RADIO_CFG_TX: u16 = 0x0406;

/// Last byte of the MAC Operation record and second byte of the private 8
/// payload, which AC100 sends per radio (`0d`/`06` for radio 1, `0f`/`09` for
/// radio 2).
fn radio_cfg_variant(radio_id: u8) -> (u8, u8) {
    if radio_id == 1 {
        (0x0d, 0x06)
    } else {
        (0x0f, 0x09)
    }
}

/// Radio-record channel field value (`0x0404` byte 2, `uChannel`) that selects
/// ACS: the WTP runs its own background channel scan and picks the channel.
/// This is the default.
pub const CHANNEL_ACS: u8 = 0;

/// Map the AC's IEEE channel number for a band to the radio-record byte. `0`
/// keeps [`CHANNEL_ACS`] so the WTP runs its own scan and picks the channel
/// (allowed and preferred); a non-zero number pins it (2.4G: 1–13,
/// 5G: 36–165).
pub fn channel_field(channel: u32) -> u8 {
    channel as u8
}

/// Configuration Update Request (7), radio part 1: the bare administrative-state
/// element. AC100 sends this once per radio before the record that enables it
/// (`radio 1 -> 2`, `radio 2 -> 2`).
pub fn radio_admin_state_request(seq: u32, radio_id: u8, admin_state: u8) -> CtrlMsg {
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_element(BaseElem::RadioAdminState {
        radio_id,
        admin_state,
    })
}

/// Configuration Update Request (7), radio part 2: enable the radio and hand it
/// its private records, AC100's element set.
///
/// The element set is TP-Link's own and is not the RFC 5415 radio form; it is
/// reproduced verbatim because the WTP keys its radio bring-up on it. Without
/// this the radio stays administratively down and the WTP silently drops the
/// per-radio WLAN/SSID configuration, so the SSID never goes on the air. Only
/// the leading radio id, the two per-radio variant bytes and `channel` differ
/// between radios.
///
/// `channel` is the `0x0404` record's channel field (byte 2, `uChannel`); pass
/// it through [`channel_field`] so ACS (the default) stays AUTO and only a
/// band configured manual pins a concrete channel. While the field is AUTO the
/// WTP keeps its background channel scan running and may re-tune; a pinned
/// channel disables that ("Channel != AUTO"). AC100 sent AUTO on both radios.
pub fn radio_config_request(seq: u32, radio_id: u8, channel: u8) -> CtrlMsg {
    let (mac_op_last, priv8_second) = radio_cfg_variant(radio_id);
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq)
        .add_element(BaseElem::RadioAdminState {
            radio_id,
            admin_state: 1,
        })
        .add_elem(
            RADIO_CFG_CHAN,
            &[
                radio_id, 0x00, channel, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08,
                0x00, 0x32, 0x00, 0x64, 0x00, 0x14, 0x00,
            ],
        )
        .add_elem(
            RADIO_CFG_TX,
            &[
                radio_id, 0x00, 0x09, 0x2a, 0x00, 0x00, 0x09, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
        )
        .add_elem(MsgElemType::MAC_OPERATION, &[radio_id, 0x00, 0x00, mac_op_last])
        .add_elem(
            MsgElemType::STATION_EVENT_TYPE,
            &[
                radio_id, 0x01, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x43,
                0x4e, 0x20, 0x00,
            ],
        )
        .add_element(vendor_specific_rsv(
            0x0008,
            vec![(
                8,
                vec![
                    radio_id,
                    priv8_second,
                    0x02,
                    0x01,
                    0x00,
                    0x64,
                    0x00,
                    0x01,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x0a,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ],
            )],
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capwap::MsgElemType;
    use crate::vendor::vsp;

    /// Element framing as it lands on the wire: `[tag u16][len u16][value]`.
    fn elems(msg: &CtrlMsg) -> Vec<(u16, Vec<u8>)> {
        msg.elems.iter().map(|e| (e.tag, e.data.clone())).collect()
    }

    #[test]
    fn reset_request_matches_ac100_layout() {
        let msg = reset_request(7, b"all_version", RESET_MASK_RESTART);
        assert_eq!(msg.hdr.msg_type, MsgType::RESET_REQ);
        let e = elems(&msg);
        assert_eq!(e.len(), 2);
        // Image Identifier: vendor id 0x12345678 then the bare name, no NUL.
        assert_eq!(e[0].0, MsgElemType::IMAGE_ID);
        let mut want = vec![0x12, 0x34, 0x56, 0x78];
        want.extend_from_slice(b"all_version");
        assert_eq!(e[0].1, want);
        // Vendor Specific Payload wrapping private 35 (reset mask, u32).
        assert_eq!(e[1].0, MsgElemType::VENDOR_SPECIFIC_PAYLOAD);
        assert_eq!(
            e[1].1,
            vsp::join_value(VENDOR_ID, 0, &[(35, vec![0, 0, 0, 1])])
        );
        let (vendor, _, tlvs) = vsp::split_value(&e[1].1).unwrap();
        assert_eq!(vendor, VENDOR_ID);
        assert_eq!(tlvs, vec![(35u16, vec![0u8, 0, 0, 1])]);
    }

    #[test]
    fn image_update_request_is_image_identifier_only() {
        let msg = image_update_request(9, b"sw-version 1.0");
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        let e = elems(&msg);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, MsgElemType::IMAGE_ID);
        assert_eq!(e[0].1.len(), 4 + 14);
        assert_eq!(e[0].1[..4], [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn config_update_request_producer_b_order() {
        let sync = ConfigSync {
            base_para: &[0xaa],
            offline: (0, 300),
            timers: (20, 60),
            idle_timeout: 300,
            wire_vlan: (48, &[0x01, 0x02]),
            ap_user: &[0x11; 128],
            trunk: Some(7),
        };
        let msg = config_update_request(3, &sync);
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        let e = elems(&msg);
        assert_eq!(e.len(), 6);
        assert_eq!(e[0].0, MsgElemType::VENDOR_SPECIFIC_PAYLOAD);
        let (_, _, tlvs) = vsp::split_value(&e[0].1).unwrap();
        assert_eq!(vsp::find(&tlvs, 5), Some(&[0xaau8][..]));
        // private 60 = two u32, the second being the 300-second interval
        assert_eq!(vsp::find(&tlvs, 60), Some(&[0u8, 0, 0, 0, 0, 0, 1, 44][..]));
        assert_eq!(e[1].0, MsgElemType::CAPWAP_TIMERS);
        assert_eq!(e[1].1, vec![20, 60]);
        assert_eq!(e[2].0, MsgElemType::IDLE_TIMEOUT);
        assert_eq!(e[2].1, 300u32.to_be_bytes());
        assert_eq!(e[3].0, MsgElemType::VENDOR_SPECIFIC_PAYLOAD);
        assert_eq!(
            vsp::split_value(&e[3].1).unwrap().2,
            vec![(48u16, vec![1, 2])]
        );
        assert_eq!(e[4].0, MsgElemType::VENDOR_SPECIFIC_PAYLOAD);
        assert_eq!(
            vsp::split_value(&e[4].1).unwrap().2,
            vec![(61u16, vec![0x11; 128])]
        );
        assert_eq!(e[5].0, MsgElemType::VENDOR_SPECIFIC_PAYLOAD);
        assert_eq!(
            vsp::split_value(&e[5].1).unwrap().2,
            vec![(68u16, 7u32.to_be_bytes().to_vec())]
        );
    }

    #[test]
    fn config_status_response_element_order() {
        let inp = ConfigStatusResp {
            seq: 11,
            timers: (20, 20),
            ac_ip: Ipv4Addr::new(192, 168, 5, 253),
            ap_user: &[0x22; 4],
        };
        let msg = config_status_response(&inp);
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_STATUS_RESP);
        // Only the base types the WTP parser dispatches on: no RFC 33 and no
        // 1024 (both would make the WTP drop the message). Element order and
        // values mirror AC100's own response.
        let tags: Vec<u16> = msg.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                MsgElemType::CAPWAP_TIMERS,
                MsgElemType::DECRYPT_ERR_REPORT_PERIOD,
                MsgElemType::IDLE_TIMEOUT,
                MsgElemType::WTP_FALLBACK,
                MsgElemType::AC_IPV4_LIST,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 38
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 5
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 60
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 61
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 58
            ]
        );
        assert_eq!(msg.elems[0].data, vec![20, 20]);
        assert_eq!(msg.elems[1].data, DECRYPT_ERR_REPORT_PERIOD.to_vec());
        assert_eq!(msg.elems[2].data, IDLE_TIMEOUT_SECS.to_be_bytes().to_vec());
        assert_eq!(msg.elems[3].data, vec![1]);
        // Element 2 value is the bare address, no count octet (len % 4 == 0).
        assert_eq!(msg.elems[4].data, vec![192, 168, 5, 253]);
        // private 38 carries msgMask/swMask as two u32 (8 bytes) plus AC100's
        // non-zero reserved word.
        let (_, rsv38, tlvs38) = vsp::split_value(&msg.elems[5].data).unwrap();
        assert_eq!(rsv38, SPEC_MSG_RSV);
        assert_eq!(tlvs38, vec![(38u16, SPEC_MSG_MASKS.to_vec())]);
        assert_eq!(SPEC_MSG_MASKS, [0, 0, 0, 0x6e, 0, 0, 0, 0x6e]);
        // private 5 (AP base parameters) and 60 (AP offline behaviour) carry
        // AC100's own reserved words.
        let (_, rsv5, tlvs5) = vsp::split_value(&msg.elems[6].data).unwrap();
        assert_eq!(rsv5, AP_BASE_PARA_RSV);
        assert_eq!(tlvs5, vec![(5u16, AP_BASE_PARA_VALUE.to_vec())]);
        let (_, rsv60, tlvs60) = vsp::split_value(&msg.elems[7].data).unwrap();
        assert_eq!(rsv60, AP_OFFLINE_RSV);
        assert_eq!(tlvs60, vec![(60u16, AP_OFFLINE_VALUE.to_vec())]);
        // private 61 (AP_USER) follows, with its own reserved word.
        let (_, rsv61, tlvs61) = vsp::split_value(&msg.elems[8].data).unwrap();
        assert_eq!(rsv61, AP_USER_RSV);
        assert_eq!(tlvs61, vec![(61u16, vec![0x22; 4])]);
        // private 58 closes the message.
        let (_, rsv58, tlvs58) = vsp::split_value(&msg.elems[9].data).unwrap();
        assert_eq!(rsv58, AP_PRIV58_RSV);
        assert_eq!(tlvs58, vec![(58u16, AP_PRIV58_VALUE.to_vec())]);
    }

    #[test]
    fn wsrv_para_psk_layout() {
        let w = config::WlanConfig {
            radio_id: 2,
            wlan_id: 3,
            vlan_id: 7,
            client_count: 32,
            isolate: true,
            rekey_period: 3600,
            security: config::SecurityPolicy {
                akm: config::Akm::Psk,
                cipher: config::Cipher::Ccmp,
                psk: Some("abcdefgh".into()),
                pmf: config::Pmf::Disabled,
            },
            ..config::WlanConfig::default()
        };
        let v = wsrv_para(&w).unwrap();
        // 17-byte fixed part plus the 8-byte key.
        assert_eq!(v.len(), 17 + 8);
        assert_eq!(v[0], 2); // radio id
        assert_eq!(v[1], 3); // WLAN id
        assert_eq!(&v[2..4], &7u16.to_be_bytes()); // VLAN id
        assert_eq!(&v[4..6], &32u16.to_be_bytes()); // max users
        assert_eq!(v[6], 1); // network type (AC100)
        assert_eq!(v[7], 1); // isolation
        assert_eq!(v[8], wlan_sec::PSK); // security option
        assert_eq!(v[9], 2); // auth type (WPA2-PSK)
        assert_eq!(v[10], 2); // cipher (AES)
        assert_eq!(&v[11..15], &3600u32.to_be_bytes()); // rekey period
        assert_eq!(&v[15..17], &8u16.to_be_bytes()); // key length
        assert_eq!(&v[17..], b"abcdefgh");
    }

    #[test]
    fn wsrv_para_omitted_without_key() {
        let w = config::WlanConfig {
            security: config::SecurityPolicy::default(),
            ..config::WlanConfig::default()
        };
        assert_eq!(wsrv_para(&w), None);
    }

    #[test]
    fn wlan_config_update_request_matches_ac100_order() {
        let w = config::WlanConfig {
            radio_id: 1,
            wlan_id: 1,
            ssid: b"office".to_vec(),
            broadcast: false,
            security: config::SecurityPolicy {
                akm: config::Akm::Psk,
                cipher: config::Cipher::Ccmp,
                psk: Some("person0finterest".into()),
                pmf: config::Pmf::Disabled,
            },
            ..config::WlanConfig::default()
        };
        let msg = wlan_config_update_request(21, &w);
        assert_eq!(msg.hdr.msg_type, WLAN_CONFIG_UPDATE_REQ);
        let e = elems(&msg);
        assert_eq!(e.len(), 3);
        // AC100's own order: Add WLAN, then the private 9 security payload,
        // then the private 7 (Add MAC ACL) trailer. The WTP applies the WLAN on
        // the presence of the Add WLAN element, so the order is parity, not a
        // precondition.
        assert_eq!(e[0].0, MsgElemType::ADD_WLAN);
        let body = &e[0].1;
        assert_eq!(body[0], 1);
        assert_eq!(body[1], 1);
        assert_eq!(&body[2..4], &[0x80, 0x00]); // AC100 capability
        assert_eq!(&body[17..19], &[0x01, 0x01]); // AC100 enable/broadcast flags
        assert_eq!(body.len(), 19 + 6);
        assert_eq!(&body[19..], b"office");
        assert_eq!(e[1].0, MsgElemType::VENDOR_SPECIFIC_PAYLOAD);
        let (_, _, tlvs) = vsp::split_value(&e[1].1).unwrap();
        let para = wsrv_para(&w);
        assert_eq!(vsp::find(&tlvs, priv_id::WSRV_PARA), para.as_deref());
        assert_eq!(e[2].0, MsgElemType::ADD_MAC_ACL_ENTRY);
        assert_eq!(e[2].1, WLAN_CFG_MAC_ACL.to_vec());
    }

    #[test]
    fn radio_config_request_matches_ac100_wire() {
        for (radio, mac_op_last, priv8_second) in [(1u8, 0x0du8, 0x06u8), (2, 0x0f, 0x09)] {
            let msg = radio_config_request(2, radio, 0);
            assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
            let e = elems(&msg);
            assert_eq!(
                e.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
                vec![
                    MsgElemType::RADIO_ADMIN_STATE,
                    RADIO_CFG_CHAN,
                    RADIO_CFG_TX,
                    MsgElemType::MAC_OPERATION,
                    MsgElemType::STATION_EVENT_TYPE,
                    MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
                ]
            );
            // RADIO_ADMIN_STATE: radio id then admin state 1 (enabled).
            assert_eq!(e[0].1, vec![radio, 1]);
            assert_eq!(e[1].1.len(), 19);
            assert_eq!(e[2].1.len(), 16);
            assert_eq!(e[3].1, vec![radio, 0, 0, mac_op_last]);
            assert_eq!(e[4].1.len(), 16);
            // Private 8 payload inside the VSP, reserved word 0x0008.
            let (_, rsv, tlvs) = vsp::split_value(&e[5].1).unwrap();
            assert_eq!(rsv, 0x0008);
            let v = vsp::find(&tlvs, 8).unwrap();
            assert_eq!(v.len(), 20);
            assert_eq!(v[0], radio);
            assert_eq!(v[1], priv8_second);
        }
    }

    #[test]
    fn radio_admin_state_request_is_bare_state() {
        let msg = radio_admin_state_request(1, 1, 2);
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        let e = elems(&msg);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, MsgElemType::RADIO_ADMIN_STATE);
        assert_eq!(e[0].1, vec![1, 2]);
    }

    fn hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn radio_config_request_wire_matches_ac100_seq2() {
        let wire = crate::vendor::framing::CtrlFrame::Rfc.frame(&radio_config_request(2, 1, 0));
        // Byte-identical to AC100's Configuration Update Request seq 2: a
        // 16-byte RFC control header then these 111 element bytes.
        assert_eq!(wire.len(), 127);
        let want = hex(
            "001f0002 0101 \
             04040013 01000002000000000100000800320064001400 \
             04060010 0100092a0000092a0000000000000000 \
             04110004 0100000d \
             04160010 010108010000000000000064434e2000 \
             0025001e 1234567800080008001401060201006400010100000000000a0000000000",
        );
        assert_eq!(&wire[16..], &want[..]);
    }

    #[test]
    fn channel_field_defaults_to_acs_and_pins_only_manual() {
        // 0 keeps ACS on both bands; a non-zero channel number lands in byte 2
        // of the 0x0404 record.
        assert_eq!(channel_field(0), CHANNEL_ACS);
        assert_eq!(channel_field(11), 11);
        let e = elems(&radio_config_request(2, 1, channel_field(11)));
        assert_eq!(e[1].1[2], 11);
    }

    #[test]
    fn wlan_config_update_request_without_key_omits_wsrv() {
        let w = config::WlanConfig {
            ssid: b"guest".to_vec(),
            security: config::SecurityPolicy::default(),
            ..config::WlanConfig::default()
        };
        let msg = wlan_config_update_request(5, &w);
        let e = elems(&msg);
        // No private 9 without a key, but the Add WLAN and trailing private 7
        // elements are still present.
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].0, MsgElemType::ADD_WLAN);
        assert_eq!(e[1].0, MsgElemType::ADD_MAC_ACL_ENTRY);
    }

    #[test]
    fn wlan_config_del_request_is_del_wlan_only() {
        let msg = wlan_config_del_request(31, 2, 5);
        assert_eq!(msg.hdr.msg_type, WLAN_CONFIG_UPDATE_REQ);
        let e = elems(&msg);
        assert_eq!(e.len(), 1);
        // RFC 5416 6.4 value: radio id then WLAN id. The Delete WLAN element is
        // what routes the message to the WTP delete branch.
        assert_eq!(e[0].0, MsgElemType::DEL_WLAN);
        assert_eq!(e[0].1, vec![2, 5]);
    }

    #[test]
    fn config_status_response_omits_empty_ap_user() {
        let inp = ConfigStatusResp {
            seq: 1,
            timers: (20, 20),
            ac_ip: Ipv4Addr::new(192, 168, 5, 253),
            ap_user: &[],
        };
        let msg = config_status_response(&inp);
        let tags: Vec<u16> = msg.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                MsgElemType::CAPWAP_TIMERS,
                MsgElemType::DECRYPT_ERR_REPORT_PERIOD,
                MsgElemType::IDLE_TIMEOUT,
                MsgElemType::WTP_FALLBACK,
                MsgElemType::AC_IPV4_LIST,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 38
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 5
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 60
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD, // private 58
            ]
        );
    }

    #[test]
    fn station_report_parses_radio_count_and_macs() {
        // Live wire value with one station on radio 2: `02 00000001` then the
        // 6-byte MAC and its RSSI byte.
        let v = hex("0200000001 ee2281ceabaf cd");
        let rep = parse_station_report(&v).unwrap();
        assert_eq!(rep.radio_id, 2);
        assert_eq!(
            rep.stations,
            vec![StationRecord {
                mac: [0xee, 0x22, 0x81, 0xce, 0xab, 0xaf],
                rssi: -51,
            }]
        );
        // The no-station form is the bare 5-byte value.
        let empty = parse_station_report(&hex("0100000000")).unwrap();
        assert_eq!(empty.radio_id, 1);
        assert!(empty.stations.is_empty());
        // A count larger than the value carries is rejected, not half-read.
        assert_eq!(parse_station_report(&hex("0200000002ee2281ceabafcd")), None);
        assert_eq!(parse_station_report(&[]), None);
        assert_eq!(parse_station_report(&hex("01")), None);
    }

    #[test]
    fn wlan_list_parses_radio_ids_and_ssids() {
        // Live wire value from the WTP's Configuration Status Request: a two-word
        // header then two records of `[u8 radio_id][32B NUL-padded SSID]` holding
        // "miniac", one per radio.
        let mut v = hex("0000000100000002");
        for id in [1u8, 2] {
            v.push(id);
            let mut name = [0u8; 32];
            name[..6].copy_from_slice(b"miniac");
            v.extend_from_slice(&name);
        }
        assert_eq!(
            parse_wlan_list(&v).unwrap(),
            vec![
                SavedWlan {
                    radio_id: 1,
                    ssid: "miniac".into()
                },
                SavedWlan {
                    radio_id: 2,
                    ssid: "miniac".into()
                },
            ]
        );
        // A zero count is a valid empty list: a blank WTP holds no WLAN.
        assert_eq!(parse_wlan_list(&hex("0000000100000000")).unwrap(), vec![]);
        // A count larger than the records carried is rejected, not half-read.
        assert_eq!(parse_wlan_list(&hex("0000000100000002016d696e696163")), None);
        assert_eq!(parse_wlan_list(&hex("00000001")), None);
    }
}
