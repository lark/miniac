//! Ruijie RG-AP120-A (RGOS FIT AP) overlay.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! The RG-AP120-A is a pure FIT WTP: it speaks RFC 5415/5416 framing over a
//! plaintext CAPWAP control channel (the firmware is built with
//! `CONFIG_CAPWAP_HAVE_DTLS` unset) and needs no vendor-specific control
//! framing. Its private configuration is carried as bare top-level elements
//! (the `{u16 vsp_id, u16 len, value}` form) or inside the RFC Vendor Specific
//! Payload (element 37), and the WLAN push reuses the private
//! `0x0033DD01`/`0x0033DD02` message pair with the standard Add WLAN element
//! (1024).
//!
//! Only the forms needed to bring a WLAN up are implemented here. The private
//! RRM parameters (802.11k/r/v) are documented in
//! `.trae/records/20261110-171527-rg-ap120-a-80211krv支持与载荷分析.md`; the
//! LED, firmware-upgrade and radio/WLAN mappings in
//! `.trae/records/20261110-165347-rg-ap120-a-capwap固件逆向与元素分析.md`
//! §9-§13 and §18.
//!
//! Deliberately absent, because the firmware exposes no safe carrier:
//! client limit / client isolation (no CAPWAP element or VSP) and WEP/WAPI
//! (VSP 0x8d exists but its cipher table 4/5 is unproven and the model has no
//! WEP mode). Element 0x406 has a decodable layout but no matching model
//! field; element 0x408 only reports back the radio id.
//!
//! Channel width rides in the 28-byte 11n VSP (0x93), which also writes the
//! A-MPDU / short-GI / LDPC / STBC flags; see [`ht_11n_request`] for the
//! pre-filled defaults and their source.

use std::net::Ipv4Addr;

use crate::capwap::{CtrlMsg, MsgElemType, MsgType};
use crate::config::{self, Akm, AuthType, Cipher, Pmf, SecurityPolicy, WlanConfig};
use crate::elements::BaseElem;

/// Private control message: WLAN configuration update request (AC -> WTP).
pub const WLAN_CFG_UPDATE_REQ: u32 = 0x0033_dd01;
/// Private control message: WLAN configuration update response (WTP -> AC).
pub const WLAN_CFG_UPDATE_RESP: u32 = 0x0033_dd02;

/// Private top-level element ids that identify a Ruijie WTP. These are the
/// device-to-AC members of the RGOS VSP table; they sit outside every RFC 5415
/// element range, so a request carrying one is a Ruijie device.
pub const PRIVATE_TAGS: &[u16] = &[
    0x009d, 0x10ae, 0x10af, 0x10c4, 0x10c7, 0x10c8, 0x10c9, 0x10cc, 0x10cf, 0x10d0, 0x10d5,
    0x10dd, 0x13fa, 0x1802,
];

/// Detects a Ruijie WTP from its Discovery Request.
///
/// Two signals are used: a private top-level element id, or the RGOS/product
/// name in the WTP Descriptor (element 39), whose version strings are
/// `RGOS <version>` and `RG-AP120-A`.
pub fn looks_like_ruijie(req: &[u8]) -> bool {
    has_private_tag(req)
        || contains(req, b"RGOS")
        || contains(req, b"RG-AP")
        || contains(req, b"Ruijie")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Whether an RFC-framed request carries one of the Ruijie private top-level
/// element ids.
pub fn has_private_tag(req: &[u8]) -> bool {
    if req.len() < 16 {
        return false;
    }
    let mut off = 16;
    while off + 4 <= req.len() {
        let tag = u16::from_be_bytes([req[off], req[off + 1]]);
        let len = u16::from_be_bytes([req[off + 2], req[off + 3]]) as usize;
        if PRIVATE_TAGS.contains(&tag) {
            return true;
        }
        off += 4 + len;
    }
    false
}

/// Join Response. RGOS `capwap.cfg` marks CAPWAP Local IPv6 Address (50) as
/// mandatory in the Join Response; miniac is IPv4-only here, so the
/// unspecified address `::` is advertised to satisfy the schema.
pub fn join_response(seq: u32, ac_ip: Ipv4Addr, ac_name: &[u8], ok: bool) -> CtrlMsg {
    let mut msg = config::join_response(seq, ac_ip, ac_name, 0, ok);
    if ok {
        msg = msg.add_elem(MsgElemType::CAPWAP_LOCAL_IPV6_ADDR, &[0u8; 16]);
    }
    msg
}

/// Join Response announcing an image for this WTP.
///
/// Element 25 is `may` in the RGOS Join Response schema
/// (`etc/opt/capwap/capwap.cfg`), so an image queued for an offline WTP is
/// advertised here instead of waiting for the Run state.
pub fn join_response_with_image(
    seq: u32,
    ac_ip: Ipv4Addr,
    ac_name: &[u8],
    version: &str,
    name: &str,
) -> CtrlMsg {
    join_response(seq, ac_ip, ac_name, true)
        .add_elem(MsgElemType::IMAGE_ID, &image_identifier(version, name))
}

/// Configuration Status Response. RGOS requires CAPWAP Timers (12) and WTP
/// Fallback (40); fallback is disabled so the WTP stays under AC control.
pub fn config_status_response(seq: u32) -> CtrlMsg {
    config::config_status_response(
        seq,
        &[
            BaseElem::CapwapTimers {
                disc_interval_secs: 20,
                echo_interval_secs: 20,
            },
            BaseElem::WtpFallback(2),
        ],
    )
}

/// WLAN Configuration Update Request carrying one Add WLAN element (1024) and,
/// for a secured WLAN, the RSNA information element (1029).
pub fn wlan_config_update_request(seq: u32, wlan: &WlanConfig) -> CtrlMsg {
    let mut msg = CtrlMsg::new(WLAN_CFG_UPDATE_REQ, seq)
        .add_elem(MsgElemType::ADD_WLAN, &encode_add_wlan(wlan));
    if let Some(ie) = information_element(wlan) {
        msg = msg.add_elem(MsgElemType::INFORMATION_ELEMENT, &ie);
    }
    msg
}

/// Encode the Add WLAN (1024) body the way RGOS decodes it
/// (`apag_msg_elem_add_wlan_decode_continue`, apagd 0x41e704):
/// `radio | wlan | capability u16 | key index | key status | key len u16 |
/// key | group TSC[6] | QoS | auth | MAC mode | tunnel mode | suppress SSID |
/// SSID`.
///
/// Unlike the vendor-neutral [`WlanConfig::encode`], the WPA passphrase/PMK
/// travels in the standard `key`/`key length` fields. RGOS rejects the element
/// unless its value is 20..83 bytes (`apag_msg_elem_add_wlan_decode_continue`
/// checks `len < 0x14 || 0x53 < len`), and since the fixed part is 19 bytes the
/// key and SSID together may use at most 64. Both are capped at 32 bytes — the
/// RGOS key limit and the IEEE SSID limit — which keeps the value at or below
/// 83 bytes for any input.
pub fn encode_add_wlan(wlan: &WlanConfig) -> Vec<u8> {
    let key = if wlan.security.secured() {
        wlan.security.psk.as_deref().unwrap_or("").as_bytes()
    } else {
        &[]
    };
    let key = &key[..key.len().min(32)];
    let ssid = &wlan.ssid[..wlan.ssid.len().min(32)];
    let auth = match wlan.auth_type {
        AuthType::Rsn => 0u8,
        AuthType::Open => 1,
    };
    let mut v = Vec::with_capacity(19 + key.len() + ssid.len());
    v.push(wlan.radio_id);
    v.push(wlan.wlan_id);
    v.extend_from_slice(&wlan.capability.to_be_bytes());
    v.extend_from_slice(&[0, 0]); // key index / key status
    v.extend_from_slice(&(key.len() as u16).to_be_bytes());
    v.extend_from_slice(key);
    v.extend_from_slice(&[0u8; 6]); // group TSC
    v.push(wlan.qos);
    v.push(auth);
    v.push(wlan.mac_mode);
    v.push(wlan.tunnel_mode);
    v.push(u8::from(wlan.suppress_ssid));
    v.extend_from_slice(ssid);
    v
}

/// IEEE 802.11 Information Element (1029) body carrying the RSN IE.
///
/// RGOS decode `FUN_004b417c`: `radio | wlan | bp_bit | IE id | IE length |
/// IE body`; only IE id `0x30` (RSN) is interpreted here.
pub fn information_element(wlan: &WlanConfig) -> Option<Vec<u8>> {
    let body = rsn_ie(&wlan.security)?;
    let mut v = Vec::with_capacity(5 + body.len());
    v.push(wlan.radio_id);
    v.push(wlan.wlan_id);
    v.push(0); // bp_bit
    v.push(0x30); // RSN information element id
    v.push(body.len() as u8);
    v.extend_from_slice(&body);
    Some(v)
}

/// RSN IE body (IEEE 802.11-2020 9.4.2.24) for the policy's cipher/AKM/PMF.
fn rsn_ie(policy: &SecurityPolicy) -> Option<Vec<u8>> {
    if !policy.secured() {
        return None;
    }
    let mut v = Vec::with_capacity(22);
    v.extend_from_slice(&1u16.to_le_bytes()); // version
    let group = match policy.cipher {
        Cipher::Tkip => 2u8,
        Cipher::Ccmp | Cipher::TkipCcmp => 4,
    };
    v.extend_from_slice(&[0x00, 0x0f, 0xac, group]);
    let pairwise: &[u8] = match policy.cipher {
        Cipher::Tkip => &[2],
        Cipher::Ccmp => &[4],
        Cipher::TkipCcmp => &[2, 4],
    };
    v.push(pairwise.len() as u8);
    for cipher in pairwise {
        v.extend_from_slice(&[0x00, 0x0f, 0xac, *cipher]);
    }
    let akm: &[u8] = match policy.akm {
        Akm::Open => &[],
        Akm::Psk => &[2],
        Akm::PskSae => &[2, 8],
        Akm::Sae => &[8],
    };
    v.push(akm.len() as u8);
    for suite in akm {
        v.extend_from_slice(&[0x00, 0x0f, 0xac, *suite]);
    }
    let caps: u16 = match policy.pmf {
        Pmf::Disabled => 0,
        Pmf::Capable => 0x0080,
        Pmf::Required => 0x00c0,
    };
    v.extend_from_slice(&caps.to_le_bytes());
    Some(v)
}

/// Private LED-control VSP (AC -> WTP). Payload `[mode, state]`:
/// `mode` 0 selects the LED on/off switch, 1 the quiet mode; `state` 1 = on,
/// 0 = off. Decoded by wbs_mng `led_mng_decode` (0x4e50bc).
pub const LED_VSP: u16 = 0x13dc;

/// LED on/off Configuration Update for the RG-AP120-A.
pub fn led_update_request(seq: u32, on: bool) -> CtrlMsg {
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_elem(LED_VSP, &[0, u8::from(on)])
}

/// Private WLAN-to-VLAN VSP (AC -> WTP). Payload is three big-endian u32:
/// `{wlan_id, vid, mode}`.
///
/// Decoded by wbs_mng `FUN_00439b2c` (0x439b2c, registered 0x13b4 in
/// `FUN_004398f0`): `wlan_id` must be below 0x11, `vid` in `(0, 0xfff)`, and
/// `mode` 0 deletes the entry while non-zero installs or updates it. The
/// table is a per-WLAN list (one WLAN may carry several VIDs), so `mode = 1`
/// adds the mapping rather than replacing the WLAN's list.
pub const WLAN_VLAN_VSP: u16 = 0x13b4;

/// Install one WLAN VLAN mapping. Returns `None` when the values fall outside
/// the range RGOS accepts, so the caller can skip the message.
pub fn vlan_mapping_request(seq: u32, wlan_id: u8, vlan_id: u32) -> Option<CtrlMsg> {
    if wlan_id >= 0x11 || vlan_id == 0 || vlan_id >= 0xfff {
        return None;
    }
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&u32::from(wlan_id).to_be_bytes());
    v.extend_from_slice(&vlan_id.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes()); // mode = install/update
    Some(CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_elem(WLAN_VLAN_VSP, &v))
}

/// Private element (0xa6) reporting each radio's average client RSSI. Encoded
/// by wbs_mng `mac_radio_avg_rssi_ap_encode` (0x485100, registered 0xa6 in
/// `FUN_004823c8`) as `count, (radio_id, rssi i8) * count`; it is registered
/// AP -> AC, so it arrives in a WTP Event Request.
pub const AVG_RSSI_VSP: u16 = 0xa6;

/// Decode an average-RSSI value into `(radio_id, dBm)` pairs. A short or
/// empty value yields no pairs rather than a partial reading.
pub fn parse_avg_rssi(value: &[u8]) -> Vec<(u8, i8)> {
    let Some(&count) = value.first() else {
        return Vec::new();
    };
    let count = count as usize;
    if value.len() < 1 + count * 2 {
        return Vec::new();
    }
    value[1..]
        .chunks_exact(2)
        .take(count)
        .map(|pair| (pair[0], pair[1] as i8))
        .collect()
}

/// RGOS Image Identifier (25) body. RGOS reads the RFC vendor id at body[0..4]
/// and then sub-TLVs `[u16 type][u16 len][value]` (capwap_client
/// `FUN_0041ea40`): type 1 = software version, type 2 = image file name.
/// Each value is at most 0x40 bytes and the whole body below 0x80.
pub fn image_identifier(version: &str, name: &str) -> Vec<u8> {
    let mut v = 0u32.to_be_bytes().to_vec();
    push_sub_tlv(&mut v, 1, version.as_bytes(), 48);
    push_sub_tlv(&mut v, 2, name.as_bytes(), 64);
    v
}

fn push_sub_tlv(out: &mut Vec<u8>, kind: u16, value: &[u8], max: usize) {
    let value = &value[..value.len().min(max)];
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Extract the image file name (type 2) from an RGOS Image Identifier body.
pub fn image_identifier_name(body: &[u8]) -> Option<String> {
    if body.len() < 4 {
        return None;
    }
    let mut off = 4;
    while off + 4 <= body.len() {
        let kind = u16::from_be_bytes([body[off], body[off + 1]]);
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let start = off + 4;
        if start + len > body.len() {
            return None;
        }
        if kind == 2 {
            return Some(
                String::from_utf8_lossy(&body[start..start + len])
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
        off = start + len;
    }
    None
}

/// VSP element (0x1010) that tells the WTP all configuration has been sent and
/// the accumulated WLAN config should be applied. Carries no payload.
pub const CFG_DONE_VSP: u16 = 0x1010;

/// Radio Admin State (element 31) in a Configure Update Request (type 7).
/// `admin_state`: 1 = down, 2 = up.
///
/// Handler on the WTP: wbs_mng `mac_wtp_radio_state_decode` (element 0x1f),
/// which calls `lsm_if_set_admin_status(iface, enable)`.
pub fn radio_admin_state_request(seq: u32, radio_id: u8, admin_state: u8) -> CtrlMsg {
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_element(BaseElem::RadioAdminState {
        radio_id,
        admin_state,
    })
}

/// Configure Update Request (type 7) carrying the Ruijie radio configuration
/// for one radio:
///
/// - Element 0x404 (1028) DIRECT_SEQUENCE_CONTROL — channel
///   (`mac_dir_seq_ctrl_decode`, 12 bytes: `radio_id` at +4, `channel` at +6).
/// - Element 0x411 (1041) RADIO_TX_POWER — percent + dBm
///   (`pc_tx_power_decode`, 8 bytes: `radio_id` at +4, `percent` at +5,
///   `dbm` u16 at +6).
/// - Element 0x416 (1046) WTP_RADIO_CONFIGURATION — beacon/DTIM/preamble/country
///   (`mac_wtp_radio_cfg_decode`, 20 bytes: `radio_id` at +4, `short_preamble`
///   at +5, `dtim_period` at +7, `beacon_interval` u16 at +14, `country` at +16).
/// - Element 0x418 (1048) WTP_RADIO_INFO — `radio_type` bitmask
///   (`mac_wtp_radio_info_decode`, 9 bytes: `radio_id` at +4, `radio_type` u32
///   at +5): bit0 11b, bit1 11a, bit2 11g, bit3 11n. This element only carries
///   the legacy PHY mask; 11ac/11ax/11be are radio capabilities the AP enables
///   from its board data (RGOS 11.9 radio init 0x66158 sets properties
///   0x1a/0x4a/0x67 via `wbs_mac_radio_database_set_11ac/ax/be*`) and the AC
///   cannot toggle them over CAPWAP, so those modes map to the band's legacy
///   subset (see [`radio_type_bits`]).
///
/// `channel` is the IEEE channel number (0 = auto). `power_percent` is the
/// configured percentage (0–100), converted to dBm via the same table TP-Link
/// uses. Beacon interval defaults to 100 TU, DTIM to 1, short preamble off,
/// country "CN". `mode` is the normalized [`crate::vendor::mode`] selector.
pub fn radio_config_request(
    seq: u32,
    radio_id: u8,
    channel: u8,
    power_percent: u8,
    mode: u32,
) -> CtrlMsg {
    let power_dbm = crate::vendor::tplink::tx_power_dbm(radio_id, power_percent as u32);
    let radio_type = radio_type_bits(mode, radio_id);
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq)
        // Channel (value 8 bytes, total elem 12): radio_id at value+0,
        // channel at value+2. The WTP handler reads param_3+4 (radio_id)
        // and param_3+6 (channel) where param_3 is the 4-byte element header.
        .add_elem(
            MsgElemType::DIRECT_SEQUENCE_CONTROL,
            &[radio_id, 0x00, channel, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        // TX Power (value 4 bytes, total elem 8): radio_id at value+0,
        // percent at value+1, dbm u16 at value+2.
        .add_elem(
            MsgElemType::RADIO_TX_POWER,
            &[radio_id, power_percent, (power_dbm >> 8) as u8, power_dbm as u8],
        )
        // WTP Radio Config (value 16 bytes, total elem 20): radio_id at
        // value+0, short_preamble at value+1, dtim_period at value+3,
        // beacon_interval u16 at value+10, country at value+12.
        .add_elem(
            MsgElemType::WTP_RADIO_CONFIGURATION,
            &[
                radio_id, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, b'C',
                b'N', 0x00, 0x00,
            ],
        )
        // WTP Radio Information (value 5 bytes, total elem 9): radio_id at
        // value+0, radio_type u32 at value+1.
        .add_elem(
            MsgElemType::WTP_RADIO_INFO,
            &[
                radio_id,
                (radio_type >> 24) as u8,
                (radio_type >> 16) as u8,
                (radio_type >> 8) as u8,
                radio_type as u8,
            ],
        )
}

/// Map a normalized mode to the RGOS `radio_type` bitmask (0x418).
///
/// The element has no 11ac/11ax/11be bits: RGOS decodes it with
/// `wbs_acm_need_to_set_chanmode`, which rebuilds the mask from the 11b/11g/11n/
/// 11a enable properties (0x26/0x27/0x28/0x29) and applies only those four.
/// The same helper exists unchanged in RGOS 11.9 (wbs_mng 0x89040), and the
/// 11.9 encoder (0x98a44) only emits these bits too. 11ac/11ax/11be are enabled
/// at radio init from the board capability (properties 0x1a/0x4a/0x67) and stay
/// on; the mode selector therefore maps them to the band's n-capable subset:
/// 2.4 GHz `b|g|n`, 5 GHz `a|n`.
fn radio_type_bits(mode: u32, radio_id: u8) -> u32 {
    use crate::vendor::mode as m;
    // RGOS radio ids follow the bands: 1 = 2.4 GHz, 2 = 5 GHz.
    let is_24 = radio_id == 1;
    match mode {
        m::A => 0b0010,
        m::B => 0b0001,
        m::G => 0b0100,
        m::BG => 0b0101,
        m::N if is_24 => 0b1000,
        m::N => 0b1010, // 11n on 5 GHz implies 11a
        m::BGN => 0b1101,
        m::AN => 0b1010,
        // AUTO, 11ac, 11ax and 11be: the legacy subset only.
        _ if is_24 => 0b1101,
        _ => 0b1010,
    }
}

/// Private 11n-attribute VSP (AC -> WTP), decoded by wbs_mng
/// `mac_vsp_11n_info_skspruce_decode` (0x47c8a0) and printed by
/// `vsp_dot11_debug_hutong_info` (0x47be7c). The element must be exactly 0x20
/// bytes, i.e. a 28-byte value; bytes the decoder never reads are sent as 0.
pub const HT_11N_VSP: u16 = 0x93;

/// A-MSDU / A-MPDU / short GI / LDPC / STBC defaults for the 11n VSP.
///
/// The AP's own FAT configuration (`rg_cfg/30020122/wlan_bs/1.0.0/wlan_bs.ini`)
/// enables short GI (`short_gi=1`) and LDPC (`ebag_ldpc=1`) and runs A-MPDU
/// (`ebag_ampdu_retry=4`); A-MSDU is not exposed by the web UI and stays on.
/// The web `assocoptim` page exposes STBC as a separate toggle and the config
/// leaves it unset (`stbc_ant_confict=0`), so both directions stay off.
const HT_AMSDU: u8 = 1;
const HT_AMPDU: u8 = 1;
const HT_SHORT_GI: u8 = 1;
const HT_ENABLE: u8 = 1;
const HT_LDPC: u8 = 1;
const HT_STBC_RX: u8 = 0;
const HT_STBC_TX: u8 = 0;

/// 11n attribute update carrying the channel width.
///
/// RGOS only accepts two widths in this blob: value[5] 0 = 20 MHz and
/// 1 = 40 MHz (the decoder rejects anything else). Wider requests are clamped
/// to 40 MHz, the maximum of this 2x2 11n radio. `bandwidth_mhz == 0` means
/// auto; no message is sent so the WTP keeps its own default.
///
/// The decoder writes A-MPDU, short GI, LDPC and STBC from the same payload,
/// so filling them with the AP's factory values keeps the other attributes
/// unchanged. A-MSDU (value[1]) and HT enable (value[10]) are only compared,
/// never written.
pub fn ht_11n_request(seq: u32, radio_id: u8, bandwidth_mhz: u32) -> Option<CtrlMsg> {
    if bandwidth_mhz == 0 {
        return None; // auto: leave the WTP's own channel width alone
    }
    let mut value = [0u8; 28];
    value[0] = radio_id;
    value[1] = HT_AMSDU;
    value[2] = HT_AMPDU;
    value[4] = HT_SHORT_GI;
    value[5] = u8::from(bandwidth_mhz >= 40);
    value[10] = HT_ENABLE;
    value[11] = HT_LDPC;
    value[24] = HT_STBC_RX;
    value[25] = HT_STBC_TX;
    Some(CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_elem(HT_11N_VSP, &value))
}

/// Configure Update Request (type 7) whose sole element is the config-done
/// VSP (0x1010, empty payload). This signals the WTP to apply the accumulated
/// WLAN configuration pushed via `0x33DD01`.
pub fn config_done_request(seq: u32) -> CtrlMsg {
    CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq).add_elem(CFG_DONE_VSP, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC-framed Discovery Request: base header + control header at offset 8
    /// (type 1 at [8..12], sequence at [12], element length at [13..15]).
    fn discovery(elems: &[(u16, &[u8])]) -> Vec<u8> {
        let body: Vec<u8> = elems
            .iter()
            .flat_map(|(tag, value)| {
                let mut v = tag.to_be_bytes().to_vec();
                v.extend_from_slice(&(value.len() as u16).to_be_bytes());
                v.extend_from_slice(value);
                v
            })
            .collect();
        let mut pkt = vec![0u8; 16];
        pkt[8..12].copy_from_slice(&1u32.to_be_bytes());
        pkt[12] = 7;
        pkt[13..15].copy_from_slice(&((body.len() as u16) + 3).to_be_bytes());
        pkt.extend_from_slice(&body);
        pkt
    }

    #[test]
    fn detects_private_element_tag() {
        let req = discovery(&[(0x1802, &[1, 2, 3])]);
        assert!(looks_like_ruijie(&req));
    }

    #[test]
    fn detects_rgos_version_string() {
        let req = discovery(&[(39, b"\x00\x01\x00\x00\x00\x0bRGOS 11.1.1")]);
        assert!(looks_like_ruijie(&req));
    }

    #[test]
    fn plain_rfc_request_is_not_ruijie() {
        let req = discovery(&[(20, &[1]), (44, &[0])]);
        assert!(!looks_like_ruijie(&req));
    }

    #[test]
    fn join_response_carries_mandatory_set() {
        let msg = join_response(3, Ipv4Addr::new(192, 0, 2, 1), b"miniac", true);
        let tags: Vec<u16> = msg.elems.iter().map(|e| e.tag).collect();
        for must in [
            MsgElemType::AC_DESCRIPTOR,
            MsgElemType::AC_NAME,
            MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
            MsgElemType::CAPWAP_LOCAL_IPV6_ADDR,
            MsgElemType::RESULT_CODE,
            MsgElemType::ECN_SUPPORT,
        ] {
            assert!(tags.contains(&must), "missing element {must}");
        }
        let ipv6 = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::CAPWAP_LOCAL_IPV6_ADDR)
            .unwrap();
        assert_eq!(ipv6.data, vec![0u8; 16]);
    }

    #[test]
    fn config_status_response_carries_timers_and_fallback() {
        let msg = config_status_response(4);
        let tags: Vec<u16> = msg.elems.iter().map(|e| e.tag).collect();
        assert!(tags.contains(&MsgElemType::CAPWAP_TIMERS));
        assert!(tags.contains(&MsgElemType::WTP_FALLBACK));
        assert!(tags.contains(&MsgElemType::RESULT_CODE));
    }

    #[test]
    fn add_wlan_uses_rfc_layout() {
        let wlan = WlanConfig {
            radio_id: 1,
            wlan_id: 2,
            ssid: b"ruijie-test".to_vec(),
            ..WlanConfig::default()
        };
        let msg = wlan_config_update_request(9, &wlan);
        assert_eq!(msg.hdr.msg_type, WLAN_CFG_UPDATE_REQ);
        let elem = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::ADD_WLAN)
            .unwrap();
        assert_eq!(elem.data, wlan.encode());
        assert_eq!(elem.data[0], 1);
        assert_eq!(elem.data[1], 2);
        assert!(elem.data.ends_with(b"ruijie-test"));
    }

    #[test]
    fn add_wlan_carries_psk_and_rsn_ie() {
        let mut wlan = WlanConfig {
            radio_id: 1,
            wlan_id: 3,
            ssid: b"corp".to_vec(),
            ..WlanConfig::default()
        };
        wlan.security = SecurityPolicy {
            akm: Akm::Psk,
            cipher: Cipher::Ccmp,
            psk: Some("secret123".to_string()),
            pmf: Pmf::Capable,
        };
        let msg = wlan_config_update_request(10, &wlan);
        let add = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::ADD_WLAN)
            .expect("Add WLAN missing");
        assert_eq!(u16::from_be_bytes([add.data[6], add.data[7]]), 9);
        assert_eq!(&add.data[8..17], b"secret123");
        assert_eq!(add.data[23], 0); // QoS
        assert_eq!(add.data[24], 0); // auth = RSN
        assert_eq!(&add.data[28..], b"corp");

        let ie = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::INFORMATION_ELEMENT)
            .expect("RSN IE missing");
        assert_eq!(&ie.data[..4], &[1, 3, 0, 0x30]);
        assert_eq!(ie.data[4] as usize, ie.data.len() - 5);
        assert_eq!(&ie.data[5..7], &[1, 0]); // RSN version
        assert!(ie.data.windows(4).any(|w| w == [0x00, 0x0f, 0xac, 2])); // PSK AKM
        assert_eq!(&ie.data[ie.data.len() - 2..], &[0x80, 0x00]); // MFPC
    }

    #[test]
    fn add_wlan_stays_within_rgos_length_window() {
        let mut wlan = WlanConfig {
            ssid: vec![b'x'; 64],
            ..WlanConfig::default()
        };
        wlan.security = SecurityPolicy {
            akm: Akm::Psk,
            cipher: Cipher::Ccmp,
            psk: Some("p".repeat(64)),
            pmf: Pmf::Disabled,
        };
        let body = encode_add_wlan(&wlan);
        // RGOS accepts 20..=83 bytes only (apagd 0x41e704).
        assert_eq!(body.len(), 83);
        assert_eq!(&body[51..], &[b'x'; 32]);
    }

    #[test]
    fn open_wlan_has_no_rsn_ie() {
        let wlan = WlanConfig {
            wlan_id: 4,
            ssid: b"guest".to_vec(),
            ..WlanConfig::default()
        };
        let msg = wlan_config_update_request(11, &wlan);
        assert!(!msg
            .elems
            .iter()
            .any(|e| e.tag == MsgElemType::INFORMATION_ELEMENT));
    }

    #[test]
    fn led_request_is_vsp_0x13dc() {
        let on = led_update_request(12, true);
        let elem = on
            .elems
            .iter()
            .find(|e| e.tag == LED_VSP)
            .expect("LED VSP missing");
        assert_eq!(elem.data, vec![0, 1]);
        let off = led_update_request(13, false);
        assert_eq!(off.elems.iter().find(|e| e.tag == LED_VSP).unwrap().data, vec![0, 0]);
    }

    #[test]
    fn image_identifier_carries_version_and_name() {
        let body = image_identifier("AP_RGOS 11.1(9)B1P25", "fw.bin");
        assert!(body.len() < 0x80);
        assert_eq!(&body[4..6], &[0, 1]); // type 1 = software version
        assert_eq!(image_identifier_name(&body).as_deref(), Some("fw.bin"));
    }

    #[test]
    fn image_identifier_stays_within_rgos_limit() {
        let body = image_identifier(&"v".repeat(200), &"n".repeat(200));
        assert!(body.len() < 0x80);
        assert_eq!(image_identifier_name(&body).unwrap().len(), 64);
    }

    #[test]
    fn radio_admin_state_uses_element_31() {
        let msg = radio_admin_state_request(5, 1, 2);
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        let elem = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::RADIO_ADMIN_STATE)
            .expect("element 31 missing");
        assert_eq!(elem.data.len(), 2);
        assert_eq!(elem.data[0], 1); // radio_id
        assert_eq!(elem.data[1], 2); // admin_state = up
    }

    #[test]
    fn radio_mode_maps_to_legacy_radio_type_bits() {
        use crate::vendor::mode as m;
        // 2.4 GHz radio (id 1): b/g/n combinations.
        assert_eq!(radio_type_bits(m::B, 1), 0b0001);
        assert_eq!(radio_type_bits(m::G, 1), 0b0100);
        assert_eq!(radio_type_bits(m::BG, 1), 0b0101);
        assert_eq!(radio_type_bits(m::N, 1), 0b1000);
        assert_eq!(radio_type_bits(m::BGN, 1), 0b1101);
        // 5 GHz radio (id 2): a/n combinations; plain 11n implies 11a.
        assert_eq!(radio_type_bits(m::A, 2), 0b0010);
        assert_eq!(radio_type_bits(m::N, 2), 0b1010);
        assert_eq!(radio_type_bits(m::AN, 2), 0b1010);
        // 11ac/11ax/11be have no 0x418 bit and map to the band's n subset.
        assert_eq!(radio_type_bits(m::AC, 2), 0b1010);
        assert_eq!(radio_type_bits(m::ANAC, 2), 0b1010);
        assert_eq!(radio_type_bits(m::BGNAX, 1), 0b1101);
        assert_eq!(radio_type_bits(m::ANACAX, 2), 0b1010);
        assert_eq!(radio_type_bits(m::BGNAXBE, 1), 0b1101);
        assert_eq!(radio_type_bits(m::ANACAXBE, 2), 0b1010);
        // AUTO uses the band default.
        assert_eq!(radio_type_bits(m::AUTO, 1), 0b1101);
        assert_eq!(radio_type_bits(m::AUTO, 2), 0b1010);
    }

    #[test]
    fn radio_config_carries_channel_power_and_radio_cfg() {
        let msg = radio_config_request(6, 2, 36, 80, crate::vendor::mode::AN);
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);

        // Element 1028 (DIRECT_SEQUENCE_CONTROL): value 8 bytes.
        let chan = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::DIRECT_SEQUENCE_CONTROL)
            .expect("element 1028 missing");
        assert_eq!(chan.data.len(), 8);
        assert_eq!(chan.data[0], 2); // radio_id
        assert_eq!(chan.data[2], 36); // channel

        // Element 1041 (RADIO_TX_POWER): value 4 bytes.
        let txp = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::RADIO_TX_POWER)
            .expect("element 1041 missing");
        assert_eq!(txp.data.len(), 4);
        assert_eq!(txp.data[0], 2); // radio_id
        assert_eq!(txp.data[1], 80); // percent
        let dbm = u16::from_be_bytes([txp.data[2], txp.data[3]]);
        assert!(dbm > 0);

        // Element 1046 (WTP_RADIO_CONFIGURATION): value 16 bytes.
        let cfg = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::WTP_RADIO_CONFIGURATION)
            .expect("element 1046 missing");
        assert_eq!(cfg.data.len(), 16);
        assert_eq!(cfg.data[0], 2); // radio_id
        assert_eq!(cfg.data[1], 0); // short_preamble off
        assert_eq!(cfg.data[3], 1); // dtim_period
        let beacon = u16::from_be_bytes([cfg.data[10], cfg.data[11]]);
        assert_eq!(beacon, 100); // beacon interval 100 TU
        assert_eq!(&cfg.data[12..14], b"CN"); // country

        // Element 1048 (WTP_RADIO_INFO): value 5 bytes, radio_type at +1.
        let info = msg
            .elems
            .iter()
            .find(|e| e.tag == MsgElemType::WTP_RADIO_INFO)
            .expect("element 1048 missing");
        assert_eq!(info.data.len(), 5);
        assert_eq!(info.data[0], 2); // radio_id
        assert_eq!(
            u32::from_be_bytes([info.data[1], info.data[2], info.data[3], info.data[4]]),
            0b1010 // 11a + 11n
        );
    }

    #[test]
    fn ht_11n_request_carries_bandwidth_and_defaults() {
        // Auto (0) sends nothing so the WTP keeps its own width.
        assert!(ht_11n_request(1, 1, 0).is_none());

        for (mhz, field) in [(20u32, 0u8), (40, 1), (80, 1)] {
            let msg = ht_11n_request(2, 1, mhz).expect("11n request");
            let elem = msg
                .elems
                .iter()
                .find(|e| e.tag == HT_11N_VSP)
                .expect("0x93 missing");
            // RGOS requires a 28-byte value (0x20-byte element).
            assert_eq!(elem.data.len(), 28);
            assert_eq!(elem.data[0], 1); // radio id
            assert_eq!(elem.data[5], field); // channel width
            // Factory defaults the same blob writes.
            assert_eq!(elem.data[1], 1); // A-MSDU
            assert_eq!(elem.data[2], 1); // A-MPDU
            assert_eq!(elem.data[4], 1); // short GI
            assert_eq!(elem.data[10], 1); // HT enable
            assert_eq!(elem.data[11], 1); // LDPC
            assert_eq!(elem.data[24], 0); // STBC rx
            assert_eq!(elem.data[25], 0); // STBC tx
            // Bytes the decoder never reads stay zero.
            for i in [3usize, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 26, 27]
            {
                assert_eq!(elem.data[i], 0, "unused byte {i}");
            }
        }
    }

    #[test]
    fn vlan_mapping_is_vsp_0x13b4() {
        let msg = vlan_mapping_request(20, 3, 100).expect("mapping");
        let elem = msg
            .elems
            .iter()
            .find(|e| e.tag == WLAN_VLAN_VSP)
            .expect("VLAN VSP missing");
        assert_eq!(elem.data.len(), 12);
        assert_eq!(&elem.data[..4], &[0, 0, 0, 3]); // wlan id
        assert_eq!(&elem.data[4..8], &[0, 0, 0, 100]); // vid
        assert_eq!(&elem.data[8..], &[0, 0, 0, 1]); // mode = install
        // Out of the range RGOS accepts: nothing is sent.
        assert!(vlan_mapping_request(21, 3, 0).is_none());
        assert!(vlan_mapping_request(22, 3, 0xfff).is_none());
        assert!(vlan_mapping_request(23, 0x11, 100).is_none());
    }

    #[test]
    fn avg_rssi_report_decodes_radio_pairs() {
        let value = [2u8, 1, (-60i8) as u8, 2, (-55i8) as u8];
        assert_eq!(parse_avg_rssi(&value), vec![(1, -60), (2, -55)]);
        // Truncated and empty reports yield nothing rather than a partial read.
        assert!(parse_avg_rssi(&[2, 1, 0]).is_empty());
        assert!(parse_avg_rssi(&[]).is_empty());
    }

    #[test]
    fn config_done_is_empty_vsp_0x1010() {
        let msg = config_done_request(7);
        assert_eq!(msg.hdr.msg_type, MsgType::CONFIG_UPDATE_REQ);
        let elem = msg
            .elems
            .iter()
            .find(|e| e.tag == CFG_DONE_VSP)
            .expect("element 0x1010 missing");
        assert!(elem.data.is_empty());
    }
}
