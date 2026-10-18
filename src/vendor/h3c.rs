//! H3C message- and element-level CAPWAP handling (frame structure lives in
//! the sibling `framing` module).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Based on the observation of H3C mini AX60 behavior, should work with other
//! H3C devices.
//!
//! Covered here: the Discovery exchange (below), the Configuration Status
//! exchange (request decode + response build, including the H3C-private base
//! elements and the 0xfde8 WLAN config element encoding).
//!
//! AX60 sends an RFC-5415-shaped Discovery Request whose control message uses
//! a vendor-private prefix. The response must mirror that prefix exactly, or
//! the WTP keeps retrying (it never reaches DTLS / Join). Field layout, decoded
//! from a 150-byte live capture and confirmed against the WTP binary's
//! CWParseDiscoveryResponseMessage (WTP.dis 0x21cd4):
//!
//!   [0..8]   RFC 5415 CAPWAP header (HLEN=2: base header, no optionals)
//!   [8..12]  Message Type, 4 bytes, enterprise number 0 (low byte = type),
//!            2 = Discovery Response (the WTP rejects any other value)
//!   [12..16] 4-byte message sequence, big-endian, incremented each message
//!            (RFC uses a 1-byte Seq; AX60 widens it and yields before it)
//!   [16..18] MsgElementLength = bytes 16..end (self-inclusive, so elements + 3)
//!   [18]     Flags (0)
//!   [19..]   message elements, t2l2 framing (Type:2 BE, Len:2 BE) as RFC 5415
//!
//! The WTP element dispatcher parses tag 1 (AC Descriptor), tag 4 (AC Name)
//! and the H3C-private tag 0x418 (value must be exactly 5 bytes); tags 2 and
//! 20 are merely skipped. The AX60 collects AC addresses **only** from tag 10
//! (value = [4B IP][2B] per AC, WTP.dis 0x1df5c); without any tag 10 the DTLS
//! target stays all-zero and the WTP never sends a ClientHello. The real H3C
//! AC sends [1 Descriptor, 4 Name, 10 IPv4, 0x418], so miniac mirrors that set
//! (order is irrelevant to the WTP).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::info;

use crate::capwap::{CtrlMsg, CwElem, CwResult, MsgElemType, MsgType};
use crate::config;
use crate::elements::BaseElem;
use crate::radio::H3cRadioHeader;

/// Build a Discovery Response tailored to an H3C AX60-style WTP.
///
/// `req` is the raw inbound UDP payload; `ac_ip` is the AC control address the
/// WTP already contacted and must be told to join (the destination of the
/// request); `ac_name` is advertised in the AC Name element. Returns `None`
/// when `req` is not a recognized H3C-framed Discovery Request so the caller
/// can drop it without fabricating a broken reply.
pub fn discovery_response(req: &[u8], ac_ip: Ipv4Addr, ac_name: &[u8]) -> Option<Vec<u8>> {
    // Need enough prefix to mirror, a length that fits a u16, and a Discovery
    // Request type (low byte of the 4-byte Message Type at [8..12]).
    if req.len() <= 19 || req.len() - 16 > u16::MAX as usize {
        return None;
    }
    if req[8] != 0 || req[9] != 0 || req[10] != 0 || req[11] != 1 {
        return None;
    }

    let mut body = Vec::with_capacity(8 + ac_name.len());
    // Mirror the real AC element set: AC Descriptor(1), AC Name(4), AC IPv4
    // List(10) and the H3C-private tag 0x418. The WTP parses 1/4/0x418, collects
    // AC addresses from 10 (value = [4B IP][2B], WTP.dis 0x1df5c) and skips a
    // tag 2. No Discovery Type (20) is sent (the real AC does not include it).
    let ac_list = ac_ipv4_entry(ac_ip); // [4B IP][2B], family/class hint per the real AC
    push_elem(&mut body, 1, &ac_descriptor("1.0", "1.0")); // AC Descriptor
    push_elem(&mut body, 4, ac_name); // AC Name
    push_elem(&mut body, 10, &ac_list); // AC IPv4 List (tag 10, AX60 reads this)
    push_elem(&mut body, 0x418, &[0; 5]); // H3C private, must be exactly 5 bytes

    // 19-byte prefix: mirror the RFC header, swap Message Type to 2 (Discovery
    // Response), echo the request sequence, then a length placeholder, flags
    // and the element body.
    let mut resp = Vec::with_capacity(16 + body.len());
    resp.extend_from_slice(&req[..8]);
    resp.extend_from_slice(&[0, 0, 0, 2]); // Discovery Response (WTP rejects any other)
    resp.extend_from_slice(&req[12..16]); // echo sequence
    resp.extend_from_slice(&[0, 0]); // MsgElementLength placeholder (16..18)
    resp.push(0); // Flags (18)
    resp.extend_from_slice(&body);

    // MsgElementLength counts bytes 16..end (self-inclusive).
    let msg_len = (resp.len() - 16) as u16;
    resp[16..18].copy_from_slice(&msg_len.to_be_bytes());
    Some(resp)
}

/// Append one element in t2l2 framing: Type (2 BE), Length (2 BE), value.
fn push_elem(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Value of the AC IPv4 List element (tag 10): `[4B IP][2B]` per address, as
/// the AX60 Join/Discovery collectors (WTP.dis 0x1df5c) read exactly 4+2 bytes
/// per entry and reject any other length. `family` is a 2-byte hint (the real
/// AC sends 0x0002).
pub fn ac_ipv4_entry(ip: Ipv4Addr) -> Vec<u8> {
    let mut v = Vec::with_capacity(6);
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&[0, 2]);
    v
}

/// RFC 5415 4.6.1 AC Descriptor for Join/Discovery responses, vendor id 0.
///
/// The AX60 WTP branches on the Security byte at WTP.dis 0x223c4 (==1 passes
/// the real certificate paths to DTLS init, !=1 passes NULL and crashes); the
/// shared base bytes satisfy that.
pub fn ac_descriptor(hw: &str, sw: &str) -> Vec<u8> {
    config::ac_descriptor(hw, sw, 0)
}

/// Build the H3C AX60 Join Response (mtype 4).
///
/// On success the element set is [Result Code, AC Descriptor, AC Name, ECN
/// Support, Max Message Length, CAPWAP Control IPv4, CAPWAP Local IPv4]. The tag
/// 10 value must be the 6-byte `[4B IP][2B]` entry: the AX60 JoinResponse parser
/// (WTP.dis 0x23754) counts entries and re-parses each at 0x1df5c, and a 4-byte
/// value makes it malloc(0)/desync and reject. A refused join (unapproved WTP)
/// returns Result Code 1 with a loopback control address so the WTP keeps
/// retrying.
pub fn join_response(seq: u32, ac_ip: Ipv4Addr, ok: bool) -> CtrlMsg {
    if !ok {
        return CtrlMsg::new(MsgType::JOIN_RESP, seq)
            .with_result(CwResult::Failure)
            .add_elem(MsgElemType::AC_NAME, b"miniac")
            .add_elem(MsgElemType::CAPWAP_CTRL_IPV4_ADDR, &[127, 0, 0, 1])
            .add_elem(MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, &[127, 0, 0, 1]);
    }
    CtrlMsg::new(MsgType::JOIN_RESP, seq)
        .with_result_success()
        .add_elem(MsgElemType::AC_DESCRIPTOR, &ac_descriptor("1.0", "1.0"))
        .add_elem(MsgElemType::AC_NAME, b"miniac")
        .add_elem(MsgElemType::ECN_SUPPORT, &[1])
        .add_element(BaseElem::MaxMessageLen(2048))
        .add_elem(MsgElemType::CAPWAP_CTRL_IPV4_ADDR, &ac_ipv4_entry(ac_ip))
        .add_elem(MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, &ac_ip.octets())
}

/// H3C private WLAN configuration element (verified against the M60 AC
/// `/bin/AC` encoder `10045de4` and the AX60 WTP dispatcher `0xfde8 -> 26010`).
/// Element layout is `[Type:2 BE][Len:2 BE][body]`; a single element carries
/// SSID, enable, broadcast, encrypt and PSK (see `encode_h3c`).
pub const WLAN_CFG_H3C: u16 = 0xfde8;

/// AX60 channel-utilization report / acknowledgement. The WTP sends the
/// mtype-145 report (element 0xfe20 = [2G util%, 5G util%]) every 10s and
/// retransmits it with a fixed seq until the AC replies with mtype-146
/// carrying a zero Result Code (WTP.dis CWWTPManageGenericRunMessage 0x2c5a4
/// -> CWParseWTPChanUseRatioDyReponse 0x39c3c; pending dropped only when
/// element 33 == 0).
pub const WTP_CHAN_UTIL_REQ: u32 = 145;
pub const WTP_CHAN_UTIL_RESP: u32 = 146;

/// H3C-private element tag carried in Release Client by AC Request (mtype 139):
/// the MAC of the station the AC wants the WTP to evict. The AX60 parser
/// (`CWParseReleasedClientRequest` 0x3d68c -> `sub_52B6C`) reads one element and
/// rejects the request unless its value is exactly 6 bytes.
pub const ELEM_RELEASE_CLIENT_MAC: u16 = 65;

/// Build a Reset Request (mtype 17) that restarts the WTP on its current image.
///
/// RFC 5415 9.2; the AX60 parser `CWParseResetRequest` (WTP.dis 0x3ddb8) expects
/// exactly one Image Identifier element (tag 25) whose value is
/// `[vendor id u32 BE][image name][0x00]` — the parser forces the final byte to
/// NUL, so the name must carry its own terminator. vendor id 0 skips the image
/// check, and the name `all_version` selects the running firmware (any other
/// name that differs from the current image yields Result 10 and no restart).
pub fn reset_request(seq: u32) -> CtrlMsg {
    CtrlMsg::new(MsgType::RESET_REQ, seq)
        .add_elem(MsgElemType::IMAGE_ID, &image_id_all_version())
}

/// Value of the Image Identifier element for a plain restart: vendor id 0, the
/// name `all_version` and its trailing NUL (16 bytes).
pub fn image_id_all_version() -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(b"all_version");
    v.push(0);
    v
}

/// Build a Clear Configuration Request (mtype 23), restoring factory defaults.
/// The AX60 handler (`sub_3EE88` -> `CWWTPInitConfiguration`) parses no
/// structured elements, so the request is sent bare.
pub fn clear_config_request(seq: u32) -> CtrlMsg {
    CtrlMsg::new(MsgType::CLEAR_CONFIG_REQ, seq)
}

/// Build a Release Client by AC Request (mtype 139) evicting one station.
/// The single element (tag 65) carries the 6-byte client MAC verbatim.
pub fn release_client_request(seq: u32, mac: [u8; 6]) -> CtrlMsg {
    CtrlMsg::new(MsgType::RELEASE_CLIENT_REQ, seq).add_elem(ELEM_RELEASE_CLIENT_MAC, &mac)
}

/// Read the Result Code (tag 33) from a response message, accepting both the
/// RFC 5415 1-byte form and the H3C 4-byte widening. Returns `None` when the
/// element is absent or has an unexpected length.
pub fn result_code(msg: &CtrlMsg) -> Option<u32> {
    let e = msg.find_elems(MsgElemType::RESULT_CODE).next()?;
    match e.data.len() {
        4 => Some(u32::from_be_bytes([e.data[0], e.data[1], e.data[2], e.data[3]])),
        1 => Some(e.data[0] as u32),
        _ => None,
    }
}

/// H3C private element carrying the WTP MAC as a bare top-level tag.
///
/// H3C does not use the RFC Board Data base MAC sub-element (type 4); it sends
/// the MAC in this element instead, which is why the device identifier of an
/// H3C WTP has to be read from here rather than from the RFC WTP Board Data.
pub const ELEM_WTP_MAC: u16 = 54;

/// Board MAC of an H3C WTP from its private element 54 (raw 6-byte value).
/// `None` when the element is missing or shorter than a MAC, in which case the
/// caller falls back to the RFC Board Data (which H3C WTPs do not use).
pub fn wtp_mac(elems: &std::collections::HashMap<u16, Vec<CwElem>>) -> Option<[u8; 6]> {
    match elems.get(&ELEM_WTP_MAC).and_then(|v| v.first()) {
        Some(CwElem::Unknown(_, body)) if body.len() >= 6 => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&body[..6]);
            Some(mac)
        }
        _ => None,
    }
}

/// H3C 0xfde8 security selectors for a WLAN policy: the encrypt-type byte plus
/// the WPA cipher, both through the shared vendor mapping. An inexpressible
/// policy (pure WPA3) is snapped to the closest H3C mode (WPA2/WPA3 mixed).
fn h3c_security(w: &config::WlanConfig) -> crate::vendor::profile::SecurityFields {
    crate::vendor::profile::VendorProfile::H3c.security_fields(&w.security)
}

/// AX60 wire radio id (virtual interface): band derives as `radio_id - 1`
/// (0x3ff20), so physical radio 0 (2.4G) = id 1 and physical radio 1 (5G)
/// = id 2. The virtual-interface ids 33..64 only apply to the SSID pseudo
/// name (0x3ffbc normalization), NOT to this radio_id header field.
fn h3c_wire_radio_id(band5g: bool, _wlan_index: u32) -> u32 {
    if band5g { 2 } else { 1 }
}

/// Encode the H3C private WLAN element body (tag `WLAN_CFG_H3C`) for a
/// WTP's complete WLAN set. The AX60's authoritative decoder (`0x26010 ->
/// 0x52ee0`) walks the value sequentially (big-endian u32) and must consume
/// exactly the element length, in this order:
///
///   [7 x u32 BE]  2.4G radio header (enable, wlan id, power, mode, radio
///                 id, channel -> struct+0x00)
///   [records]     "SSID-" anchored WLAN records -> struct+0x28 slots
///   [7 x u32 BE]  5G radio header -> struct+0xa44
///   [records]     "5G-SSID-" anchored records -> struct+0xa6c slots
///
/// Both bands must ride in a single element: the 5G header doubles as the
/// element's trailing field and its enable word gates the 5G radio (an
/// all-zero tail was observed on the AX60 to explicitly power 5G off via
/// CFG_SetWifiEnable). Each record is `[33B anchor][u32 enable][33B SSID
/// name][4 x u32][u32 encrypt][if enc != 0] [65B PSK][u32 cipher][u32
/// wpa-period]`; a band with no WLAN yields an all-zero header (radio
/// disabled) and no records.
pub fn encode_h3c(
    wlans: &[config::WlanConfig],
    g24_hdr: &H3cRadioHeader,
    g5_hdr: &H3cRadioHeader,
) -> Vec<u8> {
    let g24: Vec<&config::WlanConfig> = wlans.iter().filter(|w| w.radio_id != 2).collect();
    let g5: Vec<&config::WlanConfig> = wlans.iter().filter(|w| w.radio_id == 2).collect();

    // Diagnostic encoding variants selected by MINIAC_H3C_EXP (absent by
    // default):
    //   skip5grec -> keep the 5G header (enable=1) but drop the "5G-SSID-"
    //     records (element shrinks to 28+163+28=219B).
    //   disable5g -> 5G header enable=0 but keep the records.
    //   5gslot1 -> move the 5G record to slot 1 (anchor "5G-SSID-2"); slot 0
    //     stays empty so the "SSID-33" lookup is skipped rather than
    //     hard-rejecting, and slot-1 records resolve through the j-loop.
    //   zero5g -> all-zero 5G header and no 5G records.
    let exp = std::env::var("MINIAC_H3C_EXP").unwrap_or_default();

    let mut v = Vec::new();
    emit_h3c_radio_header(
        &mut v,
        g24.first().copied(),
        g24_hdr,
        !g24.is_empty() && g24_hdr.enable,
    );
    for w in &g24 {
        emit_h3c_record(&mut v, w, b"SSID-", w.wlan_id as u32);
    }
    let g5_enable = exp != "disable5g" && !g5.is_empty() && g5_hdr.enable;
    emit_h3c_radio_header(&mut v, g5.first().copied(), g5_hdr, g5_enable);
    if exp == "zero5g" {
        // All-zero 5G header (matches the single-band tail) and no 5G
        // records.
        let n = v.len();
        v.truncate(n - 28);
        v.extend_from_slice(&[0u8; 28]);
    } else if exp != "skip5grec" {
        // 5G records keep the "5G-SSID-<n>" anchor: the AX60 decoder's Loop2
        // routes them to the band-1 slot region, while a plain "SSID-<n>"
        // anchor is consumed by Loop1 (2.4G) and collides with the 2.4G
        // records.
        for w in &g5 {
            let idx = if exp == "5gslot1" { 2 } else { w.wlan_id as u32 };
            emit_h3c_record(&mut v, w, b"5G-SSID-", idx);
        }
    }
    v
}

/// Emit one per-radio single-band element. Each element carries one band's
/// 7x u32 header plus its anchored records, ending with a 28-byte zero
/// section the decoder reads as the other band's radio header; an all-zero
/// tail leaves that band's radio disabled.
pub fn encode_h3c_per_radio(radio: &config::WlanConfig, band5g: bool) -> Vec<u8> {
    let mut v = Vec::new();
    // 5G keeps the AX60 band header defaults: radio id 2, channel AUTO (0);
    // 2.4G uses id 1, channel AUTO (0).
    let hdr = H3cRadioHeader {
        radio_id: h3c_wire_radio_id(band5g, radio.wlan_id as u32) as u8,
        enable: true,
        power: 6,
        mode: 0,
        channel: 0,
    };
    emit_h3c_radio_header(&mut v, Some(radio), &hdr, true);
    emit_h3c_record(
        &mut v,
        radio,
        if band5g { b"5G-SSID-" } else { b"SSID-" },
        radio.wlan_id as u32,
    );
    v.extend_from_slice(&[0u8; 28]);
    v
}

/// Encode the M60-style 0xfde8 body: one record per band. Per band a 7x u32
/// header ([enable, 0, 0, mode, radio id, 0, 100], mode 11 = 2.4G / 8 = 5G)
/// then "SSID-" / "5G-SSID-" anchored records, followed by a 74B tail
/// ([33B "SSID-1"][u32 1][33B "5G-SSID-1"][u32 1]).
pub fn encode_h3c_m60(wlans: &[config::WlanConfig]) -> Vec<u8> {
    let g24: Vec<&config::WlanConfig> = wlans.iter().filter(|w| w.radio_id != 2).collect();
    let g5: Vec<&config::WlanConfig> = wlans.iter().filter(|w| w.radio_id == 2).collect();
    let mut v = Vec::new();
    emit_h3c_m60_band(&mut v, &g24, b"SSID-", 11, 1);
    // M60's captured 5G header keeps radio id 1 too (word4 = 1, unlike the
    // AX60-layout convention of id 2 for 5G); replicate the capture verbatim.
    emit_h3c_m60_band(&mut v, &g5, b"5G-SSID-", 8, 1);
    // M60 tail: both anchor labels plus a trailing flag word each.
    for anchor in [b"SSID-1".as_slice(), b"5G-SSID-1".as_slice()] {
        let mut a = [0u8; 33];
        a[..anchor.len()].copy_from_slice(anchor);
        v.extend_from_slice(&a);
        v.extend_from_slice(&1u32.to_be_bytes());
    }
    v
}

/// Append one M60 band: a 7x u32 header and its anchored records. An empty
/// band keeps the header with enable=0 and no records.
fn emit_h3c_m60_band(
    v: &mut Vec<u8>,
    wlans: &[&config::WlanConfig],
    prefix: &[u8],
    mode: u32,
    radio_id: u32,
) {
    for word in [u32::from(!wlans.is_empty()), 0, 0, mode, radio_id, 0, 100] {
        v.extend_from_slice(&word.to_be_bytes());
    }
    for (i, w) in wlans.iter().enumerate() {
        emit_h3c_m60_record(v, w, prefix, i as u32 + 1);
    }
}

/// Append one M60 WLAN record: [33B anchor][u32 enable][33B SSID name][u32
/// isolate=0][u32 broadcast=1][u32 client=0xffffffff][u32 vlan][u32 encrypt]
/// and, when encrypted, [65B PSK][u32 cipher=2][u32 rekey=3600]. Only
/// SSID/PSK/enable come from the miniac DB.
fn emit_h3c_m60_record(v: &mut Vec<u8>, w: &config::WlanConfig, prefix: &[u8], idx: u32) {
    let mut anchor = [0u8; 33];
    anchor[..prefix.len()].copy_from_slice(prefix);
    {
        let label = idx.to_string();
        let n = label.len().min(33 - prefix.len());
        anchor[prefix.len()..prefix.len() + n].copy_from_slice(&label.as_bytes()[..n]);
    }
    let mut name = [0u8; 33];
    let n = w.ssid.len().min(32);
    name[..n].copy_from_slice(&w.ssid[..n]);
    let psk = w.security.psk.as_deref().unwrap_or("");
    let mut pskbuf = [0u8; 65];
    let n = psk.len().min(64);
    pskbuf[..n].copy_from_slice(psk.as_bytes()[..n].into());
    let fields = h3c_security(w);
    let enc = fields.encrypt;

    v.extend_from_slice(&anchor);
    v.extend_from_slice(&u32::from(w.wlan_enable).to_be_bytes());
    v.extend_from_slice(&name);
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
    v.extend_from_slice(&w.vlan_id.to_be_bytes());
    v.extend_from_slice(&enc.to_be_bytes());
    if enc != 0 {
        v.extend_from_slice(&pskbuf);
        v.extend_from_slice(&fields.cipher.to_be_bytes());
        v.extend_from_slice(&3600u32.to_be_bytes());
    }
}

/// Append one band's 7 x u32 radio header. The AX60 apply chain (0x26f14)
/// reads word 0 as the radio-enable flag (CFG_SetWifiEnable), word 3 as the
/// mode selector, word 4 as the radio id (band = radio_id - 1 via 0x3ff20),
/// word 5 as the IEEE channel number (0 = auto) and word 2 as power.
fn emit_h3c_radio_header(
    v: &mut Vec<u8>,
    lead: Option<&config::WlanConfig>,
    hdr: &H3cRadioHeader,
    enable: bool,
) {
    let wlan_id = lead.map_or(1, |w| w.wlan_id as u32);
    for word in [
        u32::from(enable),        // radio enable
        wlan_id,                  // opaque header word
        hdr.power,                // radio power
        hdr.mode,                 // mode selector
        u32::from(hdr.radio_id),  // radio id -> band (0x3ff20)
        hdr.channel,              // IEEE channel number (0 = auto)
        0u32,
    ] {
        v.extend_from_slice(&word.to_be_bytes());
    }
}

/// Append one WLAN record anchored by `prefix` + the decimal index `idx`
/// (e.g. "SSID-1" / "5G-SSID-2"), mirroring the decoder's field order:
/// enable, SSID name, isolate/broadcast/client/vlan, encrypt and PSK.
fn emit_h3c_record(v: &mut Vec<u8>, w: &config::WlanConfig, prefix: &[u8], idx: u32) {
    // The interface label after the anchor prefix; append the decimal
    // index, matching the "SSID-<n>" / "5G-SSID-<n>" interface naming.
    let mut anchor = [0u8; 33];
    anchor[..prefix.len()].copy_from_slice(prefix);
    {
        let label = idx.to_string();
        let n = label.len().min(33 - prefix.len());
        anchor[prefix.len()..prefix.len() + n].copy_from_slice(&label.as_bytes()[..n]);
    }
    // Broadcast SSID name (apply chain `CFG_SetWifiSsidName` reads +0x49).
    let mut name = [0u8; 33];
    {
        let n = w.ssid.len().min(32);
        name[..n].copy_from_slice(&w.ssid[..n]);
    }
    let psk = w.security.psk.as_deref().unwrap_or("");
    let mut pskbuf = [0u8; 65];
    {
        let n = psk.len().min(64);
        pskbuf[..n].copy_from_slice(psk.as_bytes()[..n].into());
    }
    let fields = h3c_security(w);
    let enc = fields.encrypt;

    v.extend_from_slice(&anchor);
    // Record slot enable: CFG_SetWifiSsidEnable, 1 = interface up.
    v.extend_from_slice(&u32::from(w.wlan_enable).to_be_bytes());
    v.extend_from_slice(&name);
    // isolate, broadcast (1 = SSID visible, the 2.4G baseline fix), client
    // count limit, vlan id — all DB-backed record fields.
    v.extend_from_slice(&u32::from(w.isolate).to_be_bytes());
    v.extend_from_slice(&u32::from(w.broadcast).to_be_bytes());
    v.extend_from_slice(&w.client_count.to_be_bytes());
    v.extend_from_slice(&w.vlan_id.to_be_bytes());
    v.extend_from_slice(&enc.to_be_bytes());
    if enc != 0 {
        v.extend_from_slice(&pskbuf);
        // WPA cipher: 1 TKIP / 2 AES / 3 TKIP+AES.
        v.extend_from_slice(&fields.cipher.to_be_bytes());
        // WPA rekey period.
        v.extend_from_slice(&w.rekey_period.to_be_bytes());
    }
}

/// Decoded view of an H3C-framed Configuration Status Request (mtype 5): the
/// WTP-reported name, per-radio operational states and the radios it declared
/// via Radio Administrative State elements.
pub struct ConfigStatusReq {
    pub wtp_name: Option<String>,       // WTP_NAME(45), trailing '\0' trimmed
    pub radio_op_states: Vec<(u8, u8)>, // RADIO_OP_STATE(32): (radio_id, state)
    pub declared_radios: Vec<(u8, u8)>, // RADIO_ADMIN_STATE(31): (radio_id, admin_state)
}

impl ConfigStatusReq {
    /// Decode a Configuration Status Request from its control message. Element
    /// values are read straight off the raw element stream (no typed CwElem
    /// map), so this also works for vendor-lenient H3C schemas.
    pub fn parse(msg: &CtrlMsg) -> Self {
        let wtp_name = msg
            .find_elems(MsgElemType::WTP_NAME)
            .next()
            .map(|e| {
                String::from_utf8_lossy(&e.data)
                    .trim_matches('\0')
                    .to_string()
            })
            .filter(|s| !s.is_empty());
        let radio_op_states = msg
            .find_elems(MsgElemType::RADIO_OP_STATE)
            .filter_map(|e| {
                if e.data.len() >= 2 {
                    Some((e.data[0], e.data[1]))
                } else {
                    None
                }
            })
            .collect();
        let declared_radios = msg
            .find_elems(MsgElemType::RADIO_ADMIN_STATE)
            .filter_map(|e| {
                if e.data.len() >= 2 {
                    Some((e.data[0], e.data[1]))
                } else {
                    None
                }
            })
            .collect();
        ConfigStatusReq {
            wtp_name,
            radio_op_states,
            declared_radios,
        }
    }
}

/// Inputs for `config_status_response`: the message sequence to echo, the AC
/// addresses to advertise and the per-radio/WLAN config to push.
pub struct ConfigStatusResp<'a> {
    pub seq: u32,
    pub ac_ip: Ipv4Addr,
    pub peer: SocketAddr,
    pub declared_radios: &'a [(u8, u8)],
    pub wlans: &'a [config::WlanConfig],
    pub g24_hdr: &'a H3cRadioHeader,
    pub g5_hdr: &'a H3cRadioHeader,
    pub wtp_mac: Option<[u8; 6]>,
    /// OFDMA / MU-MIMO enable words for the fe28 element. Mirrors the M60 AC:
    /// the element is only emitted when either word is non-zero.
    pub fe28: Option<(u32, u32)>,
    /// Band navigation (LBD) enable word for the fe31 element; only emitted
    /// when non-zero.
    pub fe31: Option<u32>,
}

/// M60 0xfe0b private element value (96B): three 32B slots
/// [type][new password][login prompt] (CWAssembleMsgElemIdleSetAPPwd): type
/// "1" = AP password follows the AC's login password, "2" = manual. Built as
/// type "1" with the default "123456" in both the password and prompt slots.
const M60_FE0B: [u8; 96] = [
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Build the H3C Configuration Status Response (mtype 6). Assembles the element
/// stream in the M60 AC's order ([2][3][12][32][16][23][40][55] then one 0xfde8
/// per radio/WLAN; H3C base elements are small-ID tags with vendor payloads,
/// appended verbatim).
pub fn config_status_response(inp: &ConfigStatusResp<'_>) -> CtrlMsg {
    let mut resp_msg = CtrlMsg::new(MsgType::CONFIG_STATUS_RESP, inp.seq)
        .add_element(BaseElem::CapwapTimers {
            disc_interval_secs: 20,
            echo_interval_secs: 60,
        })
        .add_element(BaseElem::IdleTimeout(300))
        .add_element(BaseElem::WtpFallback(2));
    // M60 template base elements (H3C private payloads):
    //   type2  = AC/management IPv4 list, 2 x u32 BE
    //   type3  = IPv6 list, 2 x 16B
    //   type12 = 2 control bytes ([0x14, 0x0a] normally)
    //   type32 = radio list, 3B per record
    //   type16 = radio params, 3B per record
    //   type23 = one u32 BE ([0, 0, 0, 0x0a] normally)
    //   type40 = constant 0x00
    //   type55 = interface MAC (6B)
    let exp = std::env::var("MINIAC_H3C_EXP").unwrap_or_default();
    if exp == "m60" {
        // Full M60 Configuration Status Response layout (718B). Element order
        // [2][3][12][32][16][23][fe0b][fe0c][fe1a][fe1b][fe0d][40] then one
        // M60-layout 0xfde8; no RFC base elements, no tag31, no type55; the
        // type32 radio list uses state byte 2 (M60 parity).
        let mut m = CtrlMsg::new(MsgType::CONFIG_STATUS_RESP, inp.seq);
        let mut ac_ip4 = [0u8; 8];
        ac_ip4[..4].copy_from_slice(&inp.ac_ip.octets());
        if let IpAddr::V4(v4) = inp.peer.ip() {
            ac_ip4[4..].copy_from_slice(&v4.octets());
        }
        m = m.add_elem(0x0002, &ac_ip4);
        m = m.add_elem(0x0003, &[0u8; 32]);
        m = m.add_elem(0x000c, &[0x14, 0x0a]);
        for (radio_id, _state) in inp.declared_radios.iter() {
            m = m.add_elem(0x0020, &[*radio_id, 2, 0]);
        }
        for (radio_id, _state) in inp.declared_radios.iter() {
            m = m.add_elem(0x0010, &[*radio_id, 0x00, 0x0f]);
        }
        m = m.add_elem(0x0017, &[0x00, 0x00, 0x00, 0x0a]);
        m = m.add_elem(0xfe0b, &M60_FE0B);
        m = m.add_elem(
            0xfe0c,
            &[
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xb5, 0x00, 0x00,
                0x00, 0x00, 0xff, 0xff, 0xff, 0xb0,
            ],
        );
        m = m.add_elem(0xfe1a, &[0x00, 0x00, 0x04, 0xb0]);
        m = m.add_elem(0xfe1b, &[0u8; 4]);
        m = m.add_elem(0xfe0d, &[0u8; 4]);
        // Advanced radio features: the M60 AC omits fe28 (OFDMA/MU-MIMO) and
        // fe31 (band navigation) entirely when their values are all zero, so
        // mirror that and only emit them when enabled. The fe28 value is 12B
        // (word0 spare, then OFDMA at word1 / MU-MIMO at word2 per the AX60
        // apply chain +0x1688 / +0x168c).
        if let Some((ofdma, mumimo)) = inp.fe28 {
            if ofdma != 0 || mumimo != 0 {
                let mut fe28 = [0u8; 12];
                fe28[4..8].copy_from_slice(&ofdma.to_be_bytes());
                fe28[8..12].copy_from_slice(&mumimo.to_be_bytes());
                m = m.add_elem(0xfe28, &fe28);
            }
        }
        if let Some(lbd) = inp.fe31 {
            if lbd != 0 {
                m = m.add_elem(0xfe31, &lbd.to_be_bytes());
            }
        }
        m = m.add_elem(0x0028, &[0u8; 1]);
        if !inp.wlans.is_empty() {
            let body = encode_h3c_m60(inp.wlans);
            m = m.add_elem(WLAN_CFG_H3C, &body);
        }
        return m;
    }
    let e2 = exp == "e2" || exp == "e5b";
    // e3/e4/f1/f2/f5/f6 drop the 8 base elements and tag31, keeping timers/
    // idle/fallback + the per-radio 0xfde8 layout; e4/f1/f2/f5/f6 re-add the
    // per-radio RADIO_ADMIN_STATE (tag31) echo.
    let e3 = exp == "e3"
        || exp == "e4"
        || exp == "f1"
        || exp == "f2"
        || exp == "f5"
        || exp == "f6";
    let mut ac_ip4 = [0u8; 8];
    if e2 {
        ac_ip4[..4].copy_from_slice(&[192, 168, 0, 2]);
    } else {
        ac_ip4[..4].copy_from_slice(&inp.ac_ip.octets());
    }
    if let IpAddr::V4(v4) = inp.peer.ip() {
        ac_ip4[4..].copy_from_slice(&v4.octets());
    }
    // e5a/e5b/e5c add back one group of the 8 base elements on top of the e3
    // layout:
    //   e5a -> type3 (IPv6 list), type32 (radio list), type16 (radio params)
    //   e5a1 -> type3 only; e5a2 -> type32 + type16
    //   e5a3 -> type32 only; e5a4 -> type16 only
    //   e5b -> type2 (AC IPv4 list), type12 (2 control bytes), type23 (1 u32)
    //   e5c -> type40 (0x00), type55 (interface MAC)
    let e5a = exp == "e5a";
    let e5a1 = exp == "e5a1" || e5a;
    let e5a2 = exp == "e5a2" || e5a;
    let e5a3 = exp == "e5a3" || e5a2;
    let e5a4 = exp == "e5a4" || e5a2;
    let e5b = exp == "e5b";
    let e5c = exp == "e5c";
    if !e3 || e5b {
        resp_msg = resp_msg.add_elem(0x0002, &ac_ip4);
        resp_msg = resp_msg.add_elem(
            0x000c,
            if e2 { &[0x00, 0x00] } else { &[0x14, 0x0a] },
        );
        resp_msg = resp_msg.add_elem(
            0x0017,
            if e2 { &[0x00, 0x00, 0x00, 0x00] } else { &[0x00, 0x00, 0x00, 0x0a] },
        );
    }
    if !e3 || e5a1 {
        // IPv6 list: two zero entries (M60 fills from rodata; an empty template
        // is fine for AX60).
        resp_msg = resp_msg.add_elem(0x0003, &[0u8; 32]);
    }
    if !e3 || e5a3 {
        // Radio list records: one per declared radio (field0 = radio id; params
        // default to 0).
        for (radio_id, _state) in inp.declared_radios.iter() {
            resp_msg = resp_msg.add_elem(0x0020, &[*radio_id, 0, 0]);
        }
    }
    if exp == "f6" {
        // f6: single type32 (radio list) element declaring both physical
        // radios (id 1,2), keeping the f2 dual-band 0xfde8 layout.
        info!("[>] f6: type32 radio list both bands");
        resp_msg = resp_msg.add_elem(0x0020, &[1, 0, 0]);
        resp_msg = resp_msg.add_elem(0x0020, &[2, 0, 0]);
    }
    if !e3 || e5a4 {
        // Radio params records: one per declared radio.
        for (radio_id, _state) in inp.declared_radios.iter() {
            resp_msg = resp_msg.add_elem(0x0010, &[*radio_id, 0x00, 0x0f]);
        }
    }
    if !e3 || e5c {
        // Constant 0x00 element.
        resp_msg = resp_msg.add_elem(0x0028, &[0u8; 1]);
        // Interface MAC (the WTP's own MAC when known).
        if let Some(mac) = inp.wtp_mac {
            resp_msg = resp_msg.add_elem(0x0037, &mac);
        }
    }
    // Each radio must be enabled: M60 encodes radio state in the 0xfde8 payload
    // (enable field) and this response's radio records; an explicit RFC
    // RADIO_ADMIN_STATE is echoed too so the AX60 apply chain can find a target
    // interface for the pushed WLANs.
    if !e3
        || exp == "e4"
        || exp == "f1"
        || exp == "f2"
        || exp == "f5"
        || exp == "f6"
    {
        for (radio_id, _reported_state) in inp.declared_radios.iter() {
            info!("[>] radio {} admin enabled", radio_id);
            resp_msg = resp_msg.add_elem(MsgElemType::RADIO_ADMIN_STATE, &[*radio_id, 0]);
        }
    }
    // Push one 0xfde8 element covering every WLAN (2.4G + 5G sections; see
    // `encode_h3c`). The AX60 applies WLAN/SSID only from this Configure-stage
    // response, and its decoder 0x52ee0 consumes one dual-band element with the
    // 5G radio header as the element's trailing field.
    if !inp.wlans.is_empty() {
        // e1/e2/e3/e4/e5*: push one 0xfde8 per radio (single-band elements)
        // instead of a single dual-band element. e2 also restores the old
        // type2/12/23 values; e3/e4/e5* drop the 8 base elements and tag31.
        if exp == "f5" {
            // f5: push only the 5G band config (single per-radio element),
            // omitting the 2.4G element.
            if let Some(w) = inp.wlans.iter().find(|w| w.radio_id == 2) {
                let body = encode_h3c_per_radio(w, true);
                resp_msg = resp_msg.add_elem(WLAN_CFG_H3C, &body);
            }
        } else if exp == "e1"
            || exp == "e2"
            || exp == "e3"
            || exp == "e4"
            || exp == "e5a"
            || exp == "e5a1"
            || exp == "e5a2"
            || exp == "e5a3"
            || exp == "e5a4"
            || exp == "e5b"
            || exp == "e5c"
        {
            for w in inp.wlans {
                let body = encode_h3c_per_radio(w, w.radio_id == 2);
                resp_msg = resp_msg.add_elem(WLAN_CFG_H3C, &body);
            }
        } else {
            // Band headers ride in from the radios store (DB-backed H3C config;
            // defaults when absent).
            let body = encode_h3c(inp.wlans, inp.g24_hdr, inp.g5_hdr);
            resp_msg = resp_msg.add_elem(WLAN_CFG_H3C, &body);
        }
    }
    resp_msg
}

// ---------------------------------------------------------------------------
// Configuration Update Request / Response (mtype 7 / 8)
// ---------------------------------------------------------------------------

/// H3C-private element tags carried in a Configuration Update Request that the
/// AX60 request parser recognizes (`CWParseConfigurationUpdateRequest`, WTP.dis
/// 0x317e4). Encoders mirror the M60 AC `CWAssembleConfigurationUpdateRequest`
/// (AC.dis 0x1002e218).
///
/// Note 0xfde8 (the Configuration Status Response WLAN element) is deliberately
/// absent: the AX60 request parser does not handle it and skips it as an
/// "Unrecognized Message Element". The runtime WLAN push instead uses 0xfdf1.
pub const CFG_KEEPALIVE: u16 = 0xfdf0;
pub const CFG_WLAN_BATCH: u16 = 0xfdf1;
pub const CFG_AP_NAME: u16 = 0xfdf2;
pub const CFG_LED: u16 = 0xfdf4;
pub const CFG_TELNET: u16 = 0xfdf5;
pub const CFG_ROAMING: u16 = 0xfdf7;
pub const CFG_CHANNEL: u16 = 0xfdf9;
pub const CFG_POWER: u16 = 0xfdfa;
/// Standard AC-address-change tag; the H3C private twin is 0xfe06.
pub const CFG_AC_ADDR_CHANGE: u16 = 0x003e;
/// Standard Image Identifier tag (RFC 5415 4.6.25).
pub const CFG_IMAGE_IDENTIFIER: u16 = 0x0019;

/// One element of an H3C Configuration Update Request (AC -> WTP, mtype 7).
/// Each variant carries its own wire encoding, matched to the M60 AC encoder.
/// `ImageIdentifier` / `WlanBatch` are modelled for completeness but not yet
/// wired to a caller (image signalling rides the Image Data exchange, and the
/// 0xfdf1 batch blob layout is not decoded).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigUpdateElem {
    /// Keep-alive interval, seconds (u32 BE).
    KeepAlive(u32),
    /// AP name; stored as a NUL-terminated string.
    ApName(Vec<u8>),
    /// LED on/off (u32 BE).
    Led(u32),
    /// Telnet service enabled (u32 BE).
    Telnet(u32),
    /// Roaming enabled (u32 BE).
    Roaming(u32),
    /// Per-radio channel: `[radio id][channel]` (2B).
    Channel { radio: u8, channel: u8 },
    /// Per-radio power: `[radio id][power u32 BE]` (5B).
    Power { radio: u8, power: u32 },
    /// New AC address the WTP should adopt (4B IPv4).
    AcAddressChange(Ipv4Addr),
    /// Image identifier (vendor id u32 BE + name); drives the WTP image path.
    ImageIdentifier { vendor_id: u32, name: Vec<u8> },
    /// Opaque H3C WLAN batch blob (tag 0xfdf1); the AX60 copies it verbatim.
    WlanBatch(Vec<u8>),
}

impl ConfigUpdateElem {
    /// Element tag and wire body for this update element.
    pub fn encode(&self) -> (u16, Vec<u8>) {
        match self {
            ConfigUpdateElem::KeepAlive(v) => (CFG_KEEPALIVE, v.to_be_bytes().to_vec()),
            ConfigUpdateElem::ApName(name) => {
                let mut b = name.clone();
                b.push(0); // C string
                (CFG_AP_NAME, b)
            }
            ConfigUpdateElem::Led(v) => (CFG_LED, v.to_be_bytes().to_vec()),
            ConfigUpdateElem::Telnet(v) => (CFG_TELNET, v.to_be_bytes().to_vec()),
            ConfigUpdateElem::Roaming(v) => (CFG_ROAMING, v.to_be_bytes().to_vec()),
            ConfigUpdateElem::Channel { radio, channel } => (CFG_CHANNEL, vec![*radio, *channel]),
            ConfigUpdateElem::Power { radio, power } => {
                let mut b = Vec::with_capacity(5);
                b.push(*radio);
                b.extend_from_slice(&power.to_be_bytes());
                (CFG_POWER, b)
            }
            ConfigUpdateElem::AcAddressChange(ip) => (CFG_AC_ADDR_CHANGE, ip.octets().to_vec()),
            ConfigUpdateElem::ImageIdentifier { vendor_id, name } => {
                let mut b = Vec::with_capacity(4 + name.len());
                b.extend_from_slice(&vendor_id.to_be_bytes());
                b.extend_from_slice(name);
                (CFG_IMAGE_IDENTIFIER, b)
            }
            ConfigUpdateElem::WlanBatch(blob) => (CFG_WLAN_BATCH, blob.clone()),
        }
    }

    /// Element tag without encoding the body (for logging / acknowledgement).
    pub fn tag(&self) -> u16 {
        self.encode().0
    }
}

/// Parsed Configuration Update Response (WTP -> AC, mtype 8).
///
/// The AX60 builds it via `CWAssembleConfigurationUpdateResponse` (WTP.dis
/// 0x3029c) with a single Result Code element (tag 33) whose value is a 4-byte
/// big-endian code; 0 means the update was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigUpdateResp {
    pub result_code: u32,
}

impl ConfigUpdateResp {
    pub fn decode(msg: &CtrlMsg) -> anyhow::Result<Self> {
        let elem = msg
            .find_elems(MsgElemType::RESULT_CODE)
            .next()
            .ok_or_else(|| anyhow::anyhow!("Configuration Update Response missing Result Code"))?;
        // H3C widens the RFC 1-byte Result Code to 4 bytes; accept both.
        let result_code = match elem.data.len() {
            4 => u32::from_be_bytes([elem.data[0], elem.data[1], elem.data[2], elem.data[3]]),
            1 => elem.data[0] as u32,
            n => return Err(anyhow::anyhow!("unexpected Result Code length {n}")),
        };
        Ok(ConfigUpdateResp { result_code })
    }

    pub fn is_success(&self) -> bool {
        self.result_code == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 150-byte AX60 Discovery Request (generated from a live capture):
    /// 16-byte control prefix + t2l2 elements.
    #[rustfmt::skip]
    const REQ: [u8; 150] = [
        0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x86, 0x00, 0x00, 0x14, 0x00, 0x01, 0x01,
        0x00, 0x26, 0x00, 0x30, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x20,
        0x53, 0x57, 0x42, 0x41, 0x31, 0x42, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x00, 0x2a, 0x02, 0x02, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x04, 0x00, 0x51,
        0x33, 0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x29, 0x00, 0x01, 0x02, 0x00, 0x2c, 0x00, 0x01, 0x00,
        0x04, 0x18, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x18, 0x00,
        0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn builds_mirrored_response() {
        let ip = Ipv4Addr::new(192, 168, 0, 254);
        let resp = discovery_response(&REQ, ip, b"miniac").expect("should build");
        // MsgType swapped to 2 (Discovery Response).
        assert_eq!(&resp[8..12], &[0, 0, 0, 2]);
        // Sequence echoed from the request.
        assert_eq!(&resp[12..16], &[0, 0, 0, 1]);
        // MsgElementLength counts bytes 16..end (self-inclusive).
        let msg_len = u16::from_be_bytes([resp[16], resp[17]]) as usize;
        assert_eq!(msg_len, resp.len() - 16);
        // Flags cleared.
        assert_eq!(resp[18], 0);
        // First element is AC Descriptor (1), not Discovery Type.
        assert_eq!(&resp[19..21], &[0, 1]);
        // AC IPv4 List uses tag 10 (the AX60 reads AC addresses only from tag 10),
        // value = [4B IP][2B]. 192.168.0.254 -> [0xC0, 0xA8, 0x00, 0xFE, 0, 2].
        let tag10 = resp
            .windows(8)
            .position(|w| w == &[0x00, 0x0A, 0x00, 0x06, 0xC0, 0xA8, 0x00, 0xFE])
            .expect("tag 10 AC IPv4 List element");
        assert_eq!(&resp[tag10 + 8..tag10 + 10], &[0, 2]);
        // H3C-private tag 0x418 present with exactly 5 bytes.
        assert_eq!(&resp[resp.len() - 9..], &[0x04, 0x18, 0, 5, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_non_discovery() {
        let mut bad = REQ.clone();
        bad[11] = 3; // Join Request, not Discovery
        assert!(discovery_response(&bad, Ipv4Addr::LOCALHOST, b"x").is_none());
    }

    use crate::config::{Akm, AuthType, Cipher, Pmf, SecurityPolicy, WlanConfig};

    // cargo runs tests in parallel, but several tests read/write the shared
    // MINIAC_H3C_EXP env var; serialize them with a module-level mutex.
    static ENV_EXP: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    fn wlan(rid: u8, wid: u8, ssid: &str) -> WlanConfig {
        WlanConfig {
            radio_id: rid,
            wlan_id: wid,
            capability: 0x0001,
            qos: 0,
            auth_type: AuthType::Rsn,
            mac_mode: 0,
            tunnel_mode: 0,
            suppress_ssid: false,
            ssid: ssid.as_bytes().to_vec(),
            security: SecurityPolicy {
                akm: Akm::PskSae,
                cipher: Cipher::Ccmp,
                psk: Some("person0finterest".into()),
                pmf: Pmf::Disabled,
            },
            ..WlanConfig::default()
        }
    }

    #[test]
    fn h3c_body_layout() {
        // Dual-band element: both radios configured. Each record is 33B anchor +
        // u32 enable + 33B name + 4*u32 + u32 enc + (PSK 65B + u32 + u32), and
        // each band leads with a 7*u32 radio header.
        let b = encode_h3c(
            &[
                WlanConfig {
                    radio_id: 1,
                    wlan_id: 1,
                    capability: 0x0001,
                    qos: 0,
                    auth_type: AuthType::Rsn,
                    mac_mode: 0,
                    tunnel_mode: 0,
                    suppress_ssid: false,
                    ssid: b"miniac24".to_vec(),
                    security: SecurityPolicy {
                        akm: Akm::PskSae,
                        cipher: Cipher::Ccmp,
                        psk: Some("person0finterest".into()),
                        pmf: Pmf::Disabled,
                    },
                    ..WlanConfig::default()
                },
                wlan(2, 1, "minimac"),
            ],
            &hdr24(),
            &hdr5(),
        );
        let rec = 33 + 4 + 33 + 16 + 4 + 73;
        assert_eq!(b.len(), 28 + rec + 28 + rec);
        // 2.4G header: enable word 0 leads, radio id = 1 at word 4.
        assert_eq!(&b[0..4], &1u32.to_be_bytes());
        assert_eq!(&b[16..20], &1u32.to_be_bytes());
        // 2.4G record anchor "SSID-1" and its broadcast SSID name.
        let g24_rec = 28;
        assert_eq!(&b[g24_rec..g24_rec + 6], b"SSID-1");
        let g24_name = g24_rec + 33 + 4;
        assert_eq!(&b[g24_name..g24_name + 8], b"miniac24");
        // 5G header sits right after the 2.4G record: enable=1, radio id=2
        // (physical radio 1; band = radio_id - 1 via 0x3ff20).
        let g5_hdr = 28 + rec;
        assert_eq!(&b[g5_hdr..g5_hdr + 4], &1u32.to_be_bytes());
        assert_eq!(&b[g5_hdr + 16..g5_hdr + 20], &2u32.to_be_bytes());
        // 5G record anchor "5G-SSID-1" and its broadcast SSID name.
        let g5_rec = g5_hdr + 28;
        assert_eq!(&b[g5_rec..g5_rec + 9], b"5G-SSID-1");
        let g5_name = g5_rec + 33 + 4;
        assert_eq!(&b[g5_name..g5_name + 7], b"minimac");
        // encrypt u32 == 6 (WPA2/WPA3 mixed), PSK ASCII right after.
        let g5_enc = g5_rec + 33 + 4 + 33 + 16;
        assert_eq!(&b[g5_enc..g5_enc + 4], &6u32.to_be_bytes());
        assert_eq!(&b[g5_enc + 4..g5_enc + 4 + 16], b"person0finterest");
    }

    #[test]
    fn h3c_body_layout_slot1() {
        let _guard = ENV_EXP.lock().unwrap();
        // MINIAC_H3C_EXP=5gslot1: single 5G record re-anchored "5G-SSID-2"
        // (slot 1) so slot 0 stays empty. Slot-0 emptiness must leave the 5G
        // header (enable=1, radio id=2) otherwise intact.
        unsafe { std::env::set_var("MINIAC_H3C_EXP", "5gslot1") };
        let b = encode_h3c(
            &[wlan(1, 1, "miniac24"), wlan(2, 1, "minimac")],
            &hdr24(),
            &hdr5(),
        );
        let rec = 33 + 4 + 33 + 16 + 4 + 73;
        assert_eq!(b.len(), 28 + rec + 28 + rec);
        // 5G header still enable=1 (word 0) and radio id=2 (word 4).
        let g5_hdr = 28 + rec;
        assert_eq!(&b[g5_hdr..g5_hdr + 4], &1u32.to_be_bytes());
        assert_eq!(&b[g5_hdr + 16..g5_hdr + 20], &2u32.to_be_bytes());
        // The 5G record is anchored "5G-SSID-2" (slot 1), not "5G-SSID-1".
        let g5_rec = g5_hdr + 28;
        assert_eq!(&b[g5_rec..g5_rec + 9], b"5G-SSID-2");
        // DB-backed record fields on the wire: broadcast=1 (visible SSID) at
        // +74, cipher=2 (AES) at +155.
        let bcast_at = g5_rec + 33 + 4 + 33 + 4;
        assert_eq!(&b[bcast_at..bcast_at + 4], &1u32.to_be_bytes());
        let cipher_at = g5_rec + 33 + 4 + 33 + 16 + 4 + 65;
        assert_eq!(&b[cipher_at..cipher_at + 4], &2u32.to_be_bytes());
        std::env::remove_var("MINIAC_H3C_EXP");
    }

    #[test]
    fn h3c_multiple_24g_ssids() {
        // Two 2.4G SSIDs (same radio, distinct wlan ids) must both be emitted as
        // "SSID-<n>" anchored records inside a single 0xfde8 element, followed by
        // the 5G band header. This verifies the decoder's Loop1 walks multiple
        // same-band records (each slot is one SSID description).
        let b = encode_h3c(
            &[wlan(1, 1, "miniac24"), wlan(1, 2, "miniac24b")],
            &hdr24(),
            &hdr5(),
        );
        let rec = 33 + 4 + 33 + 16 + 4 + 73;
        // 28 header + 2 x 163B records + 28 (empty 5G band) = 382.
        assert_eq!(b.len(), 28 + 2 * rec + 28);
        // First record anchor "SSID-1" -> miniac24.
        let r1 = 28;
        assert_eq!(&b[r1..r1 + 6], b"SSID-1");
        assert_eq!(&b[r1 + 33 + 4..r1 + 33 + 4 + 8], b"miniac24");
        // Second record anchor "SSID-2" -> miniac24b, immediately after first.
        let r2 = r1 + rec;
        assert_eq!(&b[r2..r2 + 6], b"SSID-2");
        assert_eq!(&b[r2 + 33 + 4..r2 + 33 + 4 + 9], b"miniac24b");
        // Trailing 5G band header: enable=0 (5G off) but still carries the
        // 5G radio id 2 at word 4. The AX60 decoder stores this as the 5G band
        // header and the apply chain reads enable=0 -> CFG_SetWifiEnable off.
        let g5 = 28 + 2 * rec;
        assert_eq!(&b[g5..g5 + 4], &0u32.to_be_bytes()); // enable 0
        assert_eq!(&b[g5 + 16..g5 + 20], &2u32.to_be_bytes()); // radio id 2 (5G)
        assert_eq!(b.len(), g5 + 28);
    }

    #[test]
    fn parses_config_status_req() {
        let msg = CtrlMsg::new(MsgType::CONFIG_STATUS_REQ, 1)
            .add_elem(MsgElemType::WTP_NAME, b"AX60name\0")
            .add_elem(MsgElemType::RADIO_OP_STATE, &[0, 1, 0])
            .add_elem(MsgElemType::RADIO_OP_STATE, &[1, 0, 0])
            .add_elem(MsgElemType::RADIO_ADMIN_STATE, &[0, 1])
            .add_elem(MsgElemType::RADIO_ADMIN_STATE, &[1, 1]);
        let req = ConfigStatusReq::parse(&msg);
        assert_eq!(req.wtp_name.as_deref(), Some("AX60name"));
        assert_eq!(req.radio_op_states, vec![(0, 1), (1, 0)]);
        assert_eq!(req.declared_radios, vec![(0, 1), (1, 1)]);
    }

    #[test]
    fn parses_config_status_req_missing_elems() {
        let msg = CtrlMsg::new(MsgType::CONFIG_STATUS_REQ, 2);
        let req = ConfigStatusReq::parse(&msg);
        assert!(req.wtp_name.is_none());
        assert!(req.radio_op_states.is_empty());
        assert!(req.declared_radios.is_empty());
    }

    #[test]
    fn config_status_response_default_layout() {
        let _guard = ENV_EXP.lock().unwrap();
        unsafe { std::env::remove_var("MINIAC_H3C_EXP") };
        let wlans = [wlan(1, 1, "miniac24")];
        let resp = config_status_response(&ConfigStatusResp {
            seq: 3,
            ac_ip: Ipv4Addr::new(192, 168, 0, 254),
            peer: SocketAddr::from(([192, 168, 0, 10], 5246)),
            declared_radios: &[(0, 1), (1, 1)],
            wlans: &wlans,
            g24_hdr: &hdr24(),
            g5_hdr: &hdr5(),
            wtp_mac: Some([0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25]),
            fe28: None,
            fe31: None,
        });
        assert_eq!(resp.hdr.msg_type, MsgType::CONFIG_STATUS_RESP);
        let tags: Vec<u16> = resp.elems.iter().map(|e| e.tag).collect();
        // Base elements first, then the M60 template set in assembly order
        // [2][3][12][32][16][23][40][55], then the single dual-band 0xfde8.
        assert_eq!(&tags[..3], &[
            MsgElemType::CAPWAP_TIMERS,
            MsgElemType::IDLE_TIMEOUT,
            MsgElemType::WTP_FALLBACK,
        ]);
        assert_eq!(tags[3], 0x0002);
        assert_eq!(tags[4], 0x000c);
        assert_eq!(tags[5], 0x0017);
        assert_eq!(tags[6], 0x0003);
        assert_eq!(resp.elems.iter().filter(|e| e.tag == 0x0020).count(), 2);
        assert_eq!(resp.elems.iter().filter(|e| e.tag == 0x0010).count(), 2);
        // Tail order: type40(0x0028), type55(0x0037), tag31 echo x2, then 0xfde8.
        assert_eq!(tags[tags.len() - 5], 0x0028);
        assert_eq!(tags[tags.len() - 4], 0x0037);
        assert_eq!(tags[tags.len() - 3], MsgElemType::RADIO_ADMIN_STATE);
        assert_eq!(tags[tags.len() - 2], MsgElemType::RADIO_ADMIN_STATE);
        assert_eq!(*tags.last().unwrap(), WLAN_CFG_H3C);
        // type2 = [ac_ip][peer v4]: 192.168.0.254 + 192.168.0.10.
        let t2 = resp.elems.iter().find(|e| e.tag == 0x0002).unwrap();
        assert_eq!(&t2.data[..4], &[192, 168, 0, 254]);
        assert_eq!(&t2.data[4..], &[192, 168, 0, 10]);
        // Dual-band single element: 28 + 163 + 28 = 219B (5G band empty -> its
        // header enable word stays 0).
        let fde8 = resp.elems.iter().find(|e| e.tag == WLAN_CFG_H3C).unwrap();
        assert_eq!(fde8.data.len(), 28 + 163 + 28);
        assert_eq!(&fde8.data[0..4], &1u32.to_be_bytes()); // 2.4G enable
        assert_eq!(&fde8.data[28..34], b"SSID-1");
        let g5_hdr_at = 28 + 163;
        assert_eq!(&fde8.data[g5_hdr_at..g5_hdr_at + 4], &0u32.to_be_bytes());
    }

    #[test]
    fn config_status_response_m60_layout() {
        let _guard = ENV_EXP.lock().unwrap();
        unsafe { std::env::set_var("MINIAC_H3C_EXP", "m60") };
        let wlans = [wlan(1, 1, "miniac24"), wlan(2, 2, "miniac5g")];
        let resp = config_status_response(&ConfigStatusResp {
            seq: 3,
            ac_ip: Ipv4Addr::new(192, 168, 5, 1),
            peer: SocketAddr::from(([192, 168, 5, 8], 5246)),
            declared_radios: &[(0, 1), (1, 1)],
            wlans: &wlans,
            g24_hdr: &hdr24(),
            g5_hdr: &hdr5(),
            wtp_mac: Some([0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25]),
            fe28: None,
            fe31: None,
        });
        // M60 element order, no RFC base elements / tag31 / type55.
        let tags: Vec<u16> = resp.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            &tags,
            &[0x0002, 0x0003, 0x000c, 0x0020, 0x0020, 0x0010, 0x0010, 0x0017,
              0xfe0b, 0xfe0c, 0xfe1a, 0xfe1b, 0xfe0d, 0x0028, WLAN_CFG_H3C]
        );
        // type32 radio list uses state byte 2 (M60 parity).
        let t32: Vec<&[u8]> = resp
            .elems
            .iter()
            .filter(|e| e.tag == 0x0020)
            .map(|e| e.data.as_slice())
            .collect();
        assert_eq!(t32, vec![&[0u8, 2, 0], &[1u8, 2, 0]]);
        // 0xfde8 = 456B with one record per band: 2 x (28 + 163) + 74 tail.
        let fde8 = resp.elems.iter().find(|e| e.tag == WLAN_CFG_H3C).unwrap();
        assert_eq!(fde8.data.len(), 2 * (28 + 163) + 74);
        let hdr24 = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 100,
        ];
        let hdr5 = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 100,
        ];
        assert_eq!(&fde8.data[0..28], &hdr24);
        assert_eq!(&fde8.data[28..34], b"SSID-1");
        let g5 = 28 + 163;
        assert_eq!(&fde8.data[g5..g5 + 28], &hdr5);
        assert_eq!(&fde8.data[g5 + 28..g5 + 37], b"5G-SSID-1");
        let tail = &fde8.data[2 * g5..];
        assert_eq!(tail.len(), 74);
        assert_eq!(&tail[0..6], b"SSID-1");
        assert_eq!(&tail[33..37], &1u32.to_be_bytes());
        assert_eq!(&tail[37..46], b"5G-SSID-1");
        assert_eq!(&tail[70..74], &1u32.to_be_bytes());
        std::env::remove_var("MINIAC_H3C_EXP");
    }

    #[test]
    fn config_status_response_m60_fe28_fe31_conditional() {
        let _guard = ENV_EXP.lock().unwrap();
        // fe28/fe31 must only ride when configured non-zero (M60 parity):
        // Some((0,0)) / Some(0) and None all stay omitted from the stream.
        unsafe { std::env::set_var("MINIAC_H3C_EXP", "m60") };
        let wlans = [wlan(1, 1, "miniac24")];
        let cases = [
            ("all zero", Some((0u32, 0u32)), Some(0u32), &[][..], &[][..]),
            ("enabled", Some((1, 0)), None, &[0xfe28u16][..], &[][..]),
            ("ofdma+mimo", Some((1, 1)), None, &[0xfe28u16][..], &[][..]),
            ("lbd only", None, Some(1), &[][..], &[0xfe31u16][..]),
        ];
        for (name, fe28, fe31, want28, want31) in cases {
            let resp = config_status_response(&ConfigStatusResp {
                seq: 3,
                ac_ip: Ipv4Addr::new(192, 168, 5, 1),
                peer: SocketAddr::from(([192, 168, 5, 8], 5246)),
                declared_radios: &[(0, 1), (1, 1)],
                wlans: &wlans,
                g24_hdr: &hdr24(),
                g5_hdr: &hdr5(),
                wtp_mac: Some([0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25]),
                fe28,
                fe31,
            });
            let tags: Vec<u16> = resp.elems.iter().map(|e| e.tag).collect();
            assert_eq!(
                tags.iter().filter(|t| **t == 0xfe28).copied().collect::<Vec<_>>(),
                want28,
                "{name}: fe28"
            );
            assert_eq!(
                tags.iter().filter(|t| **t == 0xfe31).copied().collect::<Vec<_>>(),
                want31,
                "{name}: fe31"
            );
            if fe28 == Some((1, 0)) {
                let e = resp.elems.iter().find(|e| e.tag == 0xfe28).unwrap();
                assert_eq!(
                    e.data,
                    vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
                    "{name}: fe28 value = [spare][ofdma][mumimo]"
                );
            }
            if fe31 == Some(1) {
                let e = resp.elems.iter().find(|e| e.tag == 0xfe31).unwrap();
                assert_eq!(e.data, vec![0, 0, 0, 1], "{name}: fe31 value");
            }
        }
        std::env::remove_var("MINIAC_H3C_EXP");
    }

    #[test]
    fn config_status_response_e2_layout() {
        let _guard = ENV_EXP.lock().unwrap();
        unsafe { std::env::set_var("MINIAC_H3C_EXP", "e2") };
        let wlans = [wlan(1, 1, "miniac24")];
        let resp = config_status_response(&ConfigStatusResp {
            seq: 4,
            ac_ip: Ipv4Addr::new(192, 168, 0, 254),
            peer: SocketAddr::from(([192, 168, 0, 10], 5246)),
            declared_radios: &[(0, 1), (1, 1)],
            wlans: &wlans,
            g24_hdr: &hdr24(),
            g5_hdr: &hdr5(),
            wtp_mac: None,
            fe28: None,
            fe31: None,
        });
        // e2 restores the legacy type2/12/23 values. Tags 12/23 collide
        // with the RFC CAPWAP_TIMERS / IDLE_TIMEOUT base elements (which ride
        // first), so the H3C type12/23 is the LAST element bearing that tag.
        let t2 = resp.elems.iter().find(|e| e.tag == 0x0002).unwrap();
        assert_eq!(&t2.data[..4], &[192, 168, 0, 2]);
        assert_eq!(&t2.data[4..], &[192, 168, 0, 10]);
        let t12: Vec<_> = resp.elems.iter().filter(|e| e.tag == 0x000c).collect();
        assert_eq!(t12.len(), 2);
        assert_eq!(t12[1].data, vec![0, 0]);
        let t23: Vec<_> = resp.elems.iter().filter(|e| e.tag == 0x0017).collect();
        assert_eq!(t23.len(), 2);
        assert_eq!(t23[1].data, vec![0, 0, 0, 0]);
        // Per-radio 0xfde8 layout: one single-band element for the 2.4G wlan,
        // ending with the 28-byte zero tail (the other band's disabled header).
        let fde8: Vec<_> = resp.elems.iter().filter(|e| e.tag == WLAN_CFG_H3C).collect();
        assert_eq!(fde8.len(), 1);
        assert_eq!(fde8[0].data.len(), 28 + 163 + 28);
        std::env::remove_var("MINIAC_H3C_EXP");
    }

    #[test]
    fn chan_util_ack_wire_format() {
        // AX60 expects an mtype-146 ack with a zero Result Code (tag 33, 4B BE
        // value 0); the H3C framer widens the 1-octet Success into 4 bytes.
        let msg = CtrlMsg::new(WTP_CHAN_UTIL_RESP, 192).with_result_success();
        let out = crate::vendor::framing::CtrlFrame::H3c.frame(&msg);
        assert_eq!(
            &out[8..],
            &[
                0, 0, 0, 146, // Message Type: channel-utilization ack
                0, 0, 0, 192, // Seq: echoes the request
                0, 11,        // MsgElemLen self-inclusive: 3 + 8
                0,            // Flags
                0, 33, 0, 4, 0, 0, 0, 0, // Result Code element, value 0
            ]
        );
    }

    #[test]
    fn config_update_elem_encodings() {
        use ConfigUpdateElem::*;
        assert_eq!(KeepAlive(30).encode(), (CFG_KEEPALIVE, vec![0, 0, 0, 30]));
        assert_eq!(Led(1).encode(), (CFG_LED, vec![0, 0, 0, 1]));
        assert_eq!(Telnet(0).encode(), (CFG_TELNET, vec![0, 0, 0, 0]));
        assert_eq!(Roaming(1).encode(), (CFG_ROAMING, vec![0, 0, 0, 1]));
        // AP name is a NUL-terminated C string.
        assert_eq!(
            ApName(b"ap-1".to_vec()).encode(),
            (CFG_AP_NAME, b"ap-1\0".to_vec())
        );
        assert_eq!(
            Channel { radio: 1, channel: 6 }.encode(),
            (CFG_CHANNEL, vec![1, 6])
        );
        assert_eq!(
            Power { radio: 2, power: 100 }.encode(),
            (CFG_POWER, vec![2, 0, 0, 0, 100])
        );
        assert_eq!(
            AcAddressChange(Ipv4Addr::new(192, 168, 0, 2)).encode(),
            (CFG_AC_ADDR_CHANGE, vec![192, 168, 0, 2])
        );
        assert_eq!(
            ImageIdentifier { vendor_id: 1916, name: b"fw".to_vec() }.encode(),
            (CFG_IMAGE_IDENTIFIER, vec![0, 0, 7, 124, b'f', b'w'])
        );
        assert_eq!(
            WlanBatch(vec![1, 2, 3]).encode(),
            (CFG_WLAN_BATCH, vec![1, 2, 3])
        );
    }

    #[test]
    fn config_update_response_result_code() {
        // H3C widens the Result Code to 4 bytes; the AX60 sends tag 33 (0x21).
        let msg = CtrlMsg::new(MsgType::CONFIG_UPDATE_RESP, 3)
            .add_elem(MsgElemType::RESULT_CODE, &[0, 0, 0, 0]);
        let resp = ConfigUpdateResp::decode(&msg).unwrap();
        assert_eq!(resp.result_code, 0);
        assert!(resp.is_success());

        let fail = CtrlMsg::new(MsgType::CONFIG_UPDATE_RESP, 4)
            .add_elem(MsgElemType::RESULT_CODE, &[0, 0, 0, 13]);
        assert_eq!(ConfigUpdateResp::decode(&fail).unwrap().result_code, 13);

        // A response without a Result Code element is rejected.
        assert!(ConfigUpdateResp::decode(&CtrlMsg::new(MsgType::CONFIG_UPDATE_RESP, 5)).is_err());
    }

    #[test]
    fn reset_request_image_id_encoding() {
        // Image Identifier value = [vendor 0, "all_version", 0x00], 16 bytes.
        assert_eq!(
            image_id_all_version(),
            vec![0, 0, 0, 0, b'a', b'l', b'l', b'_', b'v', b'e', b'r', b's', b'i', b'o', b'n', 0]
        );
        let msg = reset_request(7);
        assert_eq!(msg.hdr.msg_type, MsgType::RESET_REQ);
        assert_eq!(msg.hdr.seq_num, 7);
        assert_eq!(msg.elems.len(), 1);
        assert_eq!(msg.elems[0].tag, MsgElemType::IMAGE_ID);
        assert_eq!(msg.elems[0].data, image_id_all_version());
        // Sanity: the element body carries its own trailing NUL (the AX60 parser
        // forces the last byte to NUL, so an unterminated name is truncated).
        assert_eq!(*msg.elems[0].data.last().unwrap(), 0);
    }

    #[test]
    fn clear_config_request_is_bare() {
        let msg = clear_config_request(9);
        assert_eq!(msg.hdr.msg_type, MsgType::CLEAR_CONFIG_REQ);
        assert_eq!(msg.hdr.seq_num, 9);
        assert!(msg.elems.is_empty());
    }

    #[test]
    fn release_client_request_mac_element() {
        let mac = [0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25];
        let msg = release_client_request(11, mac);
        assert_eq!(msg.hdr.msg_type, MsgType::RELEASE_CLIENT_REQ);
        assert_eq!(msg.elems.len(), 1);
        // Tag 65 with a value that is exactly the 6-byte client MAC.
        assert_eq!(msg.elems[0].tag, ELEM_RELEASE_CLIENT_MAC);
        assert_eq!(msg.elems[0].data, mac.to_vec());
        assert_eq!(msg.elems[0].data.len(), 6);
    }

    #[test]
    fn result_code_reads_both_widths() {
        let h3c = CtrlMsg::new(MsgType::RELEASE_CLIENT_RESP, 1)
            .add_elem(MsgElemType::RESULT_CODE, &[0, 0, 0, 0]);
        assert_eq!(result_code(&h3c), Some(0));
        let rfc = CtrlMsg::new(MsgType::RESET_RESP, 2).add_elem(MsgElemType::RESULT_CODE, &[10]);
        assert_eq!(result_code(&rfc), Some(10));
        assert_eq!(result_code(&CtrlMsg::new(MsgType::RESET_RESP, 3)), None);
    }
}
