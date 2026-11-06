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

use crate::capwap::{CtrlMsg, CwElem, CwResult, MsgElemType, MsgType};
use crate::config;
use crate::elements::BaseElem;
use crate::radio::H3cRadioHeader;

/// Build a Discovery Response tailored to an H3C AX60-style WTP.
///
/// `req` is the raw inbound UDP payload; `ac_ips` are the AC control addresses
/// the WTP may join (the request's destination, or the ingress interface's
/// addresses when it arrived by broadcast); `ac_name` is advertised in the AC
/// Name element. Returns `None` when `req` is not a recognized H3C-framed
/// Discovery Request so the caller can drop it without fabricating a broken
/// reply.
pub fn discovery_response(req: &[u8], ac_ips: &[Ipv4Addr], ac_name: &[u8]) -> Option<Vec<u8>> {
    // Need enough prefix to mirror, a length that fits a u16, and a Discovery
    // Request type (low byte of the 4-byte Message Type at [8..12]).
    if req.len() <= 19 || req.len() - 16 > u16::MAX as usize {
        return None;
    }
    if req[8] != 0 || req[9] != 0 || req[10] != 0 || req[11] != 1 {
        return None;
    }
    if ac_ips.is_empty() {
        return None;
    }

    let mut body = Vec::with_capacity(8 + ac_name.len());
    // Mirror the real AC element set: AC Descriptor(1), AC Name(4), AC IPv4
    // List(10) and the H3C-private tag 0x418. The WTP parses 1/4/0x418, collects
    // AC addresses from 10 (value = [4B IP][2B], WTP.dis 0x1df5c) and skips a
    // tag 2. No Discovery Type (20) is sent (the real AC does not include it).
    let mut ac_list = Vec::with_capacity(ac_ips.len() * 6);
    for ip in ac_ips {
        // [4B IP][2B], family/class hint per the real AC. One entry per AC
        // address lets the WTP try each when the AC is multihomed.
        ac_list.extend_from_slice(&ac_ipv4_entry(*ip));
    }
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

/// Prefix on the Image Identifier element (`[4B BE][name][0x00]`) of the H3C
/// control messages that name an image. The M60 AC hardcodes it as 48
/// (`sub_1005C888` returns 48 in every Image Identifier it assembles, and its
/// own Reset Request carries the downloaded image's name) and the AX60 checks
/// it against `sub_5E308()` == 48:
///   - Configuration Update Request: mismatch -> result 13
///     (`CWSaveConfigurationUpdateRequest`); the WTP's own Image Data Request
///     uses the same value.
///   - Reset Request: mismatch -> result 10 "Vendor ID invalid"
///     (`CWWTPManageGenericRunMessage` msg 17), so a reset that should flash a
///     finished download is rejected without it.
/// A zero prefix is only sent by the vendor's `all_version` plain-restart form.
pub const IMAGE_ID_PREFIX: u32 = 48;

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

/// Join Response (mtype 4) that also announces an image to install.
///
/// The M60 AC puts the Image Identifier in the Join Response when the WTP's
/// version differs from the image it holds (`ACEnterJoin`); the AX60
/// `CWWTPEnterJoin` (WTPJoinState.c 270-274) compares that string with its own
/// running version and, when they differ, enters the Image Data state and asks
/// for the download before it takes any configuration.
pub fn join_response_with_image(seq: u32, ac_ip: Ipv4Addr, image_name: &[u8]) -> CtrlMsg {
    CtrlMsg::new(MsgType::JOIN_RESP, seq)
        .with_result_success()
        .add_elem(MsgElemType::IMAGE_ID, &image_identifier(image_name))
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
/// SSID, enable, broadcast, encrypt and PSK (see `encode_h3c_with`).
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

/// Build a Reset Request (mtype 17).
///
/// RFC 5415 9.2; the AX60 parser `CWParseResetRequest` (WTP.dis 0x3ddb8) expects
/// exactly one Image Identifier element (tag 25) whose value is
/// `[4B BE][image name][0x00]` — the parser forces the final byte to NUL, so the
/// name must carry its own terminator.
///
/// `image_name` selects which image the WTP restarts on: `all_version` (or an
/// empty name, used by the management-plane Reset) is the zero-prefix form that
/// skips the image check and reboots the running firmware (`sub_5E2AC`), while
/// the name the AC announced for a finished download makes the WTP flash the
/// file it just received before rebooting (`sub_5E1DC` -> `MW_UpdateApp`). That
/// named form must carry `IMAGE_ID_PREFIX` (48): the AX60 answers result 10
/// ("Vendor ID invalid") and does not reboot otherwise.
pub fn reset_request(seq: u32, image_name: &[u8]) -> CtrlMsg {
    let body = if image_name.is_empty() || image_name == b"all_version" {
        image_id_all_version()
    } else {
        image_identifier(image_name)
    };
    CtrlMsg::new(MsgType::RESET_REQ, seq).add_elem(MsgElemType::IMAGE_ID, &body)
}

/// Image Identifier value naming an image: `[48 4B BE][name][0x00]`.
pub fn image_identifier(name: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(name.len() + 5);
    v.extend_from_slice(&IMAGE_ID_PREFIX.to_be_bytes());
    v.extend_from_slice(name);
    v.push(0);
    v
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

/// H3C private element carrying the external (release) version string, e.g.
/// `SWBA1B0V100R010` — the external version shown on the WTP's own debug
/// page (`CWAssembleJoinRequest` sub_1A068 on AX60). This is what the WTP
/// compares against an announced image identifier.
pub const ELEM_RELEASE_VERSION: u16 = 0x40;

/// H3C private element carrying the internal (build) version string, e.g.
/// `SWBA1B0V100D017` (the internal version, sub_19F7C on AX60). Sent alongside the
/// release version; miniac only uses it when the release element is missing.
pub const ELEM_BUILD_VERSION: u16 = 0x3D;

/// Hardware revision of an H3C WTP from its WTP Descriptor value.
///
/// H3C does not use the RFC two-u32 layout: the descriptor starts with a 1-byte
/// hardware revision followed by 1-byte software revision, two 0x01 bytes and a
/// u16 (`sub_18D64` on AX60). The AX60 reports 2, which its Web UI renders as
/// `VER.B` (A=1, B=2, …).
pub fn descriptor_hardware_version(descriptor: &[u8]) -> Option<u8> {
    descriptor.first().copied().filter(|v| *v != 0)
}

/// Short form of an H3C version string: `SWBA1B0V100R010` -> `R010`. Keeps the
/// trailing marker (`R` = release, `D` = build) and its digits, dropping the
/// product model and the `V100` platform prefix. Returns `None` when the value
/// does not follow that `<model>[V<digits>]<marker><digits>` shape, so callers
/// fall back to the raw descriptor bytes.
pub fn short_version(value: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(value);
    let trimmed = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    let bytes = trimmed.as_bytes();
    let mut i = bytes.len();
    while i > 0 && bytes[i - 1].is_ascii_digit() {
        i -= 1;
    }
    // Need digits at the end and a marker letter (with a model prefix) before.
    if i == bytes.len() || i == 0 {
        return None;
    }
    let marker = bytes[i - 1];
    if !marker.is_ascii_uppercase() {
        return None;
    }
    // A marker without the `V100` platform prefix is a model suffix such as the
    // trailing "B0" of `SWBA1B0`, not a version.
    if !bytes[..i - 1].contains(&b'V') {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[i - 1..]).into_owned())
}

/// H3C 0xfde8 security selectors for a WLAN policy: the encrypt-type byte plus
/// the WPA cipher, both through the shared vendor mapping. An inexpressible
/// policy (pure WPA3) is snapped to the closest H3C mode (WPA2/WPA3 mixed).
fn h3c_security(w: &config::WlanConfig) -> crate::vendor::profile::SecurityFields {
    crate::vendor::profile::VendorProfile::H3c.security_fields(&w.security)
}

/// Encode the H3C private WLAN element body (tag `WLAN_CFG_H3C`) for a WTP's
/// complete WLAN set. The AX60's authoritative decoder (`0x26010 -> 0x52ee0`)
/// walks the value sequentially (big-endian u32) and must consume exactly the
/// element length, in the M60 AC's layout:
///
///   [7 x u32]  2.4G radio header [enable, 0, power, mode, bandwidth, channel, 100]
///   [records]  "SSID-<n>" anchored WLAN records
///   [7 x u32]  5G radio header [..same..]
///   [records]  "5G-SSID-<n>" anchored records
///   [74B]      [33B "SSID-1"][u32 1][33B "5G-SSID-1"][u32 1] tail
///
/// Both bands ride in a single element. `WTPEditSsid` reads word0 as the radio
/// enable, word2 as TX power, word3 as the mode selector, word4 as the channel
/// width selector and word5 as the channel (a selector code on 5G); word6 is
/// never read (kept at the M60's 100). A band with no WLAN yields enable=0 and
/// no records. The Configure push passes the configured per-band headers.
pub fn encode_h3c_with(wlans: &[config::WlanConfig], radios: &[H3cRadioHeader; 2]) -> Vec<u8> {
    let g24: Vec<&config::WlanConfig> = wlans.iter().filter(|w| w.radio_id != 2).collect();
    let g5: Vec<&config::WlanConfig> = wlans.iter().filter(|w| w.radio_id == 2).collect();
    let mut v = Vec::new();
    emit_h3c_band(&mut v, &g24, b"SSID-", 1, &radios[0]);
    // The captured 5G header keeps radio id 1 as well (word4 = 1, unlike the
    // per-radio convention of id 2 for 5G); replicate the capture verbatim.
    emit_h3c_band(&mut v, &g5, b"5G-SSID-", 2, &radios[1]);
    // Tail: both anchor labels plus a trailing flag word each.
    for anchor in [b"SSID-1".as_slice(), b"5G-SSID-1".as_slice()] {
        let mut a = [0u8; 33];
        a[..anchor.len()].copy_from_slice(anchor);
        v.extend_from_slice(&a);
        v.extend_from_slice(&1u32.to_be_bytes());
    }
    v
}

/// Map a configured channel width (MHz) to the 0xfde8 header word4 selector.
/// `WTPEditSsid` hands the code to `sub_3FF20`: 1 = 20 MHz, 2 = 40, 3 = 80,
/// 4 = auto, 5 = 160. An unrepresentable width falls back to 20 MHz.
pub fn h3c_bandwidth_field(mhz: u32) -> u32 {
    match mhz {
        0 => 4,
        20 => 1,
        40 => 2,
        80 => 3,
        160 => 5,
        _ => 1,
    }
}

/// Map an IEEE channel number to the 0xfde8 header word5 value. 2.4G carries
/// the IEEE number verbatim (0 = auto). 5G uses the AX60's fixed selector code
/// table (`WTPEditSsid`): 0/149/153/157/161/165 and 36..64, with any other
/// number (including DFS channels) falling back to 64.
pub fn h3c_channel_field(band: u8, ieee: u32) -> u32 {
    if band != 2 {
        return ieee;
    }
    match ieee {
        0 => 0,
        149 => 1,
        153 => 2,
        157 => 3,
        161 => 4,
        165 => 5,
        36 => 6,
        40 => 7,
        44 => 8,
        48 => 9,
        52 => 0xa,
        56 => 0xb,
        60 => 0xc,
        _ => 0xd,
    }
}

/// Map a normalized [`crate::vendor::mode`] value to the 0xfde8 header word3
/// selector. The AX60's own per-band pages enumerate the codes that
/// `WTPEditSsidInit` decodes (`www_multi/AX60/wlan_ap_basic*.asp`):
/// 2.4 GHz 1 = 11b, 2 = 11g, 3 = 11b/g, 4 = 11n, 5 = 11b/g/n, 6 = 11b/g/n/ax;
/// 5 GHz 7 = 11a, 8 = 11a/n, 10 = 11a/n/ac, 11 = 11a/n/ac/ax. H3C cannot
/// express every normalized mode (there is no ac-only or be code), so the
/// nearest superset is used, and AUTO keeps the M60 capture's defaults
/// (11 on 2.4 GHz, 8 on 5 GHz).
pub fn h3c_mode_field(band: u8, mode: u32) -> u32 {
    use crate::vendor::mode as m;
    let mode = m::for_band(band, mode);
    if band == 1 {
        match mode {
            m::B => 1,
            m::G => 2,
            m::BG => 3,
            m::N => 4,
            m::BGN => 5,
            m::BGNAX | m::BGNAXBE => 6,
            _ => 11,
        }
    } else {
        match mode {
            m::A => 7,
            m::AN => 8,
            m::AC | m::ANAC => 10,
            m::ANACAX | m::ANACAXBE => 11,
            // AUTO, and 11n alone (no pure-n 5 GHz code) select 11a/n.
            _ => 8,
        }
    }
}

/// Append one band: a 7 x u32 header and its anchored records. An empty band
/// keeps the header with enable=0 and no records.
fn emit_h3c_band(
    v: &mut Vec<u8>,
    wlans: &[&config::WlanConfig],
    prefix: &[u8],
    band: u8,
    hdr: &H3cRadioHeader,
) {
    let mode = h3c_mode_field(band, hdr.mode);
    for word in [
        u32::from(hdr.enable && !wlans.is_empty()), // radio enable
        0,                                          // opaque
        hdr.power.min(100),                         // TX power
        mode,                                       // band/mode selector
        h3c_bandwidth_field(hdr.bandwidth),         // channel width selector
        h3c_channel_field(band, hdr.channel),       // channel
        100,                                        // never read (M60 parity)
    ] {
        v.extend_from_slice(&word.to_be_bytes());
    }
    for (i, w) in wlans.iter().enumerate() {
        emit_h3c_record(v, w, prefix, i as u32 + 1);
    }
}

/// Per-SSID client ceiling the AX60 web UI exposes and `WTPEditSsidInit`
/// enforces (`<=32` kept, `>32` clamped to 32).
const MAX_CLIENTS: u32 = 32;

/// Wire value of the H3C record client-limit word (record offset +116,
/// `CFG_SetWifiSsidClientNum` in `WTPEditSsidInit`). The AX60 reads `0xffffffff`
/// as "no limit"; miniac stores 0 for "no limit", so 0 maps to that sentinel and
/// a configured limit is clamped to the per-SSID ceiling.
fn h3c_client_limit(client_count: u32) -> u32 {
    if client_count == 0 {
        0xffff_ffff
    } else {
        client_count.min(MAX_CLIENTS)
    }
}

/// Append one WLAN record: [33B anchor][u32 enable][33B SSID name][u32
/// isolate][u32 broadcast][u32 client limit][u32 vlan][u32 encrypt]
/// and, when encrypted, [65B PSK][u32 cipher][u32 rekey=3600]. SSID, PSK,
/// enable, isolate, SSID broadcast, client limit, VLAN and security come from
/// the miniac DB; the rekey period uses the M60 default (one hour). Words 4 and
/// 5 reach the WTP as the isolation and SSID broadcast flags (record offsets
/// +108/+112 in `WTPEditSsidInit`, handed to `CFG_SetWifiIsolate` and
/// `CFG_SetWifiSsidBroadcast`); word 6 is the per-SSID client limit (+116).
fn emit_h3c_record(v: &mut Vec<u8>, w: &config::WlanConfig, prefix: &[u8], idx: u32) {
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
    v.extend_from_slice(&u32::from(w.isolate).to_be_bytes());
    v.extend_from_slice(&u32::from(w.broadcast).to_be_bytes());
    v.extend_from_slice(&h3c_client_limit(w.client_count).to_be_bytes());
    v.extend_from_slice(&w.vlan_id.to_be_bytes());
    v.extend_from_slice(&enc.to_be_bytes());
    if enc != 0 {
        v.extend_from_slice(&pskbuf);
        v.extend_from_slice(&fields.cipher.to_be_bytes());
        v.extend_from_slice(&3600u32.to_be_bytes());
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
    /// Effective per-radio header config (2.4G first) written into the 0xfde8
    /// element's two band headers.
    pub radios: [H3cRadioHeader; 2],
    /// OFDMA / MU-MIMO enable words for the fe28 element. Mirrors the M60 AC:
    /// the element is only emitted when either word is non-zero.
    pub fe28: Option<(u32, u32)>,
    /// Band navigation (LBD) enable word for the fe31 element; only emitted
    /// when non-zero.
    pub fe31: Option<u32>,
    /// Remembered AP LED state, emitted as the 0xfdf4 element (u32 BE) when
    /// known. `None` leaves the WTP's own default (LED on) untouched.
    pub led: Option<bool>,
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

/// Build the H3C Configuration Status Response (mtype 6) in the M60 AC's
/// element order: [2][3][12][32][16][23][fe0b][fe0c][fe1a][fe1b][fe0d][40]
/// then one 0xfde8 WLAN element. Those small-ID tags carry H3C-private
/// payloads, appended verbatim; no RFC base element, tag 31 or type 55 is sent.
pub fn config_status_response(inp: &ConfigStatusResp<'_>) -> CtrlMsg {
    // M60 template base elements (H3C private payloads):
    //   type2  = AC/management IPv4 list, 2 x u32 BE
    //   type3  = IPv6 list, 2 x 16B
    //   type12 = 2 control bytes
    //   type32 = radio list, 3B per record (state byte 2, M60 parity)
    //   type16 = radio params, 3B per record
    //   type23 = one u32 BE
    //   type40 = constant 0x00
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
    // One dual-band 0xfde8 element: the AX60 applies WLAN/SSID only from this
    // Configure-stage response, and its decoder 0x52ee0 must consume the whole
    // element (see `encode_h3c_with`).
    if !inp.wlans.is_empty() {
        let body = encode_h3c_with(inp.wlans, &inp.radios);
        m = m.add_elem(WLAN_CFG_H3C, &body);
    }
    // The M60 AC closes this snapshot with its AP name / telnet / LED /
    // keep-alive / roaming chain (`CWAssembleConfigureResponseForPL`), so the
    // saved LED state rides here too: the AX60 applies 0xfdf4 while saving the
    // Configure-stage message (`CWSaveConfigureResponseMessage` restarts or
    // stops `led_control`), which is what makes a chosen "off" survive a reboot.
    if let Some(on) = inp.led {
        m = m.add_elem(CFG_LED, &u32::from(on).to_be_bytes());
    }
    m
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
                // The M60 sends the name as a C string (its encoder allocates
                // strlen+5: vendor id, name, terminator).
                let mut b = Vec::with_capacity(5 + name.len());
                b.extend_from_slice(&vendor_id.to_be_bytes());
                b.extend_from_slice(name);
                b.push(0);
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
        let resp = discovery_response(&REQ, &[ip], b"miniac").expect("should build");
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
        assert!(discovery_response(&bad, &[Ipv4Addr::LOCALHOST], b"x").is_none());
    }

    #[test]
    fn lists_every_ac_address() {
        // A multihomed AC advertises one tag-10 entry per address.
        let ips = [
            Ipv4Addr::new(192, 168, 0, 254),
            Ipv4Addr::new(10, 0, 0, 2),
        ];
        let resp = discovery_response(&REQ, &ips, b"miniac").expect("should build");
        let tag = resp
            .windows(4)
            .position(|w| w == [0x00, 0x0A, 0x00, 0x0C])
            .expect("tag 10 with two 6-byte entries");
        assert_eq!(&resp[tag + 4..tag + 8], &ips[0].octets());
        assert_eq!(&resp[tag + 8..tag + 10], &[0, 2]);
        assert_eq!(&resp[tag + 10..tag + 14], &ips[1].octets());
        assert_eq!(&resp[tag + 14..tag + 16], &[0, 2]);
    }

    use crate::config::{Akm, AuthType, Cipher, Pmf, SecurityPolicy, WlanConfig};

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

    fn encode_default(wlans: &[config::WlanConfig]) -> Vec<u8> {
        let defaults = [
            H3cRadioHeader {
                radio_id: 1,
                ..H3cRadioHeader::default()
            },
            H3cRadioHeader {
                radio_id: 2,
                ..H3cRadioHeader::default()
            },
        ];
        encode_h3c_with(wlans, &defaults)
    }

    #[test]
    fn h3c_body_layout() {
        // One record per band in the M60 layout. Each record is 33B anchor +
        // u32 enable + 33B name + 5*u32, plus [65B PSK][u32 cipher][u32 rekey]
        // when encrypted, i.e. 163B.
        let b = encode_default(&[wlan(1, 1, "miniac24"), wlan(2, 1, "miniac5g")]);
        let rec = 163;
        assert_eq!(b.len(), 2 * (28 + rec) + 74);
        // 2.4G header: enable=1, power=6 at word 2, mode=11 at word 3, 20 MHz
        // (selector 1) at word 4, auto channel 0 at word 5, 100 at word 6.
        let hdr24 = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 11, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 100,
        ];
        assert_eq!(&b[..28], &hdr24);
        // 2.4G record: anchor "SSID-1", broadcast SSID name, broadcast=1,
        // cipher=2 (AES).
        assert_eq!(&b[28..34], b"SSID-1");
        assert_eq!(&b[28 + 37..28 + 37 + 8], b"miniac24");
        let bcast = 28 + 33 + 4 + 33 + 4;
        assert_eq!(&b[bcast..bcast + 4], &1u32.to_be_bytes());
        let cipher = 28 + 33 + 4 + 33 + 16 + 4 + 65;
        assert_eq!(&b[cipher..cipher + 4], &2u32.to_be_bytes());
        // 5G header (mode=8, same default header fields) and its anchored record.
        let g5 = 28 + rec;
        let hdr5 = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 100,
        ];
        assert_eq!(&b[g5..g5 + 28], &hdr5);
        assert_eq!(&b[g5 + 28..g5 + 37], b"5G-SSID-1");
        assert_eq!(&b[g5 + 28 + 37..g5 + 28 + 37 + 8], b"miniac5g");
        // encrypt u32 == 6 (WPA2/WPA3 mixed), PSK ASCII right after.
        let enc = g5 + 28 + 33 + 4 + 33 + 16;
        assert_eq!(&b[enc..enc + 4], &6u32.to_be_bytes());
        assert_eq!(&b[enc + 4..enc + 4 + 16], b"person0finterest");
        // Tail: per-band anchor names and their flag words.
        let tail = &b[2 * (28 + rec)..];
        assert_eq!(tail.len(), 74);
        assert_eq!(&tail[0..6], b"SSID-1");
        assert_eq!(&tail[33..37], &1u32.to_be_bytes());
        assert_eq!(&tail[37..46], b"5G-SSID-1");
        assert_eq!(&tail[70..74], &1u32.to_be_bytes());
    }

    #[test]
    fn h3c_empty_band_disables_radio() {
        // A single 2.4G WLAN still emits the 5G header, with enable=0, and the
        // full tail.
        let b = encode_default(&[wlan(1, 1, "miniac24")]);
        assert_eq!(b.len(), 28 + 163 + 28 + 74);
        assert_eq!(&b[0..4], &1u32.to_be_bytes());
        let g5 = 28 + 163;
        assert_eq!(&b[g5..g5 + 4], &0u32.to_be_bytes());
        assert_eq!(&b[g5 + 12..g5 + 16], &8u32.to_be_bytes());
    }

    #[test]
    fn h3c_header_carries_configured_radio_settings() {
        let h24 = H3cRadioHeader {
            radio_id: 1,
            power: 3,
            mode: 0,
            bandwidth: 40,
            ..H3cRadioHeader::default()
        };
        let h5 = H3cRadioHeader {
            radio_id: 2,
            power: 7,
            mode: 5,
            bandwidth: 80,
            channel: 149,
            ..H3cRadioHeader::default()
        };
        let b = encode_h3c_with(&[wlan(1, 1, "a"), wlan(2, 1, "b")], &[h24, h5]);
        let word = |v: &[u8], at: usize| {
            u32::from_be_bytes([v[at], v[at + 1], v[at + 2], v[at + 3]])
        };
        // 2.4G: enable, power 3, mode 0 -> band default 11, 40 MHz -> 2,
        // auto channel 0, unread word6 stays 100.
        assert_eq!(word(&b, 0), 1);
        assert_eq!(word(&b, 8), 3);
        assert_eq!(word(&b, 12), 11);
        assert_eq!(word(&b, 16), 2);
        assert_eq!(word(&b, 20), 0);
        assert_eq!(word(&b, 24), 100);
        // 5G: power 7, mode 5 (11n only) -> 8 (a/n, the nearest superset),
        // 80 MHz -> 3, channel 149 -> selector 1.
        let g5 = 28 + 163;
        assert_eq!(word(&b, g5 + 8), 7);
        assert_eq!(word(&b, g5 + 12), 8);
        assert_eq!(word(&b, g5 + 16), 3);
        assert_eq!(word(&b, g5 + 20), 1);
    }

    #[test]
    fn h3c_header_disabled_radio_stays_off() {
        // An explicitly disabled radio keeps enable=0 even with a WLAN record.
        let off24 = H3cRadioHeader {
            radio_id: 1,
            enable: false,
            ..H3cRadioHeader::default()
        };
        let on5 = H3cRadioHeader {
            radio_id: 2,
            ..H3cRadioHeader::default()
        };
        let b = encode_h3c_with(&[wlan(1, 1, "a"), wlan(2, 1, "b")], &[off24, on5]);
        assert_eq!(&b[0..4], &0u32.to_be_bytes());
    }

    #[test]
    fn h3c_bandwidth_and_channel_selectors() {
        assert_eq!(h3c_bandwidth_field(20), 1);
        assert_eq!(h3c_bandwidth_field(40), 2);
        assert_eq!(h3c_bandwidth_field(80), 3);
        assert_eq!(h3c_bandwidth_field(0), 4);
        assert_eq!(h3c_bandwidth_field(160), 5);
        // An unrepresentable width (e.g. 30 MHz) falls back to 20 MHz.
        assert_eq!(h3c_bandwidth_field(30), 1);
        // 2.4G passes the IEEE channel through unchanged.
        assert_eq!(h3c_channel_field(1, 6), 6);
        assert_eq!(h3c_channel_field(1, 0), 0);
        // 5G selector table.
        assert_eq!(h3c_channel_field(2, 0), 0);
        assert_eq!(h3c_channel_field(2, 36), 6);
        assert_eq!(h3c_channel_field(2, 64), 0xd);
        assert_eq!(h3c_channel_field(2, 149), 1);
        assert_eq!(h3c_channel_field(2, 165), 5);
        // DFS channels are absent from the AX60 table and fall back to 64.
        assert_eq!(h3c_channel_field(2, 100), 0xd);
    }

    #[test]
    fn h3c_mode_selectors_are_per_band() {
        use crate::vendor::mode;
        // Defaults reproduce the M60 capture.
        assert_eq!(h3c_mode_field(1, mode::AUTO), 11);
        assert_eq!(h3c_mode_field(2, mode::AUTO), 8);
        // 2.4 GHz codes from the AX60's own page.
        assert_eq!(h3c_mode_field(1, mode::B), 1);
        assert_eq!(h3c_mode_field(1, mode::G), 2);
        assert_eq!(h3c_mode_field(1, mode::BG), 3);
        assert_eq!(h3c_mode_field(1, mode::N), 4);
        assert_eq!(h3c_mode_field(1, mode::BGN), 5);
        assert_eq!(h3c_mode_field(1, mode::BGNAX), 6);
        assert_eq!(h3c_mode_field(1, mode::BGNAXBE), 6);
        // 5 GHz codes, with modes H3C cannot name snapped to the nearest set.
        assert_eq!(h3c_mode_field(2, mode::A), 7);
        assert_eq!(h3c_mode_field(2, mode::AN), 8);
        assert_eq!(h3c_mode_field(2, mode::N), 8);
        assert_eq!(h3c_mode_field(2, mode::AC), 10);
        assert_eq!(h3c_mode_field(2, mode::ANAC), 10);
        assert_eq!(h3c_mode_field(2, mode::ANACAX), 11);
        assert_eq!(h3c_mode_field(2, mode::ANACAXBE), 11);
        // A value from the other band is never sent as that band's code.
        assert_eq!(h3c_mode_field(1, mode::AC), 11);
        assert_eq!(h3c_mode_field(2, mode::BG), 8);
    }

    #[test]
    fn h3c_multiple_24g_ssids() {
        // Two 2.4G wlans become consecutive "SSID-<n>" records (indices 1, 2),
        // followed by the empty 5G header and the tail.
        let b = encode_default(&[wlan(1, 1, "miniac24"), wlan(1, 2, "miniac24b")]);
        let rec = 163;
        assert_eq!(b.len(), 28 + 2 * rec + 28 + 74);
        assert_eq!(&b[28..34], b"SSID-1");
        assert_eq!(&b[28 + 37..28 + 37 + 8], b"miniac24");
        assert_eq!(&b[28 + rec..28 + rec + 6], b"SSID-2");
        assert_eq!(&b[28 + rec + 37..28 + rec + 37 + 9], b"miniac24b");
    }

    #[test]
    fn short_version_strips_model_and_platform() {
        assert_eq!(short_version(b"SWBA1B0V100R010\0").as_deref(), Some("R010"));
        assert_eq!(short_version(b"SWBA1B0V100D017").as_deref(), Some("D017"));
        assert_eq!(short_version(b"SWBA1A0V100R006").as_deref(), Some("R006"));
        // A bare model name (no V-platform prefix) is not a version.
        assert_eq!(short_version(b"SWBA1B0"), None);
        assert_eq!(short_version(b""), None);
    }

    #[test]
    fn descriptor_hardware_version_is_first_byte() {
        // AX60 descriptor prefix: hardware 2 (VER.B), software 2, then 0x01 0x01.
        let body = [0x02u8, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(descriptor_hardware_version(&body), Some(2));
        assert_eq!(descriptor_hardware_version(&[]), None);
        assert_eq!(descriptor_hardware_version(&[0]), None);
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
    fn config_status_response_m60_layout() {
        let wlans = [wlan(1, 1, "miniac24"), wlan(2, 2, "miniac5g")];
        let resp = config_status_response(&ConfigStatusResp {
            seq: 3,
            ac_ip: Ipv4Addr::new(192, 168, 5, 1),
            peer: SocketAddr::from(([192, 168, 5, 8], 5246)),
            declared_radios: &[(0, 1), (1, 1)],
            wlans: &wlans,
            radios: [
                H3cRadioHeader::default(),
                H3cRadioHeader {
                    radio_id: 2,
                    ..H3cRadioHeader::default()
                },
            ],
            fe28: None,
            fe31: None,
            led: Some(false),
        });
        // M60 element order, no RFC base elements / tag31 / type55.
        let tags: Vec<u16> = resp.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            &tags,
            &[0x0002, 0x0003, 0x000c, 0x0020, 0x0020, 0x0010, 0x0010, 0x0017,
              0xfe0b, 0xfe0c, 0xfe1a, 0xfe1b, 0xfe0d, 0x0028, WLAN_CFG_H3C, CFG_LED]
        );
        // The remembered "off" state is a u32 BE in the trailing 0xfdf4 element.
        let led = resp.elems.iter().find(|e| e.tag == CFG_LED).unwrap();
        assert_eq!(led.data, vec![0, 0, 0, 0]);
        // type32 radio list uses state byte 2 (M60 parity).
        let t32: Vec<&[u8]> = resp
            .elems
            .iter()
            .filter(|e| e.tag == 0x0020)
            .map(|e| e.data.as_slice())
            .collect();
        assert_eq!(t32, vec![&[0u8, 2, 0], &[1u8, 2, 0]]);
        // type2 = [ac_ip][peer v4].
        let t2 = resp.elems.iter().find(|e| e.tag == 0x0002).unwrap();
        assert_eq!(&t2.data[..4], &[192, 168, 5, 1]);
        assert_eq!(&t2.data[4..], &[192, 168, 5, 8]);
        // 0xfde8 = 456B with one record per band: 2 x (28 + 163) + 74 tail.
        let fde8 = resp.elems.iter().find(|e| e.tag == WLAN_CFG_H3C).unwrap();
        assert_eq!(fde8.data.len(), 2 * (28 + 163) + 74);
        assert_eq!(&fde8.data[28..34], b"SSID-1");
        assert_eq!(&fde8.data[28 + 163 + 28..28 + 163 + 37], b"5G-SSID-1");
    }

    #[test]
    fn config_status_response_m60_fe28_fe31_conditional() {
        // fe28/fe31 must only ride when configured non-zero (M60 parity):
        // Some((0,0)) / Some(0) and None all stay omitted from the stream.
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
                radios: [
                    H3cRadioHeader::default(),
                    H3cRadioHeader {
                        radio_id: 2,
                        ..H3cRadioHeader::default()
                    },
                ],
                fe28,
                fe31,
                led: None,
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
            (CFG_IMAGE_IDENTIFIER, vec![0, 0, 7, 124, b'f', b'w', 0])
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
        let msg = reset_request(7, b"all_version");
        assert_eq!(msg.hdr.msg_type, MsgType::RESET_REQ);
        assert_eq!(msg.hdr.seq_num, 7);
        assert_eq!(msg.elems.len(), 1);
        assert_eq!(msg.elems[0].tag, MsgElemType::IMAGE_ID);
        assert_eq!(msg.elems[0].data, image_id_all_version());
        // Sanity: the element body carries its own trailing NUL (the AX60 parser
        // forces the last byte to NUL, so an unterminated name is truncated).
        assert_eq!(*msg.elems[0].data.last().unwrap(), 0);

        // A named image (finished download) carries the 48 prefix and makes the
        // WTP flash the received file before rebooting.
        let fw_msg = reset_request(8, b"SWBA1B0V100D017");
        assert_eq!(fw_msg.elems[0].data, image_identifier(b"SWBA1B0V100D017"));
        assert_eq!(&fw_msg.elems[0].data[..4], &IMAGE_ID_PREFIX.to_be_bytes());
        assert_eq!(*fw_msg.elems[0].data.last().unwrap(), 0);
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

    #[test]
    fn record_carries_isolation_and_broadcast() {
        let record = 28; // after the band header
        let isolate_at = record + 33 + 4 + 33;
        let broadcast_at = isolate_at + 4;
        let mut w = wlan(1, 1, "miniac24");
        w.isolate = true;
        w.broadcast = false;
        let b = encode_default(&[w]);
        let word = |at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        assert_eq!(word(isolate_at), 1);
        assert_eq!(word(broadcast_at), 0);
    }

    #[test]
    fn record_carries_client_limit() {
        let client_at = 28 + 33 + 4 + 33 + 4 + 4;
        let limit = |b: &[u8]| {
            u32::from_be_bytes([
                b[client_at],
                b[client_at + 1],
                b[client_at + 2],
                b[client_at + 3],
            ])
        };
        // 0 in the DB means "no limit", which H3C spells 0xffffffff.
        assert_eq!(limit(&encode_default(&[wlan(1, 1, "miniac24")])), 0xffff_ffff);
        // A configured per-SSID limit rides as-is.
        let mut w = wlan(1, 1, "miniac24");
        w.client_count = 20;
        assert_eq!(limit(&encode_default(&[w])), 20);
        // Values above the AX60 ceiling are clamped on the wire.
        let mut w = wlan(1, 1, "miniac24");
        w.client_count = 64;
        assert_eq!(limit(&encode_default(&[w])), 32);
    }
}
