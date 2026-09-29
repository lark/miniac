//! H3C customized CAPWAP framing support.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Based on the observation of H3C AX60 behavior, should work with other H3C
//! devices.
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

use std::net::Ipv4Addr;

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

/// RFC 5415 4.6.1 AC Descriptor for Join/Discovery responses: 12-byte base
/// plus the two mandatory AC Information sub-elements (Hardware and Software
/// Version, vendor id 0). Shared so the WTP sees a consistent descriptor.
pub fn ac_descriptor(hw: &str, sw: &str) -> Vec<u8> {
    // Stations(2) + Limit(2): 0 / 1024
    // Active WTPs(2) + Max WTPs(2): 0 / 32
    // Security(1): R bit (0x01) of the S|X|R mask. The AX60 branches on this
    // byte at WTP.dis 0x223c4: ==1 passes the real certificate paths to DTLS
    // init, !=1 passes NULL and crashes.
    // R-MAC Field(1): 1 = supported
    // Reserved(1): 0
    // DTLS Policy(1): clear-text data bit of the D|C|R mask (0x02)
    let mut v = Vec::with_capacity(12 + 20);
    v.extend_from_slice(&[
        0x00, 0x00, 0x04, 0x00, //
        0x00, 0x00, 0x00, 0x20, //
        0x01, 0x01, 0x00, 0x02,
    ]);
    // AC Information sub-elements: Vendor id(4) + Type(2) + Len(2) + data.
    // Type 4 = Hardware Version, Type 5 = Software Version (RFC 5415 4.6.1).
    for (ty, ver) in [(4u16, hw), (5u16, sw)] {
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&(ver.len() as u16).to_be_bytes());
        v.extend_from_slice(ver.as_bytes());
    }
    v
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
}
