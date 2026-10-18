//! Vendor CAPWAP control framing: where control fields sit relative to the
//! carrier (9 bytes: 8-byte base header + the message content).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! RFC 5415 control messages are
//!   [base header 8B][Message Type 4B][Seq 1B][MsgElemLen 2B][Flags 1B][elements]
//! with elements starting at byte 16. H3C AX60-style WTPs use the same shape
//! for the whole control session (not just discovery) but widen Seq to 4 bytes:
//!   [base header 8B][Message Type 4B][Seq 4B][MsgElemLen 2B][Flags 1B][elements]
//! with elements at byte 19. In both, MsgElemLen counts the bytes that follow
//! the Sequence Number field (RFC 5415 4.5.1.3), i.e. MsgElemLen + Flags +
//! elements = elements + 3; the AX60/M60 and TL-AP1300GI parsers read it that
//! way and subtract 3. All offsets handled here are relative to the control
//! payload that follows the 8-byte base header (i.e. app_data[8..]).

use anyhow::Result;

use crate::capwap::{CtrlHdr, CtrlMsg};

/// Base header echoed from the live AX60 request: version/HLEN 0, control
/// type, Fragment ID 0 and 8-byte length. The AX60 parser addresses fields by
/// offset, so a fixed valid value is enough for responses.
const BASE_HEADER: [u8; 8] = [0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

/// RFC 5415 transport header. TP-Link AC100's defaults
/// (`cw_ac_create_parsed_pkt` 0x4C0268, packed by `cw_header_assemble`
/// 0x4CE158): Version 0, Type 0, HLEN 2 (8-byte header, so elements follow at
/// offset 16), RID 0, WBID 1, T 1.
const BASE_HEADER_RFC: [u8; 8] = [0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtrlFrame {
    /// RFC 5415: 1-byte Seq; elements follow the 8-byte control header.
    Rfc,
    /// H3C AX60: 4-byte Seq; elements follow an 11-byte control region.
    H3c,
}

impl CtrlFrame {
    /// Width of the Seq field (1 byte RFC, 4 bytes H3C).
    pub fn seq_len(self) -> usize {
        match self {
            CtrlFrame::Rfc => 1,
            CtrlFrame::H3c => 4,
        }
    }

    /// Byte offset of the first element inside the control payload (the
    /// content after the 8-byte base header): Message Type(4) + Seq + MsgElemLen(2)
    /// + Flags(1).
    pub fn elem_off(self) -> usize {
        7 + self.seq_len()
    }

    /// Parse the control header from `buf`, the payload after the 8-byte base
    /// header (app_data[8..]). RFC and H3C share Message Type, then diverge on
    /// Seq width.
    pub fn parse_hdr(self, buf: &[u8]) -> Result<CtrlHdr> {
        // The control header occupies exactly `elem_off` bytes (Message Type +
        // Seq + MsgElemLen + Flags); a zero-element message is still valid and
        // is only that long (the AX60 Run-state 19B ECHO_REQ keepalive).
        if buf.len() < self.elem_off() {
            return Err(anyhow::anyhow!("ctrl header too short"));
        }
        let msg_type = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let seq = match self {
            CtrlFrame::Rfc => buf[4] as u32,
            CtrlFrame::H3c => u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        };
        let elem_len = u16::from_be_bytes([buf[4 + self.seq_len()], buf[5 + self.seq_len()]]);
        // Flags is the last control-header byte (offset 6 + seq_len); the old
        // `7 + seq_len` index read the first element's tag high byte instead
        // (masked only by tags whose high byte is 0x00).
        let flags = buf[6 + self.seq_len()];
        Ok(CtrlHdr {
            msg_type,
            seq_num: seq,
            elem_len,
            flags,
        })
    }

    /// Serialize a control message back to wire bytes (including the 8-byte
    /// base header) for transmission.
    pub fn frame(self, msg: &CtrlMsg) -> Vec<u8> {
        let body_len: usize = msg.elems.iter().map(wire_elem_len).sum();
        match self {
            CtrlFrame::Rfc => {
                let mut out = Vec::with_capacity(19 + body_len);
                out.extend_from_slice(&BASE_HEADER_RFC);
                out.extend_from_slice(&msg.hdr.msg_type.to_be_bytes());
                out.push((msg.hdr.seq_num & 0xff) as u8);
                // MsgElemLen counts the bytes after the Sequence Number field
                // (RFC 5415 4.5.1.3): its own 2 bytes + Flags + elements.
                out.extend_from_slice(&((3 + body_len) as u16).to_be_bytes());
                out.push(msg.hdr.flags);
                append_elems(&mut out, &msg.elems);
                out
            }
            CtrlFrame::H3c => {
                let mut out = Vec::with_capacity(19 + body_len);
                out.extend_from_slice(&BASE_HEADER);
                out.extend_from_slice(&msg.hdr.msg_type.to_be_bytes());
                out.extend_from_slice(&msg.hdr.seq_num.to_be_bytes());
                // MsgElemLen self-inclusive: bytes 16..end = 3 + elements.
                out.extend_from_slice(&((3 + body_len) as u16).to_be_bytes());
                out.push(msg.hdr.flags);
                append_elems(&mut out, &msg.elems);
                out
            }
        }
    }
}

/// Append elements in t2l2 framing (Type:2 BE, Len:2 BE, value), widening the
/// Result Code to the 4-byte form of RFC 5415 4.6.35.
fn append_elems(out: &mut Vec<u8>, elems: &[crate::capwap::RawElem]) {
    for e in elems {
        out.extend_from_slice(&e.tag.to_be_bytes());
        if e.tag == crate::capwap::MsgElemType::RESULT_CODE && e.data.len() == 1 {
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&(e.data[0] as u32).to_be_bytes());
        } else {
            out.extend_from_slice(&(e.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&e.data);
        }
    }
}

/// On-wire byte count of one element. The AX60/M60 and TL-AP1300GI Result-Code
/// parsers read a 32-bit value (WTP.dis 0x528b4; TL-AP1300GI CWParseResultCode),
/// unlike the 1-octet form `CtrlMsg` keeps in memory, so encoding must account
/// for that widening.
fn wire_elem_len(e: &crate::capwap::RawElem) -> usize {
    let data_len = if e.tag == crate::capwap::MsgElemType::RESULT_CODE && e.data.len() == 1 {
        4
    } else {
        e.data.len()
    };
    4 + data_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capwap::CtrlMsg;

    /// The confirmed AX60 JoinRequest control payload (= app_data[8..]):
    /// msg_type 3, 4-byte seq 2, MsgElemLen self-inclusive, then elements.
    #[rustfmt::skip]
    const JOIN: &[u8] = &[
        0x00, 0x00, 0x00, 0x03, // Message Type: Join Request
        0x00, 0x00, 0x00, 0x02, // Seq 4 bytes
        0x00, 0x19,             // MsgElemLen: 0x19 = elements + 3
        0x00,                   // Flags
        0x00, 0x1c, 0x00, 0x15, // element: LOCATION_DATA (28), len 21
        b'N', b'e', b'x', b't', b' ', b't', b'o', b' ', b'F', b'r', b'i', b'd', b'g', b'e', b' ', b'x', b'x', b'x', b'x', b'x', b' ',
    ];

    #[test]
    fn parses_h3c_join_header_offsets() {
        let hdr = CtrlFrame::H3c.parse_hdr(&JOIN).expect("parse");
        // msg_type and seq sit at [0..4]/[4..8] of the control payload, so the
        // old RFC reader (which assumed msg_type at byte 8) must not fire.
        assert_eq!(hdr.msg_type, 3);
        assert_eq!(hdr.seq_num, 2);
        assert_eq!(hdr.elem_len, 0x19);
        assert_eq!(hdr.flags, 0);
        // Elements begin at byte 11 of the control payload (16 in app_data).
        assert_eq!(CtrlFrame::H3c.elem_off(), 11);
    }

    #[test]
    fn h3c_parses_zero_element_keepalive() {
        // 11-byte control payload (msg_type + 4-byte seq + MsgElemLen + flags)
        // with no elements: the AX60 Run-state 19B ECHO_REQ keepalive shape.
        let echo = [
            0x00, 0x00, 0x00, 0x0d, // Message Type: Echo Request
            0x00, 0x00, 0x01, 0x77, // Seq 375
            0x00, 0x03,             // MsgElemLen: self-inclusive 3 = no elements
            0x00,                   // Flags
        ];
        let hdr = CtrlFrame::H3c.parse_hdr(&echo).expect("parse");
        assert_eq!(hdr.msg_type, 13);
        assert_eq!(hdr.seq_num, 375);
        assert_eq!(hdr.elem_len, 3);
        assert_eq!(hdr.flags, 0);
    }

    #[test]
    fn h3c_frame_roundtrip() {
        let msg = CtrlMsg::new(4, 2) // Join Response, seq 2
            .add_elem(0x0001, &[0u8; 4]);
        let out = CtrlFrame::H3c.frame(&msg);
        // 8-byte base header precedes the control region.
        assert_eq!(&out[0..8], &BASE_HEADER);
        // msg_type, then 4-byte seq.
        assert_eq!(&out[8..12], &[0, 0, 0, 4]);
        assert_eq!(&out[12..16], &[0, 0, 0, 2]);
        // MsgElemLen self-inclusive: 3 + (4 + 4 element bytes).
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 11);
        // Elements start at byte 19.
        assert_eq!(&out[19..], &[0, 1, 0, 4, 0, 0, 0, 0]);
        // Roundtrip: feed the control region (after the base header) back.
        let back = CtrlMsg::decode(CtrlFrame::H3c, &out[8..]).expect("decode");
        assert_eq!(back.hdr.msg_type, 4);
        assert_eq!(back.hdr.seq_num, 2);
        assert_eq!(back.elems.len(), 1);
    }

    #[test]
    fn result_code_is_four_bytes_in_both_frames() {
        // A 1-octet RFC Result Code element (Success) must be widened to the
        // 4-byte value of RFC 5415 4.6.35 on the wire, with MsgElemLen
        // reflecting it.
        let msg = CtrlMsg::new(4, 2).with_result(crate::capwap::CwResult::Success);
        let out = CtrlFrame::H3c.frame(&msg);
        // Elements start at byte 19: [tag=33 0x0021][len=4][4-byte value].
        assert_eq!(&out[19..23], &[0x00, 0x21, 0x00, 0x04]);
        assert_eq!(&out[23..27], &[0x00, 0x00, 0x00, 0x00]);
        // MsgElemLen (at offset 16): 3 + one 8-byte element.
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 11);
        // RFC framing: 8-byte base header, then Seq(1) / MsgElemLen(2) / Flags(1)
        // and the same 4-byte Result Code at offset 16.
        let rfc = CtrlFrame::Rfc.frame(&msg);
        assert_eq!(&rfc[0..8], &BASE_HEADER_RFC);
        assert_eq!(&rfc[8..12], &[0x00, 0x00, 0x00, 0x04]);
        assert_eq!(&rfc[16..20], &[0x00, 0x21, 0x00, 0x04]);
        assert_eq!(&rfc[20..24], &[0x00, 0x00, 0x00, 0x00]);
        // MsgElemLen counts from the Sequence Number field onward: 3 + 8.
        assert_eq!(u16::from_be_bytes([rfc[13], rfc[14]]), 11);
    }

    #[test]
    fn rfc_msg_elem_len_is_self_inclusive() {
        // A message with no elements is still 3 bytes past the Sequence Number.
        let msg = CtrlMsg::new(13, 5);
        let out = CtrlFrame::Rfc.frame(&msg);
        assert_eq!(&out[12..16], &[5, 0, 3, 0]);
        // One 4-byte element: 3 + (4 + 4) = 11, elements start at offset 16.
        let msg = CtrlMsg::new(14, 7).add_elem(0x0001, &[0u8; 4]);
        let out = CtrlFrame::Rfc.frame(&msg);
        assert_eq!(u16::from_be_bytes([out[13], out[14]]), 11);
        assert_eq!(out.len(), 16 + 8);
        assert_eq!(&out[16..], &[0, 1, 0, 4, 0, 0, 0, 0]);
    }
}