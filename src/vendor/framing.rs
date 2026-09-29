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
//! with elements at byte 19 and MsgElemLen self-inclusive (elements + 3). All
//! offsets handled here are relative to the control payload that follows the
//! 8-byte base header (i.e. app_data[8..]).

use anyhow::Result;

use crate::capwap::{CtrlHdr, CtrlMsg};

/// Base header echoed from the live AX60 request: version/HLEN 0, control
/// type, Fragment ID 0 and 8-byte length. The AX60 parser addresses fields by
/// offset, so a fixed valid value is enough for responses.
const BASE_HEADER: [u8; 8] = [0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

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
        if buf.len() < self.elem_off() + 1 {
            return Err(anyhow::anyhow!("ctrl header too short"));
        }
        let msg_type = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let seq = match self {
            CtrlFrame::Rfc => buf[4] as u32,
            CtrlFrame::H3c => u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        };
        let elem_len = u16::from_be_bytes([buf[4 + self.seq_len()], buf[5 + self.seq_len()]]);
        let flags = buf[7 + self.seq_len()];
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
        match self {
            CtrlFrame::Rfc => {
                let body_len: usize = msg.elems.iter().map(|e| 4 + e.data.len()).sum();
                let mut out = Vec::with_capacity(8 + body_len);
                out.extend_from_slice(&msg.hdr.msg_type.to_be_bytes());
                out.push((msg.hdr.seq_num & 0xff) as u8);
                out.extend_from_slice(&(body_len as u16).to_be_bytes());
                out.push(msg.hdr.flags);
                append_elems(&mut out, &msg.elems);
                out
            }
            CtrlFrame::H3c => {
                let body_len: usize = msg.elems.iter().map(wire_elem_len_h3c).sum();
                let mut out = Vec::with_capacity(19 + body_len);
                out.extend_from_slice(&BASE_HEADER);
                out.extend_from_slice(&msg.hdr.msg_type.to_be_bytes());
                out.extend_from_slice(&msg.hdr.seq_num.to_be_bytes());
                // MsgElemLen self-inclusive: bytes 16..end = 3 + elements.
                out.extend_from_slice(&((3 + body_len) as u16).to_be_bytes());
                out.push(msg.hdr.flags);
                append_elems_h3c(&mut out, &msg.elems);
                out
            }
        }
    }
}

/// Append elements in t2l2 framing (Type:2 BE, Len:2 BE, value).
fn append_elems(out: &mut Vec<u8>, elems: &[crate::capwap::RawElem]) {
    for e in elems {
        out.extend_from_slice(&e.tag.to_be_bytes());
        out.extend_from_slice(&(e.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&e.data);
    }
}

/// On-wire byte count of one element under H3C framing. The AX60 Result-Code
/// element is a 4-byte value (WTP.dis 0x528b4 reads via 4d5f8 = bcopy4+ntohl),
/// unlike the RFC 1-octet form, so the length must account for that widening.
fn wire_elem_len_h3c(e: &crate::capwap::RawElem) -> usize {
    let data_len = if e.tag == crate::capwap::MsgElemType::RESULT_CODE && e.data.len() == 1 {
        4
    } else {
        e.data.len()
    };
    4 + data_len
}

/// Append elements in H3C t2l2 framing, widening the Result Code element.
fn append_elems_h3c(out: &mut Vec<u8>, elems: &[crate::capwap::RawElem]) {
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
    fn h3c_widens_result_code_to_4_bytes() {
        // A 1-octet RFC Result Code element (Success) must be widened to 4
        // bytes when framed for the H3C AX60, with MsgElemLen reflecting it.
        let msg = CtrlMsg::new(4, 2).with_result(crate::capwap::CwResult::Success);
        let out = CtrlFrame::H3c.frame(&msg);
        // Elements start at byte 19: [tag=33 0x0021][len=4][4-byte value].
        assert_eq!(&out[19..23], &[0x00, 0x21, 0x00, 0x04]);
        assert_eq!(&out[23..27], &[0x00, 0x00, 0x00, 0x00]);
        // MsgElemLen (at offset 16): 3 + one 8-byte element.
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 11);
        // RFC framing (no base header, 8-byte control header) keeps the 1-octet form.
        let rfc = CtrlFrame::Rfc.frame(&msg);
        assert_eq!(&rfc[8..12], &[0x00, 0x21, 0x00, 0x01]);
        assert_eq!(rfc[12], 0x00);
    }
}