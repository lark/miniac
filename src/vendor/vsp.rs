//! Vendor Specific Payload (RFC 5415 4.6.37) codec.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! The element value is a vendor identifier header followed by vendor-private
//! payload. Vendors addressed here (TP-Link AC100) use a
//! `[vendor id u32][reserved u16]` header and then base-framed
//! `[id u16][len u16][value]` private TLVs. Vendors that instead carry private
//! elements as bare top-level tags (H3C) bypass this module.
#![allow(dead_code)] // used by the vendor forms and their unit tests

/// Vendor identifier header size: vendor id plus reserved field.
pub const HEADER_LEN: usize = 6;

/// Split an element-37 value into `(vendor id, reserved, private TLVs)`.
///
/// Returns `None` when the header is short or the TLV chain does not consume
/// the value exactly — a truncated chain is rejected rather than partially
/// kept, so a malformed payload never reaches callers as partially valid.
pub fn split_value(value: &[u8]) -> Option<(u32, u16, Vec<(u16, Vec<u8>)>)> {
    if value.len() < HEADER_LEN {
        return None;
    }
    let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let reserved = u16::from_be_bytes([value[4], value[5]]);

    let mut tlvs = Vec::new();
    let mut rest = &value[HEADER_LEN..];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return None;
        }
        let id = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + len {
            return None;
        }
        tlvs.push((id, rest[4..4 + len].to_vec()));
        rest = &rest[4 + len..];
    }
    Some((vendor_id, reserved, tlvs))
}

/// Join a header and private TLVs into an element-37 value.
pub fn join_value(vendor_id: u32, reserved: u16, tlvs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&vendor_id.to_be_bytes());
    v.extend_from_slice(&reserved.to_be_bytes());
    for (id, value) in tlvs {
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
    }
    v
}

/// Look up a single private TLV value by id.
pub fn find<'a>(tlvs: &'a [(u16, Vec<u8>)], id: u16) -> Option<&'a [u8]> {
    tlvs.iter()
        .find(|(t, _)| *t == id)
        .map(|(_, v)| v.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_private_tlv() {
        let value = join_value(0x1234_5678, 0, &[(35, vec![0, 0, 0, 1])]);
        assert_eq!(
            value,
            vec![0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x23, 0x00, 0x04, 0, 0, 0, 1]
        );
        let (vendor, reserved, tlvs) = split_value(&value).unwrap();
        assert_eq!(vendor, 0x1234_5678);
        assert_eq!(reserved, 0);
        assert_eq!(tlvs, vec![(35u16, vec![0u8, 0, 0, 1])]);
        assert_eq!(find(&tlvs, 35), Some(&[0u8, 0, 0, 1][..]));
        assert_eq!(find(&tlvs, 36), None);
    }

    #[test]
    fn multiple_tlvs_and_empty_chain() {
        let value = join_value(1, 2, &[(5, vec![9]), (61, Vec::new())]);
        let (vendor, reserved, tlvs) = split_value(&value).unwrap();
        assert_eq!((vendor, reserved), (1, 2));
        assert_eq!(tlvs, vec![(5u16, vec![9u8]), (61u16, Vec::new())]);
        // Header only is a valid, empty payload.
        assert_eq!(split_value(&[0; 6]), Some((0, 0, Vec::new())));
    }

    #[test]
    fn malformed_chains_are_rejected() {
        assert_eq!(split_value(&[0; 5]), None);
        let value = join_value(1, 0, &[(35, vec![0, 0, 0, 1])]);
        // Truncated TLV value.
        assert_eq!(split_value(&value[..value.len() - 2]), None);
        // Truncated TLV header (3 leftover bytes).
        let mut bad = value.clone();
        bad.extend_from_slice(&[0, 35, 0]);
        assert_eq!(split_value(&bad), None);
    }
}
