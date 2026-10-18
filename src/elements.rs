//! Structured encode/decode layer for CAPWAP base message elements.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Provides a typed `BaseElem` view and bidirectional conversion with
//! `(tag, value)`, so callers build requests/responses with strong typing
//! instead of hand-assembling raw bytes. Element numbers and wire order
//! follow RFC 5415 section 4.6 (network / big-endian order).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::capwap::MsgElemType;

/// Structured Image Identifier element (RFC 5415 4.6.25): a vendor identifier
/// followed by the image name. Vendors differ on the name terminator, so it is
/// the caller's choice: the H3C AX60 parser forces the last value byte to NUL
/// (name must be NUL-terminated) while the TP-Link AC100 keeps the raw length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageIdentifier {
    pub vendor_id: u32,
    pub name: Vec<u8>,
}

impl ImageIdentifier {
    pub fn new(vendor_id: u32, name: impl Into<Vec<u8>>) -> Self {
        ImageIdentifier {
            vendor_id,
            name: name.into(),
        }
    }

    /// Element value = `[vendor id u32 BE][name]`. `terminate` appends a NUL.
    pub fn encode(&self, terminate: bool) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.name.len() + 1);
        v.extend_from_slice(&self.vendor_id.to_be_bytes());
        v.extend_from_slice(&self.name);
        if terminate {
            v.push(0);
        }
        v
    }

    /// Decode an element value; the trailing NUL (if any) is stripped.
    pub fn decode(value: &[u8]) -> Option<Self> {
        if value.len() < 4 {
            return None;
        }
        let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let name = value[4..].to_vec();
        Some(ImageIdentifier {
            vendor_id,
            name: name.strip_suffix(&[0]).map(|b| b.to_vec()).unwrap_or(name),
        })
    }
}

/// A typed CAPWAP base message element.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // most variants are constructed as higher milestones land
pub enum BaseElem {
    /// Result Code (33). RFC 5415 4.6.35 defines a 32-bit value; the in-memory
    /// form keeps the low octet and the encoder widens it to 4 bytes.
    ResultCode(u8),
    /// Discovery Type (20), 1 byte.
    DiscoveryType(u8),
    /// AC Name (4), 0..255 byte name; trailing 0x00 may be omitted.
    AcName(Vec<u8>),
    /// AC Name with Priority (5).
    AcNameWithPriority { name: Vec<u8>, priority: u8 },
    /// CAPWAP Timers (12): Discovery(sec) + Echo(sec), 1 byte each.
    CapwapTimers {
        disc_interval_secs: u8,
        echo_interval_secs: u8,
    },
    /// Radio Administrative State (31): RadioID + AdminState(1=enabled,2=disabled).
    RadioAdminState { radio_id: u8, admin_state: u8 },
    /// Radio Operational State (32): RadioID + State + Cause.
    RadioOpState { radio_id: u8, state: u8, cause: u8 },
    /// Idle Timeout (23), u32 seconds.
    IdleTimeout(u32),
    /// ECN Support (53), 1 byte (1=support).
    EcnSupport(u8),
    /// WTP Fallback (40), 1 byte (1=enabled,2=disabled).
    WtpFallback(u8),
    /// Session ID (35), 8 bytes.
    SessionId(u64),
    /// Maximum Message Length (29), u32.
    MaxMessageLen(u32),
    /// Statistics Timer (36), u16 seconds.
    StatsTimer(u16),
    /// AC Timestamp (6), u32 Unix seconds.
    AcTimestamp(u32),
    /// WTP Name (45), string.
    WtpName(Vec<u8>),
    /// Location Data (28), 0..255 byte string.
    LocationData(Vec<u8>),
    /// Image Identifier (25) as a raw value (kept for verbatim pass-through).
    ImageId(Vec<u8>),
    /// Image Identifier (25), structured as vendor id + name.
    ImageIdentifier(ImageIdentifier),
    /// AC IPv4 List (2): `[count u8][IPv4 addresses]`.
    AcIpv4List(Vec<Ipv4Addr>),
    /// AC IPv6 List (3): `[count u8][IPv6 addresses]`.
    AcIpv6List(Vec<Ipv6Addr>),
    /// Decrypt Error Report Period (16), u32 seconds.
    DecryptErrReportPeriod(u32),
    /// Vendor Specific Payload (37): `[vendor id u32][reserved u16][private TLVs]`.
    /// The private TLVs use the base `[id u16][len u16][value]` framing. Vendors
    /// that carry private elements as bare top-level tags (H3C) do not use this.
    VendorSpecific {
        vendor_id: u32,
        reserved: u16,
        tlvs: Vec<(u16, Vec<u8>)>,
    },
    /// Initiate Download (27), u32 (0 to terminate).
    InitDownload(u32),
    /// Add Station (8): MAC(6) + WLAN ID(1).
    AddStation { mac: [u8; 6], wlan_id: u8 },
    /// Delete Station (18), 6-byte MAC.
    DeleteStation([u8; 6]),
    /// Unrecognized / unmodeled element, kept verbatim.
    Unknown(u16, Vec<u8>),
}

impl BaseElem {
    /// Decode a single element from its `(tag, value)`.
    pub fn decode(tag: u16, value: &[u8]) -> Self {
        match tag {
            // RFC 5415 4.6.35 carries Result Code as a 32-bit value; the older
            // 1-octet form is still seen on some WTPs, so accept both and keep
            // the low octet in memory.
            MsgElemType::RESULT_CODE if value.len() == 4 => BaseElem::ResultCode(value[3]),
            MsgElemType::RESULT_CODE if value.len() == 1 => BaseElem::ResultCode(value[0]),
            MsgElemType::DISC_TYPE if value.len() == 1 => BaseElem::DiscoveryType(value[0]),
            MsgElemType::AC_NAME => BaseElem::AcName(value.to_vec()),
            MsgElemType::AC_NAME_WITH_PRIORITY if value.len() >= 1 => {
                BaseElem::AcNameWithPriority {
                    name: value[..value.len() - 1].to_vec(),
                    priority: value[value.len() - 1],
                }
            }
            MsgElemType::CAPWAP_TIMERS if value.len() == 2 => BaseElem::CapwapTimers {
                disc_interval_secs: value[0],
                echo_interval_secs: value[1],
            },
            MsgElemType::RADIO_ADMIN_STATE if value.len() == 2 => BaseElem::RadioAdminState {
                radio_id: value[0],
                admin_state: value[1],
            },
            MsgElemType::RADIO_OP_STATE if value.len() == 3 => BaseElem::RadioOpState {
                radio_id: value[0],
                state: value[1],
                cause: value[2],
            },
            MsgElemType::IDLE_TIMEOUT if value.len() == 4 => {
                BaseElem::IdleTimeout(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            MsgElemType::ECN_SUPPORT if value.len() == 1 => BaseElem::EcnSupport(value[0]),
            MsgElemType::WTP_FALLBACK if value.len() == 1 => BaseElem::WtpFallback(value[0]),
            MsgElemType::SESSION_ID if value.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(value);
                BaseElem::SessionId(u64::from_be_bytes(b))
            }
            MsgElemType::MAX_MESSAGE_LEN if value.len() == 4 => {
                BaseElem::MaxMessageLen(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ]))
            }
            MsgElemType::STATS_TIMER if value.len() == 2 => {
                BaseElem::StatsTimer(u16::from_be_bytes([value[0], value[1]]))
            }
            MsgElemType::AC_TIMESTAMP if value.len() == 4 => {
                BaseElem::AcTimestamp(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            MsgElemType::WTP_NAME => BaseElem::WtpName(value.to_vec()),
            MsgElemType::LOCATION_DATA => BaseElem::LocationData(value.to_vec()),
            // Image Identifier is decoded verbatim: whether the name is NUL
            // terminated is vendor specific, so `ImageIdentifier` is a
            // build-side convenience only (use `ImageIdentifier::decode`).
            MsgElemType::IMAGE_ID => BaseElem::ImageId(value.to_vec()),
            // AC IPv4 List: 1-byte count followed by that many 4-byte addresses.
            MsgElemType::AC_IPV4_LIST if value.len() == 1 + 4 * value[0] as usize => {
                BaseElem::AcIpv4List(
                    value[1..]
                        .chunks_exact(4)
                        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                        .collect(),
                )
            }
            MsgElemType::AC_IPV6_LIST if value.len() == 1 + 16 * value[0] as usize => {
                BaseElem::AcIpv6List(
                    value[1..]
                        .chunks_exact(16)
                        .map(|c| {
                            let mut a = [0u8; 16];
                            a.copy_from_slice(c);
                            Ipv6Addr::from(a)
                        })
                        .collect(),
                )
            }
            MsgElemType::DECRYPT_ERR_REPORT_PERIOD if value.len() == 4 => {
                BaseElem::DecryptErrReportPeriod(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ]))
            }
            MsgElemType::VENDOR_SPECIFIC_PAYLOAD => match crate::vendor::vsp::split_value(value) {
                Some((vendor_id, reserved, tlvs)) => BaseElem::VendorSpecific {
                    vendor_id,
                    reserved,
                    tlvs,
                },
                None => BaseElem::Unknown(tag, value.to_vec()),
            },
            MsgElemType::INIT_DOWNLOAD if value.len() == 4 => {
                BaseElem::InitDownload(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            MsgElemType::ADD_STATION if value.len() >= 7 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&value[..6]);
                BaseElem::AddStation {
                    mac,
                    wlan_id: value[6],
                }
            }
            MsgElemType::DEL_STATION if value.len() == 6 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(value);
                BaseElem::DeleteStation(mac)
            }
            _ => BaseElem::Unknown(tag, value.to_vec()),
        }
    }

    /// Encode to `(tag, value)` for appending into a message body.
    pub fn encode(&self) -> (u16, Vec<u8>) {
        match self {
            BaseElem::ResultCode(v) => (MsgElemType::RESULT_CODE, vec![*v]),
            BaseElem::DiscoveryType(v) => (MsgElemType::DISC_TYPE, vec![*v]),
            BaseElem::AcName(n) => (MsgElemType::AC_NAME, n.clone()),
            BaseElem::AcNameWithPriority { name, priority } => {
                let mut v = name.clone();
                v.push(*priority);
                (MsgElemType::AC_NAME_WITH_PRIORITY, v)
            }
            BaseElem::CapwapTimers {
                disc_interval_secs,
                echo_interval_secs,
            } => (
                MsgElemType::CAPWAP_TIMERS,
                vec![*disc_interval_secs, *echo_interval_secs],
            ),
            BaseElem::RadioAdminState {
                radio_id,
                admin_state,
            } => (
                MsgElemType::RADIO_ADMIN_STATE,
                vec![*radio_id, *admin_state],
            ),
            BaseElem::RadioOpState {
                radio_id,
                state,
                cause,
            } => (MsgElemType::RADIO_OP_STATE, vec![*radio_id, *state, *cause]),
            BaseElem::IdleTimeout(s) => (MsgElemType::IDLE_TIMEOUT, s.to_be_bytes().to_vec()),
            BaseElem::EcnSupport(v) => (MsgElemType::ECN_SUPPORT, vec![*v]),
            BaseElem::WtpFallback(v) => (MsgElemType::WTP_FALLBACK, vec![*v]),
            BaseElem::SessionId(v) => (MsgElemType::SESSION_ID, v.to_be_bytes().to_vec()),
            BaseElem::MaxMessageLen(v) => (MsgElemType::MAX_MESSAGE_LEN, v.to_be_bytes().to_vec()),
            BaseElem::StatsTimer(v) => (MsgElemType::STATS_TIMER, v.to_be_bytes().to_vec()),
            BaseElem::AcTimestamp(v) => (MsgElemType::AC_TIMESTAMP, v.to_be_bytes().to_vec()),
            BaseElem::WtpName(n) => (MsgElemType::WTP_NAME, n.clone()),
            BaseElem::LocationData(l) => (MsgElemType::LOCATION_DATA, l.clone()),
            BaseElem::ImageId(i) => (MsgElemType::IMAGE_ID, i.clone()),
            // Generic encoder emits the RFC form (no forced NUL); vendors that
            // require termination should call `ImageIdentifier::encode(true)`.
            BaseElem::ImageIdentifier(id) => (MsgElemType::IMAGE_ID, id.encode(false)),
            BaseElem::AcIpv4List(list) => {
                let mut v = Vec::with_capacity(1 + 4 * list.len());
                v.push(list.len() as u8);
                for ip in list {
                    v.extend_from_slice(&ip.octets());
                }
                (MsgElemType::AC_IPV4_LIST, v)
            }
            BaseElem::AcIpv6List(list) => {
                let mut v = Vec::with_capacity(1 + 16 * list.len());
                v.push(list.len() as u8);
                for ip in list {
                    v.extend_from_slice(&ip.octets());
                }
                (MsgElemType::AC_IPV6_LIST, v)
            }
            BaseElem::DecryptErrReportPeriod(p) => {
                (MsgElemType::DECRYPT_ERR_REPORT_PERIOD, p.to_be_bytes().to_vec())
            }
            BaseElem::VendorSpecific {
                vendor_id,
                reserved,
                tlvs,
            } => (
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
                crate::vendor::vsp::join_value(*vendor_id, *reserved, tlvs),
            ),
            BaseElem::InitDownload(v) => (MsgElemType::INIT_DOWNLOAD, v.to_be_bytes().to_vec()),
            BaseElem::AddStation { mac, wlan_id } => {
                let mut v = Vec::with_capacity(7);
                v.extend_from_slice(mac);
                v.push(*wlan_id);
                (MsgElemType::ADD_STATION, v)
            }
            BaseElem::DeleteStation(mac) => (MsgElemType::DEL_STATION, mac.to_vec()),
            BaseElem::Unknown(tag, v) => (*tag, v.clone()),
        }
    }
}

/// WTP Board Data sub-element type codes (RFC 5415 4.6.40).
pub mod board_data {
    /// 0 - WTP Model Number (mandatory).
    pub const MODEL_NUMBER: u16 = 0;
    /// 1 - WTP Serial Number (mandatory).
    pub const SERIAL_NUMBER: u16 = 1;
    /// 2 - Board ID.
    pub const BOARD_ID: u16 = 2;
    /// 3 - Board Revision.
    pub const BOARD_REVISION: u16 = 3;
    /// 4 - Base MAC Address.
    pub const BASE_MAC: u16 = 4;
}

/// Decoded WTP Board Data element value (RFC 5415 4.6.40): a vendor identifier
/// followed by `[type u16][len u16][value]` board data sub-elements.
///
/// The sub-element type codes are fixed by the RFC and are not extensible by
/// vendors, so a WTP that reports its MAC here uses the standardized Base MAC
/// Address entry (type 4). Reading a fixed offset off the element head instead
/// picks up the vendor identifier and the first sub-element's type/length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtpBoardData {
    pub vendor_id: u32,
    pub sub_elems: Vec<(u16, Vec<u8>)>,
}

impl WtpBoardData {
    /// Decode an element-38 value. `None` when the value is off the RFC shape:
    /// shorter than the vendor identifier, or a sub-element chain that does not
    /// consume the value exactly.
    pub fn decode(value: &[u8]) -> Option<Self> {
        if value.len() < 4 {
            return None;
        }
        let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let mut sub_elems = Vec::new();
        let mut rest = &value[4..];
        while !rest.is_empty() {
            if rest.len() < 4 {
                return None;
            }
            let sub_type = u16::from_be_bytes([rest[0], rest[1]]);
            let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            if rest.len() < 4 + len {
                return None;
            }
            sub_elems.push((sub_type, rest[4..4 + len].to_vec()));
            rest = &rest[4 + len..];
        }
        Some(WtpBoardData {
            vendor_id,
            sub_elems,
        })
    }

    /// The Base MAC Address sub-element (type 4), which the RFC lets a WTP
    /// report as the address of its primary Ethernet interface. Requires the
    /// canonical 6-byte value.
    pub fn base_mac(&self) -> Option<[u8; 6]> {
        let (_, value) = self
            .sub_elems
            .iter()
            .find(|(t, _)| *t == board_data::BASE_MAC)?;
        if value.len() != 6 {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(value);
        Some(mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(e: BaseElem) -> BaseElem {
        let (tag, v) = e.encode();
        BaseElem::decode(tag, &v)
    }

    #[test]
    fn result_and_timers() {
        assert_eq!(round_trip(BaseElem::ResultCode(0)), BaseElem::ResultCode(0));
        assert_eq!(
            round_trip(BaseElem::CapwapTimers {
                disc_interval_secs: 20,
                echo_interval_secs: 60
            }),
            BaseElem::CapwapTimers {
                disc_interval_secs: 20,
                echo_interval_secs: 60
            }
        );
    }

    #[test]
    fn radio_states() {
        assert_eq!(
            round_trip(BaseElem::RadioAdminState {
                radio_id: 1,
                admin_state: 1
            }),
            BaseElem::RadioAdminState {
                radio_id: 1,
                admin_state: 1
            }
        );
        let op = BaseElem::RadioOpState {
            radio_id: 2,
            state: 1,
            cause: 0,
        };
        let (tag, v) = op.encode();
        assert_eq!(v.len(), 3);
        assert_eq!(BaseElem::decode(tag, &v), op);
    }

    #[test]
    fn ac_name_and_priority() {
        assert_eq!(
            round_trip(BaseElem::AcName(b"miniac".to_vec())),
            BaseElem::AcName(b"miniac".to_vec())
        );
        let e = BaseElem::AcNameWithPriority {
            name: b"ac1".to_vec(),
            priority: 1,
        };
        let (tag, v) = e.encode();
        assert_eq!(v, b"ac1\x01");
        assert_eq!(BaseElem::decode(tag, &v), e);
    }

    #[test]
    fn station() {
        let add = BaseElem::AddStation {
            mac: [0x00; 6],
            wlan_id: 1,
        };
        let (tag, v) = add.encode();
        assert_eq!(v.len(), 7);
        assert_eq!(BaseElem::decode(tag, &v), add);

        let del = BaseElem::DeleteStation([1, 2, 3, 4, 5, 6]);
        assert_eq!(round_trip(del.clone()), del);
    }

    #[test]
    fn wtp_board_data_base_mac() {
        // Live TL-AP1300GI Join Request element 38 (42-byte value): vendor id
        // 0x12345678, then Model Number, Serial Number and Base MAC Address.
        let mut value = vec![0x12, 0x34, 0x56, 0x78];
        value.extend_from_slice(&[0, 0, 0, 4, 0x13, 0x00, 0x8e, 0x02]);
        value.extend_from_slice(&[0, 1, 0, 16]);
        value.extend_from_slice(b"0000808f1d8dafa7");
        value.extend_from_slice(&[0, 4, 0, 6, 0x80, 0x8f, 0x1d, 0x8d, 0xaf, 0xa7]);
        assert_eq!(value.len(), 42);

        let bd = WtpBoardData::decode(&value).unwrap();
        assert_eq!(bd.vendor_id, 0x1234_5678);
        assert_eq!(
            bd.sub_elems,
            vec![
                (board_data::MODEL_NUMBER, vec![0x13, 0x00, 0x8e, 0x02]),
                (board_data::SERIAL_NUMBER, b"0000808f1d8dafa7".to_vec()),
                (board_data::BASE_MAC, vec![0x80, 0x8f, 0x1d, 0x8d, 0xaf, 0xa7]),
            ]
        );
        assert_eq!(bd.base_mac(), Some([0x80, 0x8f, 0x1d, 0x8d, 0xaf, 0xa7]));
    }

    #[test]
    fn wtp_board_data_rejects_non_rfc_shapes() {
        // A truncated vendor identifier.
        assert!(WtpBoardData::decode(&[0x12, 0x34, 0x56]).is_none());
        // A sub-element whose declared length runs past the value.
        let mut truncated = vec![0x12, 0x34, 0x56, 0x78];
        truncated.extend_from_slice(&[0, 4, 0, 6, 0x80, 0x8f]);
        assert!(WtpBoardData::decode(&truncated).is_none());
        // A vendor identifier alone is a well-formed (if empty) chain, but it
        // carries no board MAC.
        let empty = WtpBoardData::decode(&[0x12, 0x34, 0x56, 0x78]).unwrap();
        assert!(empty.sub_elems.is_empty());
        assert!(empty.base_mac().is_none());
        // A Base MAC sub-element with a non-canonical length is not a MAC.
        let mut short_mac = vec![0x12, 0x34, 0x56, 0x78];
        short_mac.extend_from_slice(&[0, 4, 0, 4, 0x80, 0x8f, 0x1d, 0x8d]);
        assert_eq!(WtpBoardData::decode(&short_mac).unwrap().base_mac(), None);
    }
}
