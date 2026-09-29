//! Structured encode/decode layer for CAPWAP base message elements.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Provides a typed `BaseElem` view and bidirectional conversion with
//! `(tag, value)`, so callers build requests/responses with strong typing
//! instead of hand-assembling raw bytes. Element numbers and wire order
//! follow RFC 5415 section 4.6 (network / big-endian order).

use crate::capwap::MsgElemType;

/// A typed CAPWAP base message element.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // most variants are constructed as higher milestones land
pub enum BaseElem {
    /// Result Code (33), 1 byte.
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
    /// Image Identifier (25), string.
    ImageId(Vec<u8>),
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
            MsgElemType::IMAGE_ID => BaseElem::ImageId(value.to_vec()),
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
}
