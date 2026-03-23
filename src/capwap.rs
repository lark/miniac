use anyhow::{anyhow, Result};
use std::time::{Instant, Duration};
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::collections::{HashMap, HashSet};
use dashmap::DashMap;

pub struct CtrlHdr {
    pub msg_type: u32,
    pub seq_num: u8,
    pub elem_len: u16,
    pub flags: u8,
}

pub struct RawElem {
    pub tag: u16,
    pub data: Vec<u8>,
}

pub struct CtrlMsg {
    pub hdr: CtrlHdr,
    pub elems: Vec<RawElem>,
}

#[allow(unused)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WtpState {
    Sulking,
    Discovery,
    DtlsSetup,
    Join,
    Configure,
    DataCheck,
    Run,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Wlan {
    pub wlan_id: u8,
    pub ssid: String,
    pub enabled: bool,
    pub bssid: [u8; 6],
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Radio {
    pub id: u8,
    pub radio_type: u8,
    pub admin_state: u8,
    pub wlans: Vec<Wlan>,
}

pub struct LastSentInfo {
    pub buf: Vec<u8>,
    pub seq: u8,
    pub msg_type: u32,
    pub send_time: Instant,
    pub retry_count: u32,
}

#[allow(unused)]
pub struct WtpContext {
    pub wtp_id: Vec<u8>,
    pub name: String,
    pub description: String,

    pub state: WtpState,

    pub hardware_version: u32,
    pub software_version: u32,
    pub boot_version: u32,

    pub radios: Vec<Radio>,

    pub led_enabled: bool,
    pub session_id: u64,
    pub last_seen: Instant,
    pub last_sent: Option<LastSentInfo>,

    pub echo_interval: Duration,
    pub retrans_interval: Duration,
    pub max_retries: u32,

    pub seq_counter: u8,
}

#[allow(unused)]
pub struct AcState {
    pub wtps: DashMap<SocketAddr, WtpContext>,
}

impl CtrlHdr {
    pub const SIZE: usize = 8;

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(anyhow::anyhow!("hdr too short"));
        }
        Ok(Self {
            msg_type: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            seq_num: buf[4],
            elem_len: u16::from_be_bytes([buf[5], buf[6]]),
            flags: buf[7],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.push(self.seq_num);
        buf.extend_from_slice(&self.elem_len.to_be_bytes());
        buf.push(self.flags);

        buf
    }
}

#[allow(unused)]
impl CtrlMsg {
    pub fn new(m_type: u32, seq: u8) -> Self {
        Self {
            hdr: CtrlHdr {
                msg_type: m_type,
                seq_num: seq,
                elem_len: 0,
                flags: 0,
            },
            elems: Vec::new(),
        }
    }

    pub fn add_elem(mut self, tag: u16, val: &[u8]) -> Self {
        self.elems.push(RawElem { tag, data: val.to_vec(), });
        self.hdr.elem_len += (4 + val.len()) as u16;
        self
    }

    pub fn with_result_success(self) -> Self {
        self.add_elem(MsgElemType::RESULT_CODE, &[CwResult::Success as u8])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.hdr.encode();

        buf.reserve(self.hdr.elem_len as usize);

        for elem in &self.elems {
            buf.extend_from_slice(&elem.tag.to_be_bytes()); // type, u16
            buf.extend_from_slice(&(elem.data.len() as u16).to_be_bytes()); // length, u16
            buf.extend_from_slice(&elem.data); // value
        }

        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let hdr = CtrlHdr::decode(buf)?;
        let hdr_len = 8;
        let body_len = hdr.elem_len as usize;

        if buf.len() < hdr_len + body_len {
            return Err(anyhow!("truncated"));
        }

        let mut elems = Vec::new();
        let mut pos = hdr_len;
        while pos + 4 <= hdr_len + body_len {
            let tag = u16::from_be_bytes([buf[pos], buf[pos+1]]);
            let len = u16::from_be_bytes([buf[pos+2], buf[pos+3]]) as usize;
            pos += 4;

            let end = pos + len;
            if end > buf.len() { break; }

            elems.push(RawElem {
                tag,
                data: buf[pos..end].to_vec(),
            });
            pos = end;
        }

        Ok(Self { hdr, elems })
    }

    pub fn find_elems(&self, tag: u16) -> impl Iterator<Item = &RawElem> {
        self.elems.iter().filter(move |e| e.tag == tag)
    }
}

#[allow(unused)]
impl Wlan {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(self.wlan_id);
        p.push(if self.enabled { 1 } else { 0 });
        p.extend_from_slice(&self.bssid);
        p.push(self.ssid.len() as u8);
        p.extend_from_slice(self.ssid.as_bytes());
        p
    }
}

#[allow(unused)]
impl Radio {
    pub fn admin_payload(&self) -> Vec<u8> {
        vec![self.id, self.admin_state]
    }
}

#[allow(unused)]
impl WtpContext {
    pub fn new(peer: std::net::SocketAddr) -> Self {
        Self {
            wtp_id: Vec::new(),
            name: format!("AP-{}", peer.ip()),
            description: String::new(),
            state: WtpState::Join,
            hardware_version: 0,
            software_version: 0,
            boot_version: 0,
            radios: Vec::new(),
            led_enabled: true,
            session_id: 0,
            last_seen: Instant::now(),
            last_sent: None,
            echo_interval: Duration::from_secs(30),
            retrans_interval: Duration::from_secs(5),
            max_retries: 3,
            seq_counter: 100,
        }
    }

    pub fn keep_alive(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn set_last_sent(&mut self, msg: &CtrlMsg, buf: Vec<u8>) {
        self.last_sent = Some(LastSentInfo {
            buf,
            seq: msg.hdr.seq_num,
            msg_type: msg.hdr.msg_type,
            send_time: Instant::now(),
            retry_count: 0,
        });
    }

    pub fn next_seq(&mut self) -> u8 {
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);
        seq
    }
}

/*
fn parse_u8(data: &[u8]) -> u8 { data[0] }
fn parse_u16(data: &[u8]) -> u16 { u16::from_be_bytes([data[0], data[1]]) }
fn parse_u32(data: &[u8]) -> u32 { u32::from_be_bytes(data[0..4].try_into().unwrap()) }
fn parse_ipv4(data: &[u8]) -> Ipv4Addr { Ipv4Addr::new(data[0], data[1], data[2], data[3]) }
*/

pub fn decode(data: &[u8]) -> Result<CtrlMsg> {
    if data.len() < 16 {
        return Err(anyhow!("packet too short"));
    }

    // skip the 8-byte CAPWAP header
    let ctrl_part = &data[8..];

    let msg_type = u32::from_be_bytes([ctrl_part[0], ctrl_part[1], ctrl_part[2], ctrl_part[3]]);
    let seq_num = ctrl_part[4];
    let elem_len = u16::from_be_bytes([ctrl_part[5], ctrl_part[6]]);
    let flags = ctrl_part[7];

    Ok(CtrlMsg {
        hdr: CtrlHdr { msg_type, seq_num, elem_len, flags },
        elems: Vec::new(), // filled in later by the parser
    })
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum CwElem {
    U8(u8),
    U16(u16),
    U32(u32),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Str(String),
    Bytes(Vec<u8>),
    ResultCode(u8),
    WtpName(String),
    WtpDescriptor { hardware: u32, software: u32 },
    RadioOp { radio_id: u8, state: u8 },
    ACIp4List(Vec<Ipv4Addr>),
    WtpRadioInfo { radio_id: u8, entries: HashMap<u16, Vec<CwElem>> },
    Unknown(u16, Vec<u8>),
}

use once_cell::sync::Lazy;

/// RFC 5415 Result Codes (subset returned to the WTP)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum CwResult {
    Success = 0,
    Failure = 1,
    UnrecognizedMsg = 33,
    InvalidElement = 34,
    MissingElement = 35,
}

#[derive(Debug)]
pub struct CwError {
    pub code: CwResult,
    pub msg: String,
}

impl std::fmt::Display for CwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.msg)
    }
}

#[derive(Clone)]
pub struct MsgSchema {
    pub mandatory: HashSet<u16>,
    pub optional: HashSet<u16>,
    pub allow_multi: HashSet<u16>,
    pub exclusive_groups: Vec<HashSet<u16>>,
    pub at_least_one: Vec<HashSet<u16>>,
}

pub struct MsgType;
#[allow(unused)]
impl MsgType {
    pub const DISC_REQ: u32 = 1;
    pub const DISC_RESP: u32 = 2;
    pub const JOIN_REQ: u32 = 3;
    pub const JOIN_RESP: u32 = 4;
    pub const CONFIG_STATUS_REQ: u32 = 5;
    pub const CONFIG_STATUS_RESP: u32 = 6;
    pub const CONFIG_UPDATE_REQ: u32 = 7;
    pub const CONFIG_UPDATE_RESP: u32 = 8;
    pub const WTP_EVENT_REQ: u32 = 9;
    pub const WTP_EVENT_RESP: u32 = 10;
    pub const CHANGE_STATE_EV_REQ: u32 = 11;
    pub const CHANGE_STATE_EV_RESP: u32 = 12;
    pub const ECHO_REQ: u32 = 13;
    pub const ECHO_RESP: u32 = 14;

    pub const IMAGE_DATA_REQ: u32 = 15;
    pub const IMAGE_DATA_RESP: u32 = 16;
    pub const RESET_REQ: u32 = 17;
    pub const RESET_RESP: u32 = 18;
    pub const PRIMARY_DISC_REQ: u32 = 19;
    pub const PRIMARY_DISC_RESP: u32 = 20;
    pub const DATA_TRANSFER_REQ: u32 = 21;
    pub const DATA_TRANSFER_RESP: u32 = 22;
    pub const CLEAR_CONFIG_REQ: u32 = 23;
    pub const CLEAR_CONFIG_RESP: u32 = 24;
    pub const STATION_CONFIG_REQ: u32 = 25;
    pub const STATION_CONFIG_RESP: u32 = 26;

    #[inline]
    pub fn is_request(m_type: u32) -> bool {
        m_type % 2 != 0
    }

    #[inline]
    pub fn is_response(m_type: u32) -> bool {
        m_type != 0 && m_type % 2 == 0
    }
}

pub struct MsgElemType;
#[allow(unused)]
impl MsgElemType {
    /* RFC 5415 base elements, IDs aligned with the spec table */
    pub const AC_DESCRIPTOR: u16 = 1;
    pub const AC_IPV4_LIST: u16 = 2;
    pub const AC_IPV6_LIST: u16 = 3;
    pub const AC_NAME: u16 = 4;
    pub const AC_NAME_WITH_PRIORITY: u16 = 5;
    pub const AC_TIMESTAMP: u16 = 6;
    pub const ADD_MAC_ACL_ENTRY: u16 = 7;
    pub const ADD_STATION: u16 = 8;
    pub const CAPWAP_CTRL_IPV4_ADDR: u16 = 10;
    pub const CAPWAP_CTRL_IPV6_ADDR: u16 = 11;
    pub const CAPWAP_TIMERS: u16 = 12;
    pub const DATA_TRANSFER_DATA: u16 = 13;
    pub const DATA_TRANSFER_MODE: u16 = 14;
    pub const DECRYPT_ERR_REPORT: u16 = 15;
    pub const DECRYPT_ERR_REPORT_PERIOD: u16 = 16;
    pub const DEL_MAC_ACL_ENTRY: u16 = 17;
    pub const DEL_STATION: u16 = 18;
    pub const DISC_TYPE: u16 = 20;
    pub const DUPLICATE_IPV4_ADDR: u16 = 21;
    pub const DUPLICATE_IPV6_ADDR: u16 = 22;
    pub const IDLE_TIMEOUT: u16 = 23;
    pub const IMAGE_DATA: u16 = 24;
    pub const IMAGE_ID: u16 = 25;
    pub const IMAGE_INFO: u16 = 26;
    pub const INIT_DOWNLOAD: u16 = 27;
    pub const LOCATION_DATA: u16 = 28;
    pub const MAX_MESSAGE_LEN: u16 = 29;
    pub const CAPWAP_LOCAL_IPV4_ADDR: u16 = 30;
    pub const RADIO_ADMIN_STATE: u16 = 31;
    pub const RADIO_OP_STATE: u16 = 32;
    pub const RESULT_CODE: u16 = 33;
    pub const RETURNED_MESSAGE_ELEMENT: u16 = 34;
    pub const SESSION_ID: u16 = 35;
    pub const STATS_TIMER: u16 = 36;
    pub const VENDOR_SPECIFIC_PAYLOAD: u16 = 37;
    pub const WTP_BOARD_DATA: u16 = 38;
    pub const WTP_DESCRIPTOR: u16 = 39;
    pub const WTP_FALLBACK: u16 = 40;
    pub const WTP_FRAME_TUNNEL_MODE: u16 = 41;
    pub const WTP_MAC_TYPE: u16 = 44;
    pub const WTP_NAME: u16 = 45;
    pub const WTP_RADIO_STATS: u16 = 47;
    pub const WTP_REBOOT_STATS: u16 = 48;
    pub const WTP_STATIC_IP_ADDR_INFO: u16 = 49;
    pub const CAPWAP_LOCAL_IPV6_ADDR: u16 = 50;
    pub const CAPWAP_TRANSPORT_PROTO: u16 = 51;
    pub const MTU_DISC_PADDING: u16 = 52;
    pub const ECN_SUPPORT: u16 = 53;

    /* RFC 5416 IEEE 802.11 Binding Elements */
    pub const WTP_RADIO_INFO: u16 = 1048;
    pub const WTP_RADIO_CONFIG: u16 = 1049;
    pub const WTP_RADIO_CAPS: u16 = 1050;
    pub const MAC_OPERATION: u16 = 1041;
    pub const STATION_EVENT_TYPE: u16 = 1046;
}

pub static MSG_SCHEMAS: Lazy<HashMap<u32, MsgSchema>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // 1. Discovery Request
    m.insert(MsgType::DISC_REQ, MsgSchema {
        mandatory: [
            MsgElemType::DISC_TYPE, MsgElemType::WTP_BOARD_DATA,
            MsgElemType::WTP_DESCRIPTOR, MsgElemType::WTP_FRAME_TUNNEL_MODE,
            MsgElemType::WTP_MAC_TYPE, MsgElemType::WTP_RADIO_INFO,
        ].into(),
        optional: [MsgElemType::MTU_DISC_PADDING, MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
        allow_multi: [].into(),
        exclusive_groups: vec![],
        at_least_one: vec![],
    });

    // 2. Primary Discovery Request
    m.insert(MsgType::PRIMARY_DISC_REQ, m.get(&MsgType::DISC_REQ).unwrap().clone());

    // 3. Join Request
    m.insert(MsgType::JOIN_REQ, MsgSchema {
        mandatory: [
            MsgElemType::LOCATION_DATA, MsgElemType::WTP_BOARD_DATA,
            MsgElemType::WTP_DESCRIPTOR, MsgElemType::WTP_FRAME_TUNNEL_MODE,
            MsgElemType::SESSION_ID, MsgElemType::WTP_MAC_TYPE,
            MsgElemType::WTP_RADIO_INFO, MsgElemType::ECN_SUPPORT,
        ].into(),
        optional: [
            MsgElemType::CAPWAP_TRANSPORT_PROTO, MsgElemType::MAX_MESSAGE_LEN,
            MsgElemType::WTP_REBOOT_STATS, MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
        ].into(),
        allow_multi: [MsgElemType::WTP_RADIO_INFO].into(),
        exclusive_groups: vec![],
        at_least_one: vec![
            [MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, MsgElemType::CAPWAP_LOCAL_IPV6_ADDR].into()
        ],
    });

    // 4. Configuration Status Request
    m.insert(MsgType::CONFIG_STATUS_REQ, MsgSchema {
        mandatory: [
            MsgElemType::AC_NAME, MsgElemType::RADIO_ADMIN_STATE,
            MsgElemType::STATS_TIMER, MsgElemType::WTP_REBOOT_STATS,
        ].into(),
        optional: [
            MsgElemType::AC_NAME_WITH_PRIORITY, MsgElemType::CAPWAP_TRANSPORT_PROTO,
            MsgElemType::WTP_STATIC_IP_ADDR_INFO, MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
        ].into(),
        allow_multi: [].into(),
        exclusive_groups: vec![],
        at_least_one: vec![],
    });

    // 5. Change State Event Request
    m.insert(MsgType::CHANGE_STATE_EV_REQ, MsgSchema {
        mandatory: [MsgElemType::RADIO_OP_STATE, MsgElemType::RESULT_CODE].into(),
        optional: [MsgElemType::RETURNED_MESSAGE_ELEMENT, MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
        allow_multi: [MsgElemType::RETURNED_MESSAGE_ELEMENT, MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
        exclusive_groups: vec![],
        at_least_one: vec![],
    });

    // 6. WTP Event Request
    m.insert(MsgType::WTP_EVENT_REQ, MsgSchema {
        mandatory: [].into(),
        optional: [
            MsgElemType::DECRYPT_ERR_REPORT, MsgElemType::DUPLICATE_IPV4_ADDR,
            MsgElemType::DUPLICATE_IPV6_ADDR, MsgElemType::WTP_RADIO_STATS,
            MsgElemType::WTP_REBOOT_STATS, MsgElemType::DEL_STATION,
            MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
        ].into(),
        allow_multi: [
            MsgElemType::DECRYPT_ERR_REPORT, MsgElemType::DUPLICATE_IPV4_ADDR,
            MsgElemType::DUPLICATE_IPV6_ADDR, MsgElemType::WTP_RADIO_STATS,
            MsgElemType::WTP_REBOOT_STATS, MsgElemType::DEL_STATION,
            MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
        ].into(),
        exclusive_groups: vec![],
        at_least_one: vec![
            [
                MsgElemType::DECRYPT_ERR_REPORT, MsgElemType::DUPLICATE_IPV4_ADDR,
                MsgElemType::DUPLICATE_IPV6_ADDR, MsgElemType::WTP_RADIO_STATS,
                MsgElemType::WTP_REBOOT_STATS, MsgElemType::DEL_STATION,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD
            ].into()
        ],
    });

    // 7. Echo Request
    m.insert(MsgType::ECHO_REQ, MsgSchema {
        mandatory: [].into(),
        optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
        allow_multi: [].into(),
        exclusive_groups: vec![],
        at_least_one: vec![],
    });

    m
});

#[allow(unused)]
impl MsgSchema {
    fn new(m: &[u16], o: &[u16], multi: &[u16]) -> Self {
        Self {
            mandatory: m.iter().cloned().collect(),
            optional: o.iter().cloned().collect(),
            allow_multi: multi.iter().cloned().collect(),
            exclusive_groups: Vec::new(),
            at_least_one: Vec::new(),
        }
    }

    pub fn validate(&self, m_type: u32, mut data: &[u8]) -> std::result::Result<HashMap<u16, Vec<CwElem>>, CwError> {
        let mut results: HashMap<u16, Vec<CwElem>> = HashMap::new();
        let mut seen_ids = HashSet::new();

        while !data.is_empty() {
            if data.len() < 4 {
                return Err(CwError { code: CwResult::InvalidElement, msg: "tlv truncated".into() });
            }

            let id = u16::from_be_bytes([data[0], data[1]]);
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;

            if data.len() < 4 + len {
                return Err(CwError { code: CwResult::InvalidElement, msg: format!("elem {} len mismatch", id) });
            }

            if !self.mandatory.contains(&id) && !self.optional.contains(&id) {
                return Err(CwError { code: CwResult::UnrecognizedMsg, msg: format!("unexpected elem {}", id) });
            }

            if seen_ids.contains(&id) && !self.allow_multi.contains(&id) {
                return Err(CwError {
                    code: CwResult::InvalidElement,
                    msg: format!("elem {} appeared multiple times but not allowed", id)
                });
            }

            let body = &data[4..4 + len];

            let elem = self.decode_elem(id, body)?;
            results.entry(id).or_default().push(elem);

            seen_ids.insert(id);
            data = &data[4 + len..];
        }

        self.check_constraints(&seen_ids)?;
        Ok(results)
    }

    pub(crate) fn parse_raw_tlvs(&self, mut data: &[u8]) -> std::result::Result<HashMap<u16, Vec<CwElem>>, CwError> {
        let mut map: HashMap<u16, Vec<CwElem>>= HashMap::new();
        while data.len() >= 4 {
            let id = u16::from_be_bytes([data[0], data[1]]);
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if data.len() < 4 + len { break; }

            let elem = self.decode_elem(id, &data[4..4+len])?;
            map.entry(id).or_default().push(elem);
            data = &data[4+len..];
        }
        Ok(map)
    }

    fn decode_elem(&self, id: u16, data: &[u8]) -> std::result::Result<CwElem, CwError> {
        match id {
            MsgElemType::RESULT_CODE if !data.is_empty() => Ok(CwElem::ResultCode(data[0])),

            MsgElemType::WTP_NAME => {
                let name = String::from_utf8_lossy(data).trim_matches('\0').to_string();
                Ok(CwElem::WtpName(name))
            },

            MsgElemType::WTP_DESCRIPTOR if data.len() >= 8 => {
                let hw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let sw = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Ok(CwElem::WtpDescriptor { hardware: hw, software: sw })
            },

            MsgElemType::RADIO_OP_STATE if data.len() >= 2 => {
                Ok(CwElem::RadioOp { radio_id: data[0], state: data[1] })
            }

            MsgElemType::AC_IPV4_LIST => {
                let addrs = data.chunks_exact(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
                Ok(CwElem::ACIp4List(addrs))
            }

            // WTP Radio Info (1048) payload is itself nested TLVs, parsed recursively.
            MsgElemType::WTP_RADIO_INFO if !data.is_empty() => {
                let radio_id = data[0];
                let sub_data = &data[1..];
                // Recurse via self so decode_elem stays reachable inside parse_raw_tlvs.
                let entries = self.parse_raw_tlvs(sub_data)?;
                Ok(CwElem::WtpRadioInfo { radio_id, entries })
            }

            _ => Ok(CwElem::Unknown(id, data.to_vec())),
        }
    }

    fn check_constraints(&self, seen_ids: &HashSet<u16>) -> std::result::Result<(), CwError> {
        for id in &self.mandatory {
            if !seen_ids.contains(id) {
                return Err(CwError { code: CwResult::MissingElement, msg: format!("missing mandatory {}", id) });
            }
        }

        for group in &self.at_least_one {
            if !group.iter().any(|id| seen_ids.contains(id)) {
                return Err(CwError { code: CwResult::MissingElement, msg: "at least one required in group".into() });
            }
        }

        for group in &self.exclusive_groups {
            if group.iter().filter(|id| seen_ids.contains(id)).count() > 1 {
                let conflicts: Vec<u16> = group.iter().filter(|id| seen_ids.contains(id)).cloned().collect();
                return Err(CwError { code: CwResult::InvalidElement, msg: format!("exclusive conflict: {:?}", conflicts) });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_least_one_validation() {
        // Build a Join-Request-like schema.
        let schema = MsgSchema {
            mandatory: HashSet::new(), // empty so the test focuses on at_least_one
            optional: [MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, MsgElemType::CAPWAP_LOCAL_IPV6_ADDR].into(),
            allow_multi: HashSet::new(),
            at_least_one: vec![
                [MsgElemType::CAPWAP_LOCAL_IPV4_ADDR, MsgElemType::CAPWAP_LOCAL_IPV6_ADDR].into()
            ],
        };

        // Case 1: IPv4 present (ok)
        let data_ipv4 = vec![
            0, 11, 0, 4, 192, 168, 1, 1, // ID=11 (IPv4), Len=4
        ];
        assert!(schema.validate(&data_ipv4).is_ok());

        // Case 2: IPv6 present (ok)
        let data_ipv6 = vec![
            0, 12, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ID=12 (IPv6), Len=16
        ];
        assert!(schema.validate(&data_ipv6).is_ok());

        // Case 3: neither present (fails)
        let data_empty = vec![];
        let result = schema.validate(&data_empty);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one"));

        // Case 4: an unrelated element (fails)
        let data_wrong = vec![
            0, 39, 0, 4, 1, 2, 3, 4, // ID=39 (Vendor Specific)
        ];
        // 39 is not in optional/mandatory, so validate reports "not allowed" first.
        let result = schema.validate(&data_wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_wtp_event_at_least_one_complex() {
        // Model a WTP Event Request: at least one of several error reports is required.
        let schema = MsgSchema {
            mandatory: HashSet::new(),
            optional: [MsgElemType::DUPLICATE_IPV4_ADDR, MsgElemType::WTP_RADIO_STATS].into(),
            allow_multi: [MsgElemType::WTP_RADIO_STATS].into(),
            at_least_one: vec![
                [MsgElemType::DUPLICATE_IPV4_ADDR, MsgElemType::WTP_RADIO_STATS].into()
            ],
        };

        // Two same-type repeatable elements (ok)
        let data = vec![
            0, 48, 0, 2, 0, 1, // Radio Stats 1
            0, 48, 0, 2, 0, 2, // Radio Stats 2
        ];
        let res = schema.validate(&data).unwrap();
        assert_eq!(res.get(&48).unwrap().len(), 2);
    }
}
