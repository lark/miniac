//! CAPWAP control messages, message elements, schema validation and WTP session state.
//!
//! Copyright (c) 2026  Wang Jian

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

pub struct CtrlHdr {
    pub msg_type: u32,
    pub seq_num: u32,
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

/// Runtime view of a client station associated to this WTP, maintained in memory
/// from Station Configuration Request (Add/Delete Station) notifications. The
/// AC-only/controller info mirrors what is persisted to the `stations` table.
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct RuntimeStation {
    pub mac: [u8; 6],
    pub radio_id: u8,
    pub wlan_id: u8,
    pub ssid: Option<String>,
    pub rssi: Option<i32>,
    pub ip: Option<String>,
    pub state: String,
    pub associated_at: u64,
}

pub struct LastSentInfo {
    pub buf: Vec<u8>,
    pub seq: u32,
    pub msg_type: u32,
    pub send_time: Instant,
    pub retry_count: u32,
}

#[allow(unused)]
pub struct WtpContext {
    pub wtp_id: Vec<u8>,
    pub name: String,
    pub description: String,

    /// WTP board MAC learned from WTP Board Data during join (device identifier).
    pub mac: Option<[u8; 6]>,

    pub state: WtpState,

    pub hardware_version: u32,
    pub software_version: u32,
    pub boot_version: u32,

    pub radios: Vec<Radio>,

    /// Runtime client-station table, filled from Add/Delete Station
    /// (STATION_CONFIG_REQ) after the link enters the Run state.
    pub stations: Vec<RuntimeStation>,

    /// AP LED state last reported by the WTP; `None` until it reports one
    /// (TP-Link carries it in every Echo Request). The same value is persisted
    /// per device, so the management plane can show and re-apply it.
    pub led_on: Option<bool>,
    pub session_id: u64,
    pub last_seen: Instant,
    /// The AC's single outstanding Request awaiting its Response.
    pub last_sent: Option<LastSentInfo>,
    /// When the Run-state keep-alive Echo Request was last sent to the WTP.
    pub last_echo_sent: Instant,

    /// RFC 5415 4.5.3: seq of the last Request accepted from the WTP, with its
    /// Response cached to replay on a retransmission.
    pub last_req_seq: Option<u32>,
    pub last_resp_buf: Option<Vec<u8>>,
    /// Last Response (seq, type) handled, whose duplicate is discarded.
    pub last_resp_done: Option<(u32, u32)>,

    /// TP-Link Run-entry configuration push, sent strictly one frame per reply:
    /// the WTP admits a single in-flight radio operation and drops a message that
    /// arrives while one is still running. Each entry is an encoded wire frame.
    pub push_queue: VecDeque<Vec<u8>>,
    /// Frames released together once `push_queue` drains: the WLAN slot deletes
    /// and Add WLAN pushes, which the WTP accepts back-to-back.
    pub push_burst: Vec<Vec<u8>>,
    /// When the head of `push_queue` was sent, for the no-reply timeout.
    pub push_last_sent: Option<Instant>,

    pub echo_interval: Duration,
    pub retrans_interval: Duration,
    pub max_retries: u32,

    pub seq_counter: u32,
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
            seq_num: buf[4] as u32,
            elem_len: u16::from_be_bytes([buf[5], buf[6]]),
            flags: buf[7],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.push((self.seq_num & 0xff) as u8);
        buf.extend_from_slice(&self.elem_len.to_be_bytes());
        buf.push(self.flags);

        buf
    }
}

#[allow(unused)]
impl CtrlMsg {
    pub fn new(m_type: u32, seq: u32) -> Self {
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
        self.elems.push(RawElem {
            tag,
            data: val.to_vec(),
        });
        self.hdr.elem_len += (4 + val.len()) as u16;
        self
    }

    pub fn with_result_success(self) -> Self {
        self.with_result(CwResult::Success)
    }

    /// Sets the RFC 5415 Result Code element (1 octet) on a response. The H3C
    /// framing layer re-encodes this element on the wire (4-byte value) so the
    /// generic API stays RFC-compliant.
    pub fn with_result(self, code: CwResult) -> Self {
        self.add_elem(MsgElemType::RESULT_CODE, &[code as u8])
    }

    /// Append a single typed base element (see `crate::elements::BaseElem`).
    pub fn add_element(mut self, elem: crate::elements::BaseElem) -> Self {
        let (tag, val) = elem.encode();
        self.add_elem(tag, &val)
    }

    /// Append typed base elements in iteration order.
    pub fn add_elements(
        mut self,
        elems: impl IntoIterator<Item = crate::elements::BaseElem>,
    ) -> Self {
        for elem in elems {
            self = self.add_element(elem);
        }
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        crate::vendor::framing::CtrlFrame::Rfc.frame(self)
    }

    /// Encode this control message using a vendor framing (adds the 8-byte
    /// base header and widens the Seq where the vendor requires it).
    pub fn encode_for(&self, frame: crate::vendor::framing::CtrlFrame) -> Vec<u8> {
        frame.frame(self)
    }

    pub fn decode(frame: crate::vendor::framing::CtrlFrame, buf: &[u8]) -> Result<Self> {
        let hdr = frame.parse_hdr(buf)?;
        let elem_off = frame.elem_off();

        let mut elems = Vec::new();
        let mut pos = elem_off;
        while pos + 4 <= buf.len() {
            let tag = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            let end = pos + len;
            if end > buf.len() {
                break;
            }

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
            mac: None,
            state: WtpState::Join,
            hardware_version: 0,
            software_version: 0,
            boot_version: 0,
            radios: Vec::new(),
            stations: Vec::new(),
            led_on: None,
            session_id: 0,
            last_seen: Instant::now(),
            last_sent: None,
            last_echo_sent: Instant::now(),
            last_req_seq: None,
            last_resp_buf: None,
            last_resp_done: None,
            push_queue: VecDeque::new(),
            push_burst: Vec::new(),
            push_last_sent: None,
            echo_interval: Duration::from_secs(30),
            retrans_interval: Duration::from_secs(5),
            max_retries: 3,
            seq_counter: 100,
        }
    }

    pub fn keep_alive(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Store a sent frame by role (RFC 5415 4.5.3): a Request becomes the single
    /// outstanding Request, a Response is cached against the WTP Request it
    /// answers, so the two never displace each other.
    pub fn set_last_sent(&mut self, msg: &CtrlMsg, buf: Vec<u8>) {
        if MsgType::is_request(msg.hdr.msg_type) {
            // A new Request starts a new lock-step; drop the duplicate marker.
            self.last_resp_done = None;
            self.last_sent = Some(LastSentInfo {
                buf,
                seq: msg.hdr.seq_num,
                msg_type: msg.hdr.msg_type,
                send_time: Instant::now(),
                retry_count: 0,
            });
        } else {
            self.last_req_seq = Some(msg.hdr.seq_num);
            self.last_resp_buf = Some(buf);
        }
    }

    /// Whether a Request of ours awaits its Response; RFC 5415 4.5.3 allows only
    /// one outstanding at a time.
    pub fn has_outstanding_request(&self) -> bool {
        self.last_sent
            .as_ref()
            .is_some_and(|l| MsgType::is_request(l.msg_type))
    }

    /// Retransmit interval for the `retry_count`-th retransmission: doubles each
    /// time, capped at half the EchoInterval (RFC 5415 4.5.3).
    pub fn retrans_interval_for(&self, retry_count: u32) -> Duration {
        let doubled = self
            .retrans_interval
            .saturating_mul(1u32 << retry_count.min(8));
        doubled.min(self.echo_interval / 2)
    }

    pub fn next_seq(&mut self) -> u32 {
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);
        seq
    }

    /// Queue an encoded frame for serialized delivery (see [`Self::push_queue`]).
    pub fn push_msg(&mut self, buf: Vec<u8>) {
        self.push_queue.push_back(buf);
    }

    /// Queue a frame for the post-serialized burst (see [`Self::push_burst`]).
    pub fn burst_msg(&mut self, buf: Vec<u8>) {
        self.push_burst.push(buf);
    }

    /// Release what the serialized push is due to send: the next serialized
    /// frame, and — once that queue is drained — the deferred burst as well, so
    /// the trailing WLAN messages are not stranded behind the last serialized
    /// frame's reply.
    pub fn release_push(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(buf) = self.push_queue.pop_front() {
            self.push_last_sent = Some(Instant::now());
            out.push(buf);
        }
        if self.push_queue.is_empty() {
            out.extend(std::mem::take(&mut self.push_burst));
        }
        out
    }

    /// Add or refresh a station in the runtime table (Add Station notification).
    /// `associated_at` is only applied on a first sighting so a refresh does not
    /// move the association timestamp.
    pub fn add_station(&mut self, st: RuntimeStation) {
        match self.stations.iter_mut().find(|s| s.mac == st.mac) {
            Some(existing) => {
                existing.radio_id = st.radio_id;
                existing.wlan_id = st.wlan_id;
                existing.ssid = st.ssid;
                existing.rssi = st.rssi;
                existing.ip = st.ip;
                existing.state = st.state;
            }
            None => self.stations.push(st),
        }
    }

    /// Drop a station from the runtime table (Delete Station notification).
    pub fn remove_station(&mut self, mac: [u8; 6]) {
        self.stations.retain(|s| s.mac != mac);
    }
}

/*
fn parse_u8(data: &[u8]) -> u8 { data[0] }
fn parse_u16(data: &[u8]) -> u16 { u16::from_be_bytes([data[0], data[1]]) }
fn parse_u32(data: &[u8]) -> u32 { u32::from_be_bytes(data[0..4].try_into().unwrap()) }
fn parse_ipv4(data: &[u8]) -> Ipv4Addr { Ipv4Addr::new(data[0], data[1], data[2], data[3]) }
*/

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
    WtpDescriptor {
        hardware: u32,
        software: u32,
    },
    RadioOp {
        radio_id: u8,
        state: u8,
    },
    ACIp4List(Vec<Ipv4Addr>),
    WtpRadioInfo {
        radio_id: u8,
        entries: HashMap<u16, Vec<CwElem>>,
    },
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

    /// H3C Release Client by AC Request/Response (AX60 `CW_MSG_TYPE_VALUE_
    /// RELEASE_CLIENT_BY_AC_REQUEST`, WTP.dis `CWWTPManageGenericRunMessage`
    /// `v62 == 139`). Not an RFC 5415 message number; the AC evicts one station
    /// from the WTP by its MAC.
    pub const RELEASE_CLIENT_REQ: u32 = 139;
    pub const RELEASE_CLIENT_RESP: u32 = 140;

    #[inline]
    pub fn is_request(m_type: u32) -> bool {
        m_type % 2 != 0
    }

    #[inline]
    pub fn is_response(m_type: u32) -> bool {
        m_type != 0 && m_type % 2 == 0
    }
}

/// Whether seq `a` is older than `b` over the framing's counter width: the RFC
/// 1-octet Sequence Number wraps at 256, H3C's 4-octet one at 2^32. `a` is older
/// when its forward distance to `b` stays within half the modulus.
pub fn seq_is_older(a: u32, b: u32, frame: crate::vendor::framing::CtrlFrame) -> bool {
    let modulus = 1i64 << (8 * frame.seq_len());
    let diff = (b as i64 - a as i64).rem_euclid(modulus);
    diff > 0 && diff < modulus / 2
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
    /// IEEE 802.11 Add WLAN (RFC 5416 6.1).
    pub const ADD_WLAN: u16 = 1024;
    /// IEEE 802.11 Delete WLAN (RFC 5416 6.4).
    pub const DEL_WLAN: u16 = 1027;
    pub const WTP_RADIO_INFO: u16 = 1048;
    pub const WTP_RADIO_CONFIG: u16 = 1049;
    pub const WTP_RADIO_CAPS: u16 = 1050;
    pub const MAC_OPERATION: u16 = 1041;
    pub const STATION_EVENT_TYPE: u16 = 1046;
}

pub static MSG_SCHEMAS: Lazy<HashMap<u32, MsgSchema>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // 1. Discovery Request
    m.insert(
        MsgType::DISC_REQ,
        MsgSchema {
            mandatory: [
                MsgElemType::DISC_TYPE,
                MsgElemType::WTP_BOARD_DATA,
                MsgElemType::WTP_DESCRIPTOR,
                MsgElemType::WTP_FRAME_TUNNEL_MODE,
                MsgElemType::WTP_MAC_TYPE,
                MsgElemType::WTP_RADIO_INFO,
            ]
            .into(),
            optional: [
                MsgElemType::MTU_DISC_PADDING,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 2. Primary Discovery Request
    m.insert(
        MsgType::PRIMARY_DISC_REQ,
        m.get(&MsgType::DISC_REQ).unwrap().clone(),
    );

    // 3. Join Request
    m.insert(
        MsgType::JOIN_REQ,
        MsgSchema {
            mandatory: [
                MsgElemType::LOCATION_DATA,
                MsgElemType::WTP_BOARD_DATA,
                MsgElemType::WTP_DESCRIPTOR,
                MsgElemType::WTP_FRAME_TUNNEL_MODE,
                MsgElemType::SESSION_ID,
                MsgElemType::WTP_MAC_TYPE,
                MsgElemType::WTP_RADIO_INFO,
                MsgElemType::ECN_SUPPORT,
            ]
            .into(),
            optional: [
                MsgElemType::CAPWAP_TRANSPORT_PROTO,
                MsgElemType::MAX_MESSAGE_LEN,
                MsgElemType::WTP_REBOOT_STATS,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            // A TP-Link WTP carries one Vendor Specific Payload (RFC 5415 elem 37)
            // per private element, so 37 legitimately repeats in a single Join.
            allow_multi: [
                MsgElemType::WTP_RADIO_INFO,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            exclusive_groups: vec![],
            at_least_one: vec![[
                MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
                MsgElemType::CAPWAP_LOCAL_IPV6_ADDR,
            ]
            .into()],
        },
    );

    // 4. Configuration Status Request
    m.insert(
        MsgType::CONFIG_STATUS_REQ,
        MsgSchema {
            mandatory: [
                MsgElemType::AC_NAME,
                MsgElemType::RADIO_ADMIN_STATE,
                MsgElemType::STATS_TIMER,
                MsgElemType::WTP_REBOOT_STATS,
            ]
            .into(),
            optional: [
                MsgElemType::AC_NAME_WITH_PRIORITY,
                MsgElemType::CAPWAP_TRANSPORT_PROTO,
                MsgElemType::WTP_STATIC_IP_ADDR_INFO,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            // The H3C AX60 ConfigStatusRequest carries one AC-Name-with-priority
            // element per known AC, and one Radio Admin-State element per radio.
            // Both are legitimately multi-valued, so relax dedup for them.
            allow_multi: [
                MsgElemType::AC_NAME_WITH_PRIORITY,
                MsgElemType::RADIO_ADMIN_STATE,
            ]
            .into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 5. Change State Event Request
    m.insert(
        MsgType::CHANGE_STATE_EV_REQ,
        MsgSchema {
            mandatory: [MsgElemType::RADIO_OP_STATE, MsgElemType::RESULT_CODE].into(),
            optional: [
                MsgElemType::RETURNED_MESSAGE_ELEMENT,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            // The H3C AX60 sends one Radio Op-State element per radio.
            allow_multi: [
                MsgElemType::RADIO_OP_STATE,
                MsgElemType::RETURNED_MESSAGE_ELEMENT,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 6. WTP Event Request
    m.insert(
        MsgType::WTP_EVENT_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [
                MsgElemType::DECRYPT_ERR_REPORT,
                MsgElemType::DUPLICATE_IPV4_ADDR,
                MsgElemType::DUPLICATE_IPV6_ADDR,
                MsgElemType::WTP_RADIO_STATS,
                MsgElemType::WTP_REBOOT_STATS,
                MsgElemType::DEL_STATION,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [
                MsgElemType::DECRYPT_ERR_REPORT,
                MsgElemType::DUPLICATE_IPV4_ADDR,
                MsgElemType::DUPLICATE_IPV6_ADDR,
                MsgElemType::WTP_RADIO_STATS,
                MsgElemType::WTP_REBOOT_STATS,
                MsgElemType::DEL_STATION,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            exclusive_groups: vec![],
            at_least_one: vec![[
                MsgElemType::DECRYPT_ERR_REPORT,
                MsgElemType::DUPLICATE_IPV4_ADDR,
                MsgElemType::DUPLICATE_IPV6_ADDR,
                MsgElemType::WTP_RADIO_STATS,
                MsgElemType::WTP_REBOOT_STATS,
                MsgElemType::DEL_STATION,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into()],
        },
    );

    // 7. Echo Request
    m.insert(
        MsgType::ECHO_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            // TP-Link WTPs put several private TLVs in an Echo Request as
            // separate Vendor Specific Payload elements (observed: three 37s
            // carrying private 33/32/56), so a single occurrence is too strict.
            allow_multi: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 2. Discovery Response
    m.insert(
        MsgType::DISC_RESP,
        MsgSchema {
            mandatory: [
                MsgElemType::AC_DESCRIPTOR,
                MsgElemType::AC_NAME,
                MsgElemType::WTP_RADIO_INFO,
            ]
            .into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [MsgElemType::WTP_RADIO_INFO].into(),
            exclusive_groups: vec![],
            at_least_one: vec![[
                MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
                MsgElemType::CAPWAP_CTRL_IPV6_ADDR,
            ]
            .into()],
        },
    );

    // 4. Join Response
    m.insert(
        MsgType::JOIN_RESP,
        MsgSchema {
            mandatory: [
                MsgElemType::RESULT_CODE,
                MsgElemType::AC_DESCRIPTOR,
                MsgElemType::AC_NAME,
                MsgElemType::WTP_RADIO_INFO,
            ]
            .into(),
            optional: [
                MsgElemType::AC_IPV4_LIST,
                MsgElemType::AC_IPV6_LIST,
                MsgElemType::CAPWAP_TRANSPORT_PROTO,
                MsgElemType::IMAGE_ID,
                MsgElemType::MAX_MESSAGE_LEN,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [MsgElemType::WTP_RADIO_INFO].into(),
            exclusive_groups: vec![],
            at_least_one: vec![
                [
                    MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
                    MsgElemType::CAPWAP_CTRL_IPV6_ADDR,
                ]
                .into(),
                [
                    MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
                    MsgElemType::CAPWAP_LOCAL_IPV6_ADDR,
                ]
                .into(),
            ],
        },
    );

    // 6. Configuration Status Response
    m.insert(
        MsgType::CONFIG_STATUS_RESP,
        MsgSchema {
            mandatory: [
                MsgElemType::CAPWAP_TIMERS,
                MsgElemType::DECRYPT_ERR_REPORT_PERIOD,
                MsgElemType::IDLE_TIMEOUT,
                MsgElemType::WTP_FALLBACK,
            ]
            .into(),
            optional: [
                MsgElemType::AC_IPV4_LIST,
                MsgElemType::AC_IPV6_LIST,
                MsgElemType::WTP_STATIC_IP_ADDR_INFO,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [MsgElemType::DECRYPT_ERR_REPORT_PERIOD].into(),
            exclusive_groups: vec![],
            at_least_one: vec![[MsgElemType::AC_IPV4_LIST, MsgElemType::AC_IPV6_LIST].into()],
        },
    );

    // 7. Configuration Update Request (AC->WTP downlink config; same-type elements may repeat).
    m.insert(
        MsgType::CONFIG_UPDATE_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [
                MsgElemType::AC_NAME_WITH_PRIORITY,
                MsgElemType::AC_TIMESTAMP,
                MsgElemType::ADD_MAC_ACL_ENTRY,
                MsgElemType::DEL_MAC_ACL_ENTRY,
                MsgElemType::CAPWAP_TIMERS,
                MsgElemType::IDLE_TIMEOUT,
                MsgElemType::LOCATION_DATA,
                MsgElemType::RADIO_ADMIN_STATE,
                MsgElemType::STATS_TIMER,
                MsgElemType::WTP_FALLBACK,
                MsgElemType::WTP_NAME,
                MsgElemType::WTP_STATIC_IP_ADDR_INFO,
                MsgElemType::IMAGE_ID,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [
                MsgElemType::ADD_MAC_ACL_ENTRY,
                MsgElemType::DEL_MAC_ACL_ENTRY,
                MsgElemType::RADIO_ADMIN_STATE,
                MsgElemType::WTP_NAME,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            exclusive_groups: vec![],
            at_least_one: vec![[
                MsgElemType::AC_NAME_WITH_PRIORITY,
                MsgElemType::AC_TIMESTAMP,
                MsgElemType::ADD_MAC_ACL_ENTRY,
                MsgElemType::DEL_MAC_ACL_ENTRY,
                MsgElemType::CAPWAP_TIMERS,
                MsgElemType::IDLE_TIMEOUT,
                MsgElemType::LOCATION_DATA,
                MsgElemType::RADIO_ADMIN_STATE,
                MsgElemType::STATS_TIMER,
                MsgElemType::WTP_FALLBACK,
                MsgElemType::WTP_NAME,
                MsgElemType::WTP_STATIC_IP_ADDR_INFO,
                MsgElemType::IMAGE_ID,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into()],
        },
    );

    // 8. Configuration Update Response (RFC 8.5)
    m.insert(
        MsgType::CONFIG_UPDATE_RESP,
        MsgSchema {
            mandatory: [MsgElemType::RESULT_CODE].into(),
            optional: [
                MsgElemType::RADIO_OP_STATE,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [MsgElemType::RADIO_OP_STATE].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 10. WTP Event Response (RFC 9.5)
    m.insert(
        MsgType::WTP_EVENT_RESP,
        MsgSchema {
            mandatory: [].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 12. Change State Event Response (RFC 8.7)
    m.insert(
        MsgType::CHANGE_STATE_EV_RESP,
        MsgSchema {
            mandatory: [].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 14. Echo Response (RFC 7.2)
    m.insert(
        MsgType::ECHO_RESP,
        MsgSchema {
            mandatory: [].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 15/16. Image Data Request/Response (RFC 9.1, firmware upgrade)
    m.insert(
        MsgType::IMAGE_DATA_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [
                MsgElemType::IMAGE_ID,
                MsgElemType::INIT_DOWNLOAD,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );
    m.insert(
        MsgType::IMAGE_DATA_RESP,
        MsgSchema {
            mandatory: [MsgElemType::RESULT_CODE].into(),
            optional: [
                MsgElemType::IMAGE_INFO,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 17/18. Reset Request/Response (RFC 9.2/9.3)
    m.insert(
        MsgType::RESET_REQ,
        MsgSchema {
            mandatory: [MsgElemType::IMAGE_ID].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );
    m.insert(
        MsgType::RESET_RESP,
        MsgSchema {
            mandatory: [].into(),
            optional: [
                MsgElemType::RESULT_CODE,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 20. Primary Discovery Response (identical element set to Discovery Response)
    m.insert(
        MsgType::PRIMARY_DISC_RESP,
        m.get(&MsgType::DISC_RESP).unwrap().clone(),
    );

    // 21/22. Data Transfer Request/Response (RFC 9.6). Mandatory element
    //   depends on sender: AC sends Data Transfer Mode; WTP sends Data Transfer Data.
    m.insert(
        MsgType::DATA_TRANSFER_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [
                MsgElemType::DATA_TRANSFER_MODE,
                MsgElemType::DATA_TRANSFER_DATA,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );
    m.insert(
        MsgType::DATA_TRANSFER_RESP,
        MsgSchema {
            mandatory: [MsgElemType::RESULT_CODE].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 23/24. Clear Configuration Request/Response.
    //   RFC lists no mandatory elements for the request; response confirms by Result Code.
    m.insert(
        MsgType::CLEAR_CONFIG_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );
    m.insert(
        MsgType::CLEAR_CONFIG_RESP,
        MsgSchema {
            mandatory: [MsgElemType::RESULT_CODE].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 25/26. Station Configuration Request/Response (RFC 10.1/10.2).
    //   Request has no mandatory elements; Add/Delete Station may repeat.
    m.insert(
        MsgType::STATION_CONFIG_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [
                MsgElemType::ADD_STATION,
                MsgElemType::DEL_STATION,
                MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
            .into(),
            allow_multi: [MsgElemType::ADD_STATION, MsgElemType::DEL_STATION].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );
    m.insert(
        MsgType::STATION_CONFIG_RESP,
        MsgSchema {
            mandatory: [MsgElemType::RESULT_CODE].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 139/140. H3C Release Client by AC Request/Response (AC -> WTP). The request
    //   carries one vendor element (tag 65, a 6-byte client MAC); the response
    //   confirms with a Result Code (tag 33).
    m.insert(
        MsgType::RELEASE_CLIENT_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [crate::vendor::h3c::ELEM_RELEASE_CLIENT_MAC].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![[crate::vendor::h3c::ELEM_RELEASE_CLIENT_MAC].into()],
        },
    );
    m.insert(
        MsgType::RELEASE_CLIENT_RESP,
        MsgSchema {
            mandatory: [MsgElemType::RESULT_CODE].into(),
            optional: [MsgElemType::VENDOR_SPECIFIC_PAYLOAD].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // 145. H3C AX60 channel-utilization report (WTP -> AC). No RFC schema: the
    //   0xfe20 element is kept as Unknown and acked with mtype 146 in Run state
    //   (see `vendor::h3c::WTP_CHAN_UTIL_REQ`).
    m.insert(
        crate::vendor::h3c::WTP_CHAN_UTIL_REQ,
        MsgSchema {
            mandatory: [].into(),
            optional: [].into(),
            allow_multi: [].into(),
            exclusive_groups: vec![],
            at_least_one: vec![],
        },
    );

    // TP-Link private WLAN Configuration Update Request/Response
    // (0x0033DD01/0x0033DD02, AC100 `CWWTPManageRunAcRequestMessage`). The
    // request supplies WLANs with the private 9 security argument wrapped in a
    // vendor payload and the IEEE 802.11 Add WLAN element; the response echoes
    // what it accepted. Neither is an RFC 5415 message number, so the schema
    // accepts any of those elements in any order and multiplicity.
    for id in [
        crate::vendor::tplink::WLAN_CONFIG_UPDATE_REQ,
        crate::vendor::tplink::WLAN_CONFIG_UPDATE_RESP,
    ] {
        m.insert(
            id,
            MsgSchema {
                mandatory: [].into(),
                optional: [
                    MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
                    MsgElemType::ADD_WLAN,
                    MsgElemType::DEL_WLAN,
                ]
                .into(),
                allow_multi: [
                    MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
                    MsgElemType::ADD_WLAN,
                    MsgElemType::DEL_WLAN,
                ]
                .into(),
                exclusive_groups: vec![],
                at_least_one: vec![],
            },
        );
    }

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

    pub fn validate(
        &self,
        m_type: u32,
        data: &[u8],
    ) -> std::result::Result<HashMap<u16, Vec<CwElem>>, CwError> {
        self.validate_impl(m_type, data, true)
    }

    /// Validate but tolerate elements not declared in `mandatory`/`optional`:
    /// they are parsed as `Unknown` and skipped instead of hard-failing. Vendor
    /// WTPs (e.g. H3C AX60) set many private elements inside Join/Config
    /// requests, so strict RFC schema checking is impractical for them.
    pub fn validate_lenient(
        &self,
        m_type: u32,
        data: &[u8],
    ) -> std::result::Result<HashMap<u16, Vec<CwElem>>, CwError> {
        self.validate_impl(m_type, data, false)
    }

    fn validate_impl(
        &self,
        _m_type: u32,
        mut data: &[u8],
        strict: bool,
    ) -> std::result::Result<HashMap<u16, Vec<CwElem>>, CwError> {
        let mut results: HashMap<u16, Vec<CwElem>> = HashMap::new();
        let mut seen_ids = HashSet::new();

        while !data.is_empty() {
            if data.len() < 4 {
                return Err(CwError {
                    code: CwResult::InvalidElement,
                    msg: "tlv truncated".into(),
                });
            }

            let id = u16::from_be_bytes([data[0], data[1]]);
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;

            if data.len() < 4 + len {
                return Err(CwError {
                    code: CwResult::InvalidElement,
                    msg: format!("elem {} len mismatch", id),
                });
            }

            let body = &data[4..4 + len];
            let known = self.mandatory.contains(&id) || self.optional.contains(&id);

            // Unknown element: hard-fail in strict mode, otherwise record it as
            // Unknown (for logging) and skip the constraint bookkeeping.
            if !known {
                if strict {
                    return Err(CwError {
                        code: CwResult::UnrecognizedMsg,
                        msg: format!("unexpected elem {}", id),
                    });
                }
                let elem = self.decode_elem(id, body)?;
                results.entry(id).or_default().push(elem);
                data = &data[4 + len..];
                continue;
            }

            if seen_ids.contains(&id) && !self.allow_multi.contains(&id) {
                return Err(CwError {
                    code: CwResult::InvalidElement,
                    msg: format!("elem {} appeared multiple times but not allowed", id),
                });
            }

            let elem = self.decode_elem(id, body)?;
            results.entry(id).or_default().push(elem);

            seen_ids.insert(id);
            data = &data[4 + len..];
        }

        self.check_constraints(&seen_ids, strict)?;
        Ok(results)
    }

    pub(crate) fn parse_raw_tlvs(
        &self,
        mut data: &[u8],
    ) -> std::result::Result<HashMap<u16, Vec<CwElem>>, CwError> {
        let mut map: HashMap<u16, Vec<CwElem>> = HashMap::new();
        while data.len() >= 4 {
            let id = u16::from_be_bytes([data[0], data[1]]);
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if data.len() < 4 + len {
                break;
            }

            let elem = self.decode_elem(id, &data[4..4 + len])?;
            map.entry(id).or_default().push(elem);
            data = &data[4 + len..];
        }
        Ok(map)
    }

    fn decode_elem(&self, id: u16, data: &[u8]) -> std::result::Result<CwElem, CwError> {
        match id {
            MsgElemType::RESULT_CODE if !data.is_empty() => Ok(CwElem::ResultCode(data[0])),

            MsgElemType::WTP_NAME => {
                let name = String::from_utf8_lossy(data).trim_matches('\0').to_string();
                Ok(CwElem::WtpName(name))
            }

            MsgElemType::WTP_DESCRIPTOR if data.len() >= 8 => {
                let hw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let sw = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Ok(CwElem::WtpDescriptor {
                    hardware: hw,
                    software: sw,
                })
            }

            MsgElemType::RADIO_OP_STATE if data.len() >= 2 => Ok(CwElem::RadioOp {
                radio_id: data[0],
                state: data[1],
            }),

            MsgElemType::AC_IPV4_LIST => {
                let addrs = data
                    .chunks_exact(4)
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

    // Constraint checks are strict RFC guarantees. In lenient mode they are
    // skipped entirely: vendor WTPs may omit the mandatory set and pack many
    // private elements that are not tracked in `seen_ids` (so the RFC
    // at-least-one / exclusive groups cannot be evaluated reliably).
    fn check_constraints(
        &self,
        seen_ids: &HashSet<u16>,
        strict: bool,
    ) -> std::result::Result<(), CwError> {
        if !strict {
            return Ok(());
        }
        for id in &self.mandatory {
            if !seen_ids.contains(id) {
                return Err(CwError {
                    code: CwResult::MissingElement,
                    msg: format!("missing mandatory {}", id),
                });
            }
        }

        for group in &self.at_least_one {
            if !group.iter().any(|id| seen_ids.contains(id)) {
                return Err(CwError {
                    code: CwResult::MissingElement,
                    msg: "at least one required in group".into(),
                });
            }
        }

        for group in &self.exclusive_groups {
            if group.iter().filter(|id| seen_ids.contains(id)).count() > 1 {
                let conflicts: Vec<u16> = group
                    .iter()
                    .filter(|id| seen_ids.contains(id))
                    .cloned()
                    .collect();
                return Err(CwError {
                    code: CwResult::InvalidElement,
                    msg: format!("exclusive conflict: {:?}", conflicts),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_ordering_follows_framing() {
        use crate::vendor::framing::CtrlFrame;
        // RFC framing: 1-octet Sequence Number, wraps at 256 (RFC 5415 4.5.3).
        assert!(seq_is_older(5, 6, CtrlFrame::Rfc));
        assert!(seq_is_older(250, 10, CtrlFrame::Rfc)); // wrapped forward past zero
        assert!(!seq_is_older(6, 5, CtrlFrame::Rfc));
        assert!(!seq_is_older(10, 250, CtrlFrame::Rfc));
        // Half a cycle apart is the boundary and counts as newer, not older.
        assert!(!seq_is_older(0, 128, CtrlFrame::Rfc));
        assert!(!seq_is_older(128, 0, CtrlFrame::Rfc));
        assert!(!seq_is_older(7, 7, CtrlFrame::Rfc));
        // H3C framing: 4-octet Sequence Number, does not wrap at 256.
        assert!(seq_is_older(255, 511, CtrlFrame::H3c));
        assert!(seq_is_older(511, 512, CtrlFrame::H3c));
        assert!(!seq_is_older(511, 255, CtrlFrame::H3c));
        assert!(!seq_is_older(512, 511, CtrlFrame::H3c));
        assert!(!seq_is_older(9, 9, CtrlFrame::H3c));
    }

    #[test]
    fn test_at_least_one_validation() {
        // Build a Join-Request-like schema.
        let schema = MsgSchema {
            mandatory: HashSet::new(), // empty so the test focuses on at_least_one
            optional: [
                MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
                MsgElemType::CAPWAP_LOCAL_IPV6_ADDR,
            ]
            .into(),
            allow_multi: HashSet::new(),
            exclusive_groups: Vec::new(),
            at_least_one: vec![[
                MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
                MsgElemType::CAPWAP_LOCAL_IPV6_ADDR,
            ]
            .into()],
        };

        // Case 1: IPv4 present (ok)  [CAPWAP_LOCAL_IPV4_ADDR=30]
        let data_ipv4 = vec![0, 30, 0, 4, 192, 168, 1, 1];
        assert!(schema.validate(0, &data_ipv4).is_ok());

        // Case 2: IPv6 present (ok)  [CAPWAP_LOCAL_IPV6_ADDR=50]
        let data_ipv6 = vec![0, 50, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(schema.validate(0, &data_ipv6).is_ok());

        // Case 3: neither present (fails)
        let data_empty = vec![];
        let result = schema.validate(0, &data_empty);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one"));

        // Case 4: an unrelated element (fails)
        let data_wrong = vec![
            0, 39, 0, 4, 1, 2, 3, 4, // ID=39 (Vendor Specific)
        ];
        // 39 is not in optional/mandatory, so validate reports "not allowed" first.
        let result = schema.validate(0, &data_wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_wtp_event_at_least_one_complex() {
        // Model a WTP Event Request: at least one of several error reports is required.
        let schema = MsgSchema {
            mandatory: HashSet::new(),
            optional: [
                MsgElemType::DUPLICATE_IPV4_ADDR,
                MsgElemType::WTP_REBOOT_STATS,
            ]
            .into(),
            allow_multi: [MsgElemType::WTP_REBOOT_STATS].into(),
            exclusive_groups: Vec::new(),
            at_least_one: vec![[
                MsgElemType::DUPLICATE_IPV4_ADDR,
                MsgElemType::WTP_REBOOT_STATS,
            ]
            .into()],
        };

        // Two same-type repeatable elements (ok)  [WTP_REBOOT_STATS=48]
        let data = vec![
            0, 48, 0, 2, 0, 1, // Reboot Stats 1
            0, 48, 0, 2, 0, 2, // Reboot Stats 2
        ];
        let res = schema.validate(0, &data).unwrap();
        assert_eq!(res.get(&48).unwrap().len(), 2);
    }

    #[test]
    fn all_control_messages_have_schemas() {
        let ids = [
            MsgType::DISC_REQ,
            MsgType::DISC_RESP,
            MsgType::JOIN_REQ,
            MsgType::JOIN_RESP,
            MsgType::CONFIG_STATUS_REQ,
            MsgType::CONFIG_STATUS_RESP,
            MsgType::CONFIG_UPDATE_REQ,
            MsgType::CONFIG_UPDATE_RESP,
            MsgType::WTP_EVENT_REQ,
            MsgType::WTP_EVENT_RESP,
            MsgType::CHANGE_STATE_EV_REQ,
            MsgType::CHANGE_STATE_EV_RESP,
            MsgType::ECHO_REQ,
            MsgType::ECHO_RESP,
            MsgType::IMAGE_DATA_REQ,
            MsgType::IMAGE_DATA_RESP,
            MsgType::RESET_REQ,
            MsgType::RESET_RESP,
            MsgType::PRIMARY_DISC_REQ,
            MsgType::PRIMARY_DISC_RESP,
            MsgType::DATA_TRANSFER_REQ,
            MsgType::DATA_TRANSFER_RESP,
            MsgType::CLEAR_CONFIG_REQ,
            MsgType::CLEAR_CONFIG_RESP,
            MsgType::STATION_CONFIG_REQ,
            MsgType::STATION_CONFIG_RESP,
        ];
        for id in ids {
            assert!(
                MSG_SCHEMAS.contains_key(&id),
                "missing schema for msg type {}",
                id
            );
        }
    }

    #[test]
    fn runtime_station_upsert_and_remove() {
        let mut ctx = WtpContext::new("127.0.0.1:5000".parse().unwrap());
        let st = RuntimeStation {
            mac: [1, 2, 3, 4, 5, 6],
            radio_id: 1,
            wlan_id: 1,
            ssid: Some("minimac".into()),
            rssi: None,
            ip: None,
            state: "associated".into(),
            associated_at: 0,
        };
        ctx.add_station(st.clone());
        assert_eq!(ctx.stations.len(), 1);
        // A refresh updates the same entry (no duplicate).
        ctx.add_station(RuntimeStation {
            rssi: Some(-48),
            ..st.clone()
        });
        assert_eq!(ctx.stations.len(), 1);
        assert_eq!(ctx.stations[0].rssi, Some(-48));
        ctx.remove_station([1, 2, 3, 4, 5, 6]);
        assert!(ctx.stations.is_empty());
    }
}
