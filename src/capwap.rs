use anyhow::{anyhow, Result};
use std::time::{Instant, Duration};
use std::net::SocketAddr;
use dashmap::DashMap;

// RFC5415 4.5.1.1
#[allow(unused)]
#[allow(non_snake_case)]
pub mod MsgType {
    pub const DISC_REQ: u32         = 1;         // Discovery Request
    pub const DISC_RESP: u32        = 2;         // Discovery Response
    pub const JOIN_REQ: u32         = 3;         // Join Request
    pub const JOIN_RESP: u32        = 4;         // Join Response
    pub const CONF_STATUS_REQ: u32  = 5;         // Configuration Status Request
    pub const CONF_STATUS_RESP: u32 = 6;         // Configuration Status Response
    pub const CONF_UPDATE_REQ: u32  = 7;         // Configuration Update Request
    pub const CONF_UPDATE_RESP: u32 = 8;         // Configuration Update Response
    pub const WTP_EV_REQ: u32       = 9;         // WTP Event Request
    pub const WTP_EV_RESP: u32      = 10;        // WTP Event Response
    pub const CH_STATE_EV_REQ: u32  = 11;        // Change State Event Request
    pub const CH_STATE_EV_RESP: u32 = 12;        // Change State Event Response
    pub const ECHO_REQ: u32         = 13;        // Echo Request
    pub const ECHO_RESP: u32        = 14;        // Echo Response
    pub const IMAGE_DATA_REQ: u32   = 15;        // Image Data Request
    pub const IMAGE_DATA_RESP: u32  = 16;        // Image Data Response
    pub const RESET_REQ: u32        = 17;        // Reset Request
    pub const RESET_RESP: u32       = 18;        // Reset Response
    pub const PRIMARY_DISC_REQ: u32 = 19;        // Primary Discovery Request
    pub const PRIMARY_DISC_RESP: u32 = 20;       // Primary Discovery Response
    pub const DATA_XFER_REQ: u32    = 21;        // Data Transfer Request
    pub const DATA_XFER_RESP: u32   = 22;        // Data Transfer Response
    pub const CLEAR_CONF_REQ: u32   = 23;        // Clear Configuration Request
    pub const CLEAR_CONF_RESP: u32  = 24;        // Clear Configuration Response
    pub const STATION_CONF_REQ: u32 = 25;        // Station Configuration Request
    pub const STATION_CONF_RESP: u32 = 26;       // Station Configuration Response

    #[inline]
    pub fn is_request(m_type: u32) -> bool {
        m_type % 2 != 0
    }

    #[inline]
    pub fn is_response(m_type: u32) -> bool {
        m_type != 0 && m_type % 2 == 0
    }
}

// RFC5415 4.6
#[allow(unused)]
#[allow(non_snake_case)]
pub mod MsgElemType {
    pub const AC_DESCRIPTOR: u16        = 1;         // AC Descriptor
    pub const AC_IPV4_LIST: u16         = 2;         // AC IPv4 List
    pub const AC_IPV6_LIST: u16         = 3;         // AC IPv6 List
    pub const AC_NAME: u16              = 4;         // AC Name
    pub const AC_NAME_WITH_PRIO: u16    = 5;         // AC Name with Priority
    pub const AC_TIMESTAMP: u16         = 6;         // AC Timestamp
    pub const ADD_MAC_ACL_ENTRY: u16    = 7;         // Add MAC ACL Entry
    pub const ADD_STATION: u16          = 8;         // Add Station
    pub const CAPWAP_CTRL_V4_ADDR: u16  = 10;        // CAPWAP Control IPV4 Address
    pub const CAPWAP_CTRL_V6_ADDR: u16  = 11;        // CAPWAP Control IPV6 Address
    pub const CAPWAP_LOCAL_V4_ADDR: u16 = 30;        // CAPWAP Local IPV4 Address
    pub const CAPWAP_LOCAL_V6_ADDR: u16 = 50;        // CAPWAP Local IPV6 Address
    pub const CAPWAP_TIMERS: u16        = 12;        // CAPWAP Timers
    pub const CAPWAP_XPORT_PROTO: u16   = 51;        // CAPWAP Transport Protocol
    pub const DATA_XFER_DATA: u16       = 13;        // Data Transfer Data
    pub const DATA_XFER_MODE: u16       = 14;        // Data Transfer Mode
    pub const DEC_ERR_REPORT: u16       = 15;        // Decryption Error Report
    pub const DEC_ERR_REPORT_PERIOD: u16 = 16;       // Decryption Error Report Period
    pub const DEL_MAC_ACL_ENTRY: u16    = 17;        // Delete MAC ACL Entry
    pub const DEL_STATION: u16          = 18;        // Delete Station
    pub const DISC_TYPE: u16            = 20;        // Discovery Type
    pub const DUP_V4_ADDR: u16          = 21;        // Duplicate IPv4 Address
    pub const DUP_V6_ADDR: u16          = 22;        // Duplicate IPv6 Address
    pub const ECN_SUPPORT: u16          = 53;        // ECN Support
    pub const IDLE_TIMEOUT: u16         = 23;        // Idle Timeout
    pub const IMAGE_DATA: u16           = 24;        // Image Data
    pub const IMAGE_ID: u16             = 25;        // Image Identifier
    pub const IMAGE_INFO: u16           = 26;        // Image Information
    pub const INIT_DOWNLOAD: u16        = 27;        // Initiate Download
    pub const LOCATION_DATA: u16        = 28;        // Location Data
    pub const MAX_MSG_LEN: u16          = 29;        // Maximum Message Length
    pub const MTU_DISC_PAD: u16         = 52;        // MTU Discovery Padding
    pub const RADIO_ADMIN_STATE: u16    = 31;        // Radio Administrative State
    pub const RADIO_OP_STATE: u16       = 32;        // Radio Operational State
    pub const RESULT_CODE: u16          = 33;        // Result Code
    pub const RETURNED_MSG_ELEM: u16    = 34;        // Returned Message Element
    pub const SESSION_ID: u16           = 35;        // Session ID
    pub const STATS_TIMER: u16          = 36;        // Statistics Timer
    pub const VENDOR_PAYLOAD: u16       = 37;        // Vendor Specific Payload
    pub const WTP_BOARD_DATA: u16       = 38;        // WTP Board Data
    pub const WTP_DESCRIPTOR: u16       = 39;        // WTP Descriptor
    pub const WTP_FALLBACK: u16         = 40;        // WTP Fallback
    pub const WTP_FRAME_TUN_MODE: u16   = 41;        // WTP Frame Tunnel Mode
    pub const WTP_MAC_TYPE: u16         = 44;        // WTP MAC Type
    pub const WTP_NAME: u16             = 45;        // WTP Name
    pub const WTP_RADIO_STATS: u16      = 47;        // WTP Radio Statistics
    pub const WTP_REBOOT_STATS: u16     = 48;        // WTP Reboot Statistics
    pub const WTP_STATIC_ADDR_INFO: u16 = 49;        // WTP Static IP Address Information
    pub const WTP_RADIO_INFO: u16       = 1048;      // RFC 5416 6.2, IEEE 802.11 WTP Radio Information
}

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
        self.add_elem(33, &[0])
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
