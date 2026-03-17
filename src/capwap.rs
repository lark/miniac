use anyhow::{anyhow, Result};
use std::time::{Instant, Duration};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MsgType {
    JoinReq = 1,
    JoinResp = 2,
    ConfigReq = 3,
    ConfigResp = 4,
    EchoReq = 13,
    EchoResp = 14,
    Unknown,
}

impl From<u32> for MsgType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::JoinReq,
            2 => Self::JoinResp,
            3 => Self::ConfigReq,
            4 => Self::ConfigResp,
            13 => Self::EchoReq,
            14 => Self::EchoResp,
            _ => Self::Unknown,
        }
    }
}

impl MsgType {
    pub fn is_request(&self) -> bool {
        match self {
            Self::JoinReq | Self::ConfigReq | Self::EchoReq => true,
            _ => false,
        }
    }

    pub fn is_response(&self) -> bool {
        match self {
            Self::JoinResp | Self::ConfigResp | Self::EchoResp => true,
            _ => false,
        }
    }
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

#[derive(Debug, Clone)]
pub struct Wlan {
    pub wlan_id: u8,
    pub ssid: String,
    pub enabled: bool,
    pub bssid: [u8; 6],
}

#[derive(Debug, Clone)]
pub struct Radio {
    pub id: u8,
    pub radio_type: u8,
    pub admin_state: u8,
    pub wlans: Vec<Wlan>,
}

pub struct LastSentPkt {
    pub buf: Vec<u8>,
    pub seq: u8,
    pub msg_type: MsgType,
    pub send_time: Instant,
    pub retry_count: u32,
}

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

    pub last_sent: Option<LastSentPkt>,
    pub retrans_interval: Duration,
    pub max_retries: u32,

    pub last_recv_time: Instant,
    pub echo_interval: Duration,

    pub seq_counter: u8,
}

impl CtrlHdr {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 { return Err(anyhow!("hdr too short")); }
        Ok(Self {
            msg_type: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            seq_num: buf[4],
            elem_len: u16::from_be_bytes([buf[5], buf[6]]),
            flags: buf[7],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&u32::from(self.msg_type).to_be_bytes());
        buf.push(self.seq_num);
        buf.extend_from_slice(&self.elem_len.to_be_bytes());
        buf.push(self.flags);

        buf
    }

    pub fn msg_type(&self) -> MsgType {
        MsgType::from(self.msg_type)
    }
}

impl CtrlMsg {
    pub fn new(m_type: MsgType, seq: u8) -> Self {
        Self {
            hdr: CtrlHdr {
                msg_type: m_type as u32,
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
            buf.extend_from_slice(&elem.tag.to_be_bytes());
            buf.extend_from_slice(&(elem.data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&elem.data);
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

impl Radio {
    pub fn admin_payload(&self) -> Vec<u8> {
        vec![self.id, self.admin_state]
    }
}

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
            retrans_interval: Duration::from_secs(5),
            max_retries: 3,
            last_recv_time: Instant::now(),
            echo_interval: Duration::from_secs(30),
            seq_counter: 100,
        }
    }

    pub fn set_last_sent(&mut self, msg: &CtrlMsg, buf: Vec<u8>) {
        self.last_sent = Some(LastSentPkt {
            buf,
            seq: msg.hdr.seq_num,
            msg_type: msg.hdr.msg_type(),
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
