//! 802.1X / IEEE 802.11 security model: RSN information element, EAP PDU codec
//! and port state machine.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Includes the persisted AC security profile store. Byte layouts follow RFC
//! 5416 (802.11 bindings) and IEEE 802.11i / RFC 3748; all multi-byte values
//! are big-endian.

#![allow(dead_code)] // protocol models; wired as WLAN/RADIUS handling lands

use std::sync::Arc;

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use crate::db::Db;

/// Default RSN OUI anchor used by all IEEE 802.11 cipher/AKM suites
/// (`00:0f:ac`).
#[allow(dead_code)]
const RSN_OUI: [u8; 3] = [0x00, 0x0f, 0xac];

/// RSN protocol generation advertised through the RSN version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum WpaVersion {
    Wpa,
    Wpa2,
    Wpa3,
}

/// IEEE 802.11 cipher suite identifiers (the low byte of the RSN OUI anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum Cipher {
    Group,   // use group cipher (reserved, id 0)
    Wep40,   // id 1
    Tkip,    // id 2
    Ccmp,    // id 4
    Wep104,  // id 5
    BipCmac, // id 6
}

impl Cipher {
    #[allow(dead_code)]
    fn id(self) -> u8 {
        match self {
            Cipher::Group => 0x0,
            Cipher::Wep40 => 0x1,
            Cipher::Tkip => 0x2,
            Cipher::Ccmp => 0x4,
            Cipher::Wep104 => 0x5,
            Cipher::BipCmac => 0x6,
        }
    }
}

/// IEEE 802.11 AKM suite identifiers used to select the authentication + key
/// management method between the station and the AC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum Akm {
    Dot1x,       // 802.1X / PMKSA caching, id 1
    Psk,         // WPA/WPA2-PSK, id 2
    FtDot1x,     // Fast BSS transition over 802.1X, id 3
    FtPsk,       // Fast BSS transition over PSK, id 4
    Dot1xSha256, // 802.1X / SHA-256, id 5
    PskSha256,   // PSK / SHA-256, id 6
    Sae,         // WPA3 personal (SAE), id 8
}

impl Akm {
    fn id(self) -> u8 {
        match self {
            Akm::Dot1x => 0x1,
            Akm::Psk => 0x2,
            Akm::FtDot1x => 0x3,
            Akm::FtPsk => 0x4,
            Akm::Dot1xSha256 => 0x5,
            Akm::PskSha256 => 0x6,
            Akm::Sae => 0x8,
        }
    }
}

/// RSN capabilities octet flags (RSNA capabilities as a u16 bitmask).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RsnCaps(pub u16);

#[allow(unused)]
impl RsnCaps {
    pub const PRE_AUTH: u16 = 0x0001;
    pub const NO_PAIRWISE: u16 = 0x0004;
    pub const MFPC: u16 = 0x0100; // management frame protection capable
    pub const MFPR: u16 = 0x0200; // management frame protection required
    pub const SAE_H2E: u16 = 0x2000;
}
fn suite(id: u8) -> [u8; 4] {
    [RSN_OUI[0], RSN_OUI[1], RSN_OUI[2], id]
}

/// A parsed/encoded RSN information element body (starts at the Version field;
/// the element Tag (48) / Length header is not included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsnInfo {
    pub group: Cipher,
    pub pairwise: Cipher,
    pub akm: Akm,
    pub caps: RsnCaps,
}

#[allow(dead_code)] // wired once WLAN config parsing lands
impl RsnInfo {
    /// Encode the element body. Layout follows IEEE 802.11i section 8.4.2.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(18);
        v.extend_from_slice(&1u16.to_be_bytes()); // version (RSN == 1)
        v.extend_from_slice(&suite(self.group.id()));
        v.extend_from_slice(&1u16.to_be_bytes()); // pairwise count
        v.extend_from_slice(&suite(self.pairwise.id()));
        v.extend_from_slice(&1u16.to_be_bytes()); // AKM count
        v.extend_from_slice(&suite(self.akm.id()));
        v.extend_from_slice(&self.caps.0.to_be_bytes());
        v
    }

    /// Parse an RSN element body. Only single-suite lists are decoded; longer
    /// lists are rejected so an unsupported policy surfaces explicitly.
    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < 18 {
            return Err(anyhow!("RSN element too short"));
        }
        let version = u16::from_be_bytes([body[0], body[1]]);
        if version != 1 {
            return Err(anyhow!("unsupported RSN version {}", version));
        }
        let _group = &body[2..6];
        let grp_id = _group[3];
        let pw_count = u16::from_be_bytes([body[6], body[7]]) as usize;
        let pair_start = 8;
        let pair_bytes = pw_count.saturating_mul(4);
        if body.len() < pair_start + pair_bytes + 2 {
            return Err(anyhow!("pairwise list truncated"));
        }
        let pairwise_id = body[pair_start + 3]; // first (single) suite
        let akm_count_off = pair_start + pair_bytes;
        let akm_count = u16::from_be_bytes([body[akm_count_off], body[akm_count_off + 1]]) as usize;
        if akm_count != 1 {
            return Err(anyhow!("only single-AKM RSN supported"));
        }
        let akm_start = akm_count_off + 2;
        let akm_id = body[akm_start + 3];
        let caps = u16::from_be_bytes([body[akm_start + 4], body[akm_start + 5]]);

        Ok(RsnInfo {
            group: cipher_from_id(grp_id)?,
            pairwise: cipher_from_id(pairwise_id)?,
            akm: akm_from_id(akm_id)?,
            caps: RsnCaps(caps),
        })
    }
}

fn cipher_from_id(id: u8) -> Result<Cipher> {
    Ok(match id {
        0x0 => Cipher::Group,
        0x1 => Cipher::Wep40,
        0x2 => Cipher::Tkip,
        0x4 => Cipher::Ccmp,
        0x5 => Cipher::Wep104,
        0x6 => Cipher::BipCmac,
        other => return Err(anyhow!("unknown cipher suite 0x{:02x}", other)),
    })
}

fn akm_from_id(id: u8) -> Result<Akm> {
    Ok(match id {
        0x1 => Akm::Dot1x,
        0x2 => Akm::Psk,
        0x3 => Akm::FtDot1x,
        0x4 => Akm::FtPsk,
        0x5 => Akm::Dot1xSha256,
        0x6 => Akm::PskSha256,
        0x8 => Akm::Sae,
        other => return Err(anyhow!("unknown AKM 0x{:02x}", other)),
    })
}

/// EAP packet code (RFC 3748 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

/// EAP method type byte within Request/Response packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum EapMethod {
    Identity = 1,
    Notification = 2,
    Nak = 3,
    Md5Challenge = 4,
    Otp = 5,
    Gtc = 6,
    Tls = 13,
}

/// A single EAP packet: 4-byte header (code, id, length) plus, for
/// Request/Response, a method type and method-specific data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPkt {
    pub code: EapCode,
    pub id: u8,
    pub method: Option<EapMethod>,
    pub data: Vec<u8>,
}

impl EapPkt {
    pub fn request(id: u8, method: EapMethod, data: Vec<u8>) -> Self {
        EapPkt {
            code: EapCode::Request,
            id,
            method: Some(method),
            data,
        }
    }

    pub fn response(id: u8, method: EapMethod, data: Vec<u8>) -> Self {
        EapPkt {
            code: EapCode::Response,
            id,
            method: Some(method),
            data,
        }
    }

    pub fn success(id: u8) -> Self {
        EapPkt {
            code: EapCode::Success,
            id,
            method: None,
            data: Vec::new(),
        }
    }

    pub fn failure(id: u8) -> Self {
        EapPkt {
            code: EapCode::Failure,
            id,
            method: None,
            data: Vec::new(),
        }
    }

    /// Encode the 4-byte header plus optional type byte and data.
    pub fn encode(&self) -> Vec<u8> {
        let body_len = self.data.len() + usize::from(self.method.is_some());
        let total = 4 + body_len;
        let mut v = Vec::with_capacity(total);
        v.push(self.code as u8);
        v.push(self.id);
        v.extend_from_slice(&(total as u16).to_be_bytes());
        if let Some(m) = self.method {
            v.push(m as u8);
        }
        v.extend_from_slice(&self.data);
        v
    }

    /// Parse an EAP packet from its full wire encoding.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(anyhow!("EAP packet too short"));
        }
        let code = match buf[0] {
            1 => EapCode::Request,
            2 => EapCode::Response,
            3 => EapCode::Success,
            4 => EapCode::Failure,
            other => return Err(anyhow!("invalid EAP code {}", other)),
        };
        let id = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || buf.len() < len {
            return Err(anyhow!("invalid EAP length"));
        }
        let (method, data) = match code {
            EapCode::Request | EapCode::Response => {
                let m = match buf[4] {
                    1 => EapMethod::Identity,
                    2 => EapMethod::Notification,
                    3 => EapMethod::Nak,
                    4 => EapMethod::Md5Challenge,
                    5 => EapMethod::Otp,
                    6 => EapMethod::Gtc,
                    13 => EapMethod::Tls,
                    other => return Err(anyhow!("unsupported EAP type {}", other)),
                };
                (Some(m), buf[5..len].to_vec())
            }
            _ => (None, buf[4..len].to_vec()),
        };
        Ok(EapPkt {
            code,
            id,
            method,
            data,
        })
    }
}

/// 802.1X port state (IEEE 802.1X authenticator / RFC 5416 supplicant model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum Dot1xState {
    Initialize,
    Disconnected,
    Connecting,
    Authenticating,
    Authenticated,
    Holding,
}

/// State transitions that confirm the EAP exchange arrived/succeeded:
/// an identity request moves the port to Authenticating, success to
/// Authenticated, and any failure resets it.
pub fn transition(state: Dot1xState, eap: &EapPkt) -> Dot1xState {
    match (state, eap.code) {
        (Dot1xState::Connecting, EapCode::Request) => Dot1xState::Authenticating,
        (Dot1xState::Authenticating, EapCode::Request) => Dot1xState::Authenticating,
        (Dot1xState::Authenticating, EapCode::Success) => Dot1xState::Authenticated,
        (Dot1xState::Authenticating, EapCode::Failure) => Dot1xState::Disconnected,
        (Dot1xState::Authenticated, EapCode::Failure) => Dot1xState::Disconnected,
        (other, _) => other,
    }
}

/// A finite EAP identity/method conversation hosted by the AC side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapSession {
    pub state: Dot1xState,
    pub id: u8,
    pub method: EapMethod,
}

impl EapSession {
    pub fn new(method: EapMethod) -> Self {
        EapSession {
            state: Dot1xState::Connecting,
            id: 0,
            method,
        }
    }

    pub fn next_id(&mut self) -> u8 {
        self.state = transition(self.state, &EapPkt::request(self.id, self.method, vec![]));
        self.id
    }

    /// Drive the session: absorb a station Response and return the next AC
    /// action. `None` means authentication completed (Success sent).
    pub fn handle_response(&mut self, resp: &EapPkt) -> Result<Option<EapPkt>> {
        if resp.id != self.id {
            return Err(anyhow!("stale EAP id {} != {}", resp.id, self.id));
        }
        // In-band success/failure are terminal packets (RFC 3748).
        match resp.code {
            EapCode::Success => {
                self.state = transition(self.state, resp);
                Ok(None)
            }
            EapCode::Failure => {
                self.state = transition(self.state, resp);
                Ok(None)
            }
            EapCode::Response => {
                // For a non-interactive method (e.g. external RADIUS), the AC
                // can hand off; a TLS handshake would need multiple passes.
                Ok(Some(EapPkt::request(
                    self.next_id(),
                    self.method,
                    Vec::new(),
                )))
            }
            EapCode::Request => Err(anyhow!("unexpected request in response slot")),
        }
    }
}

/// A persisted WLAN security profile (RSN policy) the AC can hand to WTPs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityProfile {
    pub id: i64,
    pub name: String,
    pub method: String, // "wpa2-psk" | "wpa3-sae" | "802.1x" etc.
    pub cipher: String, // "ccmp" | "tkip" ...
    pub caps: u16,      // RsnCaps bitmask
}

/// Operations over the security_profiles table.
pub struct ProfileStore {
    db: Arc<Db>,
}

impl ProfileStore {
    pub fn new(db: Arc<Db>) -> Self {
        ProfileStore { db }
    }

    /// Insert a new profile or update by name. Returns `Ok(true)` on insert.
    pub fn upsert(&self, name: &str, method: &str, cipher: &str, caps: u16) -> Result<bool> {
        let conn = self.db.lock();
        let existing = conn
            .query_row(
                "SELECT id FROM security_profiles WHERE name=?1",
                params![name],
                |_| Ok(()),
            )
            .optional()?;
        let created = existing.is_none();
        if created {
            conn.execute(
                "INSERT INTO security_profiles (name,method,cipher,caps) VALUES (?1,?2,?3,?4)",
                params![name, method, cipher, caps],
            )?;
        } else {
            conn.execute(
                "UPDATE security_profiles SET method=?2, cipher=?3, caps=?4 WHERE name=?1",
                params![name, method, cipher, caps],
            )?;
        }
        Ok(created)
    }

    pub fn list(&self) -> Result<Vec<SecurityProfile>> {
        let conn = self.db.lock();
        let mut stmt =
            conn.prepare("SELECT id,name,method,cipher,caps FROM security_profiles ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(SecurityProfile {
                id: r.get(0)?,
                name: r.get(1)?,
                method: r.get(2)?,
                cipher: r.get(3)?,
                caps: r.get::<_, u16>(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn get(&self, name: &str) -> Result<Option<SecurityProfile>> {
        let conn = self.db.lock();
        let p = conn
            .query_row(
                "SELECT id,name,method,cipher,caps FROM security_profiles WHERE name=?1",
                params![name],
                |r| {
                    Ok(SecurityProfile {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        method: r.get(2)?,
                        cipher: r.get(3)?,
                        caps: r.get::<_, u16>(4)?,
                    })
                },
            )
            .optional()?;
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsn_roundtrip() {
        let r = RsnInfo {
            group: Cipher::Ccmp,
            pairwise: Cipher::Ccmp,
            akm: Akm::Psk,
            caps: RsnCaps(RsnCaps::MFPC),
        };
        let bytes = r.encode();
        assert_eq!(bytes.len(), 20);
        assert_eq!(RsnInfo::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn eap_codec() {
        let p = EapPkt::request(7, EapMethod::Identity, vec![]);
        let bytes = p.encode();
        assert_eq!(bytes.len(), 5);
        assert_eq!(EapPkt::decode(&bytes).unwrap(), p);

        let resp = EapPkt::response(7, EapMethod::Identity, b"user@realm".to_vec());
        assert_eq!(EapPkt::decode(&resp.encode()).unwrap(), resp);

        let ok = EapPkt::success(7);
        let enc = ok.encode();
        assert_eq!(enc.len(), 4);
        assert_eq!(EapPkt::decode(&enc).unwrap(), ok);
    }

    #[test]
    fn eap_session_identity_to_success() {
        let mut s = EapSession::new(EapMethod::Identity);
        let req = EapPkt::request(s.next_id(), EapMethod::Identity, vec![]);
        assert_eq!(s.state, Dot1xState::Authenticating);

        let resp = EapPkt::response(req.id, EapMethod::Identity, b"u@r".to_vec());
        let next = s.handle_response(&resp).unwrap();
        assert!(next.is_some()); // AC continues the exchange

        let done = EapPkt::success(s.id);
        assert_eq!(s.handle_response(&done).unwrap(), None);
        assert_eq!(s.state, Dot1xState::Authenticated);
    }

    #[test]
    fn profiles_persist() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let p = ProfileStore::new(db.clone());
        assert!(p.upsert("corp", "802.1x", "ccmp", RsnCaps::MFPC).unwrap());
        assert!(!p.upsert("corp", "802.1x", "ccmp", RsnCaps::MFPC).unwrap());
        assert_eq!(p.list().unwrap().len(), 1);
        assert_eq!(p.get("corp").unwrap().unwrap().cipher, "ccmp");
        assert!(p.get("guest").unwrap().is_none());
    }
}
