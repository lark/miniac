//! 802.11k / 802.11v / 802.11r roaming support on the AC side.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Provides the neighbor-report (11k RRM), BSS-transition (11v BTM) and
//! fast-BSS-transition (FT) policy models the AC uses to steer client roaming
//! and to hand transition parameters to the WTPs. Byte layouts follow the
//! IEEE 802.11 management-element encodings; multi-byte fields are big-endian.

#![allow(dead_code)] // protocol models; wired as RRM/BTM/RR FT handling lands

use anyhow::{anyhow, Result};

/// PHY type octet used by the 802.11k Neighbor Report element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
pub enum PhyType {
    Dsss,
    Ofdm,
    HrDsss,
    Erp,
    Ht,
    Vht,
    He,
    Htm,
}

impl PhyType {
    fn byte(self) -> u8 {
        match self {
            PhyType::Dsss => 0x01,
            PhyType::Ofdm => 0x02,
            PhyType::HrDsss => 0x03,
            PhyType::Erp => 0x04,
            PhyType::Ht => 0x05,
            PhyType::Vht => 0x07,
            PhyType::He => 0x08,
            PhyType::Htm => 0x09,
        }
    }
}

/// A single 802.11k Neighbor Report entry (element ID 52) body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    pub bssid: [u8; 6],
    pub bssid_info: u32,
    pub operating_class: u8,
    pub channel: u8,
    pub phy_type: PhyType,
    /// Optional 16-byte neighbor P2P (vendor) info; empty when absent.
    pub tsf: Vec<u8>,
}

impl NeighborEntry {
    /// Encode the element body (Tag 52 / Length header excluded).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(13 + self.tsf.len());
        v.extend_from_slice(&self.bssid);
        v.extend_from_slice(&self.bssid_info.to_be_bytes());
        v.push(self.operating_class);
        v.push(self.channel);
        v.push(self.phy_type.byte());
        v.extend_from_slice(&self.tsf);
        v
    }

    /// Parse a Neighbor Report entry body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < 13 {
            return Err(anyhow!("neighbor entry too short"));
        }
        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&body[..6]);
        let bssid_info = u32::from_be_bytes([body[6], body[7], body[8], body[9]]);
        let operating_class = body[10];
        let channel = body[11];
        let phy_type = match body[12] {
            0x01 => PhyType::Dsss,
            0x02 => PhyType::Ofdm,
            0x03 => PhyType::HrDsss,
            0x04 => PhyType::Erp,
            0x05 => PhyType::Ht,
            0x07 => PhyType::Vht,
            0x08 => PhyType::He,
            0x09 => PhyType::Htm,
            other => return Err(anyhow!("unknown PHY type 0x{:02x}", other)),
        };
        let tsf = body[13..].to_vec();
        Ok(NeighborEntry {
            bssid,
            bssid_info,
            operating_class,
            channel,
            phy_type,
            tsf,
        })
    }
}

/// 802.11v BSS Transition Management request flags (waypoint / disassoc).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransitionFlags(pub u8);

#[allow(unused)]
impl TransitionFlags {
    pub const DISASSOC_IMMINENT: u8 = 0x01;
    pub const BSS_TERMINATION_INCLUDED: u8 = 0x02;
    pub const PREFERRED_BSS_LIST: u8 = 0x40; // same band preference
    pub const ABRIDGED: u8 = 0x80;
}

/// 802.11r Mobility Domain Information element (MDIE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MobilityDomain {
    pub mdid: u16,
    pub ftd_caps: u8,
}

impl MobilityDomain {
    /// Encode the element (Tag 54 / Length header included for completeness).
    pub fn encode(&self) -> Vec<u8> {
        vec![
            54,
            3,
            (self.mdid >> 8) as u8,
            (self.mdid & 0xff) as u8,
            self.ftd_caps,
        ]
    }

    /// Parse an MDIE including its Tag/Length header.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 5 || buf[0] != 54 || buf[1] != 3 {
            return Err(anyhow!("invalid MDIE"));
        }
        Ok(MobilityDomain {
            mdid: u16::from_be_bytes([buf[2], buf[3]]),
            ftd_caps: buf[4],
        })
    }
}

/// The AC-side roaming policy attached to a WLAN, consumed later by the
/// Configuration Update path to push 11k/11v/11r capability bits to the WTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoamPolicy {
    pub rrm: bool, // 802.11k radio resource measurement
    pub btm: bool, // 802.11v BSS transition management
    pub ft: bool,  // 802.11r fast BSS transition
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_entry_roundtrip() {
        let e = NeighborEntry {
            bssid: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            bssid_info: 0x80000001,
            operating_class: 115,
            channel: 36,
            phy_type: PhyType::Vht,
            tsf: vec![1, 2, 3],
        };
        let enc = e.encode();
        assert_eq!(NeighborEntry::decode(&enc).unwrap(), e);
    }

    #[test]
    fn mobility_domain_roundtrip() {
        let md = MobilityDomain {
            mdid: 0x1234,
            ftd_caps: 0x01,
        };
        assert_eq!(MobilityDomain::decode(&md.encode()).unwrap(), md);
    }

    #[test]
    fn policy_bit_report() {
        let p = RoamPolicy {
            rrm: true,
            btm: true,
            ft: false,
        };
        assert!(p.rrm && p.btm && !p.ft);
        let n = (u8::from(p.rrm) << 0) | (u8::from(p.btm) << 1) | (u8::from(p.ft) << 2);
        assert_eq!(n, 0b011);
        let _ = TransitionFlags::PREFERRED_BSS_LIST; // keep docs constant reachable
    }
}
