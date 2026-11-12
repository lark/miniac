//! Vendor profile selection for the configuration message families.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! miniac carries separate forms for the Configuration Status Response, the
//! Configuration Update Request, the Reset Request and the Clear Configuration
//! Request: a vendor-neutral RFC 5415 form plus vendor overlays (H3C AX60/M60,
//! TP-Link AC100). The profile selects which form and which control framing a
//! session speaks.
//!
//! When several vendors' WTPs meet one miniac, the profile is detected per
//! device from its Discovery/Join Request (see [`VendorProfile::detect`]); a
//! device whose vendor has no custom form falls back to the RFC profile.

use std::net::Ipv4Addr;
use std::path::Path;

use crate::capwap::{CtrlMsg, MsgElemType, MsgType};
use crate::config::{self, Akm, Cipher, SecurityPolicy};
use crate::elements::ImageIdentifier;
use crate::vendor::framing::CtrlFrame;
use crate::vendor::{h3c, ruijie, tplink, vsp};

/// Which vendor form a session speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VendorProfile {
    /// H3C AX60/M60: H3C framing (RFC header plus a 4-byte sequence field) and
    /// private elements carried as bare top-level tags.
    H3c,
    /// TP-Link AC100: RFC framing and private elements nested in the RFC
    /// Vendor Specific Payload element (37).
    TpLink,
    /// Ruijie RG-AP120-A (RGOS FIT AP): RFC framing, private elements as bare
    /// top-level tags, and the `0x33DD01`/`0x33DD02` WLAN update messages.
    Ruijie,
    /// Vendor-neutral RFC 5415 forms; the default for unrecognized devices.
    #[default]
    Rfc,
}

impl VendorProfile {
    /// Detect the profile a WTP speaks from its Discovery/Join Request.
    ///
    /// The control framing is the primary signal: H3C AX60-style WTPs widen the
    /// Sequence field to four bytes for the whole session, so their messages
    /// carry `MsgElemLen` at offset 16 and elements at offset 19, whereas
    /// RFC 5415 (and TP-Link) put `MsgElemLen` at offset 13 and elements at
    /// offset 16. A frame is H3C-framed when its H3C-shaped length equals
    /// `len - 16` while its RFC-shaped length does not.
    ///
    /// Otherwise the request is RFC-framed and the profile comes from the vendor
    /// identifier in the Vendor Specific Payload (element 37) — TP-Link AC100
    /// carries its enterprise number there. A device whose identifier has no
    /// custom form falls back to the vendor-neutral RFC profile.
    pub fn detect(req: &[u8]) -> Self {
        if is_h3c_framed(req) {
            return VendorProfile::H3c;
        }
        if let Some(profile) = Self::for_vendor_id(rfc_vsp_vendor_id(req)) {
            return profile;
        }
        if ruijie::looks_like_ruijie(req) {
            return VendorProfile::Ruijie;
        }
        VendorProfile::Rfc
    }

    /// Profile for a vendor identifier (IANA enterprise number, as carried in
    /// the Vendor Specific Payload). Only identifiers with a custom form are
    /// listed, so [`VendorProfile::detect`] falls back to RFC otherwise.
    pub fn for_vendor_id(id: Option<u32>) -> Option<Self> {
        match id? {
            tplink::VENDOR_ID => Some(VendorProfile::TpLink),
            _ => None,
        }
    }

    /// Control-channel framing this profile encodes with.
    pub fn frame(self) -> CtrlFrame {
        match self {
            VendorProfile::H3c => CtrlFrame::H3c,
            _ => CtrlFrame::Rfc,
        }
    }

    /// Directory holding an optional vendor DTLS identity (`server.pem`). Missing
    /// files fall back to the redistributable identities under `certs/default`.
    pub fn cert_dir(self) -> &'static Path {
        match self {
            VendorProfile::H3c => Path::new("certs/h3c"),
            VendorProfile::TpLink => Path::new("certs/tplink"),
            VendorProfile::Ruijie => Path::new("certs/ruijie"),
            VendorProfile::Rfc => Path::new("certs/rfc"),
        }
    }

    /// Discovery Response for this profile, framed to wire bytes.
    ///
    /// H3C mirrors the request's private prefix; the RFC and TP-Link forms use
    /// the standards-shaped builder (`config::discovery_response`) with the
    /// TP-Link enterprise number carried in the AC Descriptor.
    pub fn discovery_response(
        self,
        req: &[u8],
        ac_ips: &[Ipv4Addr],
        ac_name: &[u8],
    ) -> Option<Vec<u8>> {
        match self {
            VendorProfile::H3c => h3c::discovery_response(req, ac_ips, ac_name),
            VendorProfile::TpLink | VendorProfile::Ruijie | VendorProfile::Rfc => {
                // RFC 5415 Discovery Request: 8-byte base header, Message Type at
                // [8..12] (Discovery Request = 1), 1-byte sequence at [12].
                if req.len() < 16 || req[11] != 1 {
                    return None;
                }
                let vendor_id = match self {
                    VendorProfile::TpLink => tplink::VENDOR_ID,
                    _ => 0,
                };
                Some(
                    config::discovery_response(req[12] as u32, ac_ips, ac_name, vendor_id)
                        .encode_for(self.frame()),
                )
            }
        }
    }

    /// Join Response for this profile. `ok` is false for an unapproved WTP.
    pub fn join_response(self, seq: u32, ac_ip: Ipv4Addr, ac_name: &[u8], ok: bool) -> CtrlMsg {
        match self {
            VendorProfile::H3c => h3c::join_response(seq, ac_ip, ok),
            VendorProfile::TpLink => tplink::join_response(seq, ac_ip, ac_name, ok),
            VendorProfile::Ruijie => ruijie::join_response(seq, ac_ip, ac_name, ok),
            VendorProfile::Rfc => config::join_response(seq, ac_ip, ac_name, 0, ok),
        }
    }

    /// Reset Request for this profile.
    ///
    /// H3C uses its fixed `all_version` image identifier; TP-Link and RFC carry
    /// a caller-supplied name (AC100 sends its own software version there).
    /// TP-Link additionally attaches the private reset mask.
    pub fn reset_request(self, seq: u32, image_name: &[u8]) -> CtrlMsg {
        match self {
            VendorProfile::H3c => h3c::reset_request(seq, image_name),
            VendorProfile::TpLink => {
                tplink::reset_request(seq, image_name, tplink::RESET_MASK_RESTART)
            }
            VendorProfile::Ruijie | VendorProfile::Rfc => {
                config::reset_request(seq, &ImageIdentifier::new(0, image_name.to_vec()))
            }
        }
    }

    /// Clear Configuration Request for this profile.
    ///
    /// The RFC 5415 mtype 23 form is also what H3C expects. TP-Link AC100 has no
    /// such message — it restores defaults through the reset mask — so a caller
    /// that needs AC100 restore-defaults semantics must send
    /// [`VendorProfile::reset_request`] with a factory-default mask instead.
    pub fn clear_config_request(self, seq: u32) -> CtrlMsg {
        config::clear_config_request(seq)
    }

    /// LED on/off Configuration Update for this profile.
    ///
    /// H3C carries the u32 state in its 0xfdf4 element. TP-Link AC100 wraps the
    /// same u32 in private 57 inside the Vendor Specific Payload (captured from
    /// a TL-AC100 ↔ TL-AP1300GI session). Ruijie uses VSP 0x13dc with a
    /// `[mode, state]` payload. RFC has no standard LED element, so it keeps the
    /// H3C-shaped tag it used before.
    pub fn led_update_request(self, seq: u32, on: bool) -> CtrlMsg {
        match self {
            VendorProfile::TpLink => tplink::led_update_request(seq, on),
            VendorProfile::Ruijie => ruijie::led_update_request(seq, on),
            VendorProfile::H3c | VendorProfile::Rfc => {
                CtrlMsg::new(MsgType::CONFIG_UPDATE_REQ, seq)
                    .add_elem(h3c::CFG_LED, &u32::from(on).to_be_bytes())
            }
        }
    }

    /// Map a vendor-neutral IEEE channel number to this vendor's radio-config
    /// channel field value; `channel` is 0 for auto (ACS).
    ///
    /// This is the single place a generic IEEE channel number turns into a
    /// vendor value: TP-Link carries an ACS sentinel (0) on auto and a channel
    /// number on a fixed pin; H3C's 0xfde8 radio header carries the IEEE channel
    /// number verbatim (0 = AUTO), so it passes through unchanged.
    pub fn radio_channel_field(self, channel: u32) -> u32 {
        match self {
            VendorProfile::TpLink => u32::from(tplink::channel_field(channel)),
            VendorProfile::H3c | VendorProfile::Ruijie | VendorProfile::Rfc => channel,
        }
    }

    /// Registry token for this profile, used to key `product_caps`.
    pub fn caps_token(self) -> &'static str {
        match self {
            VendorProfile::H3c => "h3c",
            VendorProfile::TpLink => "tplink",
            VendorProfile::Ruijie => "ruijie",
            VendorProfile::Rfc => "rfc",
        }
    }

    /// Vendor family label stored on the learned device row and shown in the
    /// device views. The capability registry lookup matches both `tp-link` and
    /// `tplink`.
    pub fn vendor_name(self) -> &'static str {
        match self {
            VendorProfile::H3c => "h3c",
            VendorProfile::TpLink => "tp-link",
            VendorProfile::Ruijie => "ruijie",
            VendorProfile::Rfc => "rfc",
        }
    }

    /// Map a generic [`SecurityPolicy`] to this vendor's wire selectors.
    ///
    /// A product that cannot express the requested policy exactly is snapped to
    /// the closest mode it does support (never below the WPA-PSK+AES floor, and
    /// never dropping an existing client class silently) and the substitution is
    /// reported through [`SecurityFields::warning`]. The limitations mirror the
    /// `product_caps` registry.
    pub fn security_fields(self, policy: &SecurityPolicy) -> SecurityFields {
        match self {
            // AX60/M60 can express Open, WPA/WPA2-PSK and the WPA2/WPA3 mixed
            // mode (ssid_enc 4 / 6) but has no pure-WPA3 value: a requested
            // WPA3-SAE network becomes the WPA2/WPA3 mixed mode.
            VendorProfile::H3c => {
                let (encrypt, warning) = match policy.akm {
                    Akm::Open => (0, None),
                    Akm::Psk => (4, None),
                    Akm::PskSae => (6, None),
                    Akm::Sae => (
                        6,
                        Some(
                            "H3C has no pure WPA3-SAE mode; pushed as WPA2/WPA3-PSK mixed \
                             (WPA3 clients are served, WPA2 clients are kept working)"
                                .to_string(),
                        ),
                    ),
                };
                SecurityFields {
                    encrypt,
                    cipher: policy.cipher.wire(),
                    auth: 0,
                    warning,
                }
            }
            // AC100 carries a PSK option with auth=2 (WPA2) and an AES/CCMP
            // cipher only; WPA3 and TKIP are uncharacterized, so they are snapped
            // up to WPA2-PSK + AES with a note.
            VendorProfile::TpLink => {
                let mut warnings = Vec::new();
                let akm = match policy.akm {
                    Akm::Open | Akm::Psk => policy.akm,
                    Akm::PskSae | Akm::Sae => {
                        warnings.push(
                            "TP-Link AC100 supports WPA2-PSK only; WPA3 is pushed as WPA2-PSK"
                                .to_string(),
                        );
                        Akm::Psk
                    }
                };
                let cipher = match policy.cipher {
                    Cipher::Ccmp => Cipher::Ccmp,
                    other => {
                        warnings.push(format!(
                            "TP-Link AC100 supports AES/CCMP only; {} is pushed as AES",
                            other.as_str()
                        ));
                        Cipher::Ccmp
                    }
                };
                SecurityFields {
                    encrypt: if akm.secured() { 1 } else { 0 },
                    cipher: cipher.wire(),
                    auth: if akm.secured() { 2 } else { 0 },
                    warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
                }
            }
            // The RFC / vendor-neutral form carries the policy through the
            // private security element with no lossy mapping.
            VendorProfile::Ruijie | VendorProfile::Rfc => SecurityFields {
                encrypt: if policy.secured() { 1 } else { 0 },
                cipher: policy.cipher.wire(),
                auth: 0,
                warning: None,
            },
        }
    }
}

/// Vendor wire selectors derived from a generic [`SecurityPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFields {
    /// Security/encrypt selector (H3C 0xfde8: 0 open, 4 WPA/WPA2-PSK, 6
    /// WPA2/WPA3 mixed; RFC: 0/1 open/secured).
    pub encrypt: u32,
    /// Cipher wire integer: 1 TKIP / 2 AES / 3 TKIP+AES.
    pub cipher: u32,
    /// Private-9 authentication selector (TP-Link: 2 = WPA2-PSK).
    pub auth: u8,
    /// Set when the requested policy was substituted with a compatible mode.
    pub warning: Option<String>,
}

/// Whether `req` carries the H3C 4-byte-Sequence framing: the length field at
/// the H3C offset (16) describes the frame while the RFC offset (13) does not.
///
/// Both framings put a self-inclusive MsgElemLen (elements + 3) in their length
/// field, so the H3C test is `h3c_len == len - 16` and the RFC test is
/// `rfc_len == len - 16 + 3`; H3C shares the 8-byte base header with an RFC
/// frame, so only the length fields tell them apart.
fn is_h3c_framed(req: &[u8]) -> bool {
    if req.len() < 19 || req.first() != Some(&0x00) {
        return false;
    }
    let body = (req.len() - 16) as u16;
    let rfc_len = u16::from_be_bytes([req[13], req[14]]);
    let h3c_len = u16::from_be_bytes([req[16], req[17]]);
    h3c_len == body && rfc_len != 3 + body
}

/// Vendor identifier from the Vendor Specific Payload (element 37) of an
/// RFC-framed request, if the element is present and well formed.
fn rfc_vsp_vendor_id(req: &[u8]) -> Option<u32> {
    let mut off = 16;
    while off + 4 <= req.len() {
        let tag = u16::from_be_bytes([req[off], req[off + 1]]);
        let len = u16::from_be_bytes([req[off + 2], req[off + 3]]) as usize;
        let value = req.get(off + 4..off + 4 + len)?;
        if tag == MsgElemType::VENDOR_SPECIFIC_PAYLOAD {
            return vsp::split_value(value).map(|(vendor_id, _, _)| vendor_id);
        }
        off += 4 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capwap::MsgType;

    #[test]
    fn framing_follows_profile() {
        assert_eq!(VendorProfile::H3c.frame(), CtrlFrame::H3c);
        assert_eq!(VendorProfile::TpLink.frame(), CtrlFrame::Rfc);
        assert_eq!(VendorProfile::Ruijie.frame(), CtrlFrame::Rfc);
        assert_eq!(VendorProfile::Rfc.frame(), CtrlFrame::Rfc);
        // Unrecognized devices fall back to the RFC profile.
        assert_eq!(VendorProfile::default(), VendorProfile::Rfc);
    }

    #[test]
    fn detect_reads_framing_and_vendor_id() {
        // H3C framing (4-byte Sequence) is recognized from the message itself.
        let h3c = CtrlMsg::new(MsgType::DISC_REQ, 7)
            .add_element(crate::elements::BaseElem::DiscoveryType(1))
            .encode_for(CtrlFrame::H3c);
        assert_eq!(VendorProfile::detect(&h3c), VendorProfile::H3c);

        // An RFC-framed request with the TP-Link enterprise number in the Vendor
        // Specific Payload is TP-Link.
        let tp = CtrlMsg::new(MsgType::DISC_REQ, 7)
            .add_element(crate::elements::BaseElem::VendorSpecific {
                vendor_id: tplink::VENDOR_ID,
                reserved: 0,
                tlvs: vec![],
            })
            .encode_for(CtrlFrame::Rfc);
        assert_eq!(VendorProfile::detect(&tp), VendorProfile::TpLink);

        // An RFC-framed request with an unknown (or absent) vendor identifier
        // falls back to RFC.
        let rfc = CtrlMsg::new(MsgType::DISC_REQ, 7)
            .add_element(crate::elements::BaseElem::VendorSpecific {
                vendor_id: 0x0000_2711,
                reserved: 0,
                tlvs: vec![],
            })
            .encode_for(CtrlFrame::Rfc);
        assert_eq!(VendorProfile::detect(&rfc), VendorProfile::Rfc);
        let bare = CtrlMsg::new(MsgType::DISC_REQ, 7)
            .add_element(crate::elements::BaseElem::DiscoveryType(1))
            .encode_for(CtrlFrame::Rfc);
        assert_eq!(VendorProfile::detect(&bare), VendorProfile::Rfc);

        // Garbage is not mistaken for H3C or TP-Link.
        assert_eq!(VendorProfile::detect(&[0u8; 8]), VendorProfile::Rfc);
    }

    #[test]
    fn reset_request_per_profile() {
        // H3C: a plain restart keeps the vendor-id-0 `all_version` identifier and
        // sends no reset mask; a named image rides vendor id 1916 instead.
        let h3c_msg = VendorProfile::H3c.reset_request(5, b"all_version");
        assert_eq!(h3c_msg.hdr.msg_type, MsgType::RESET_REQ);
        assert_eq!(h3c_msg.elems.len(), 1);
        assert_eq!(h3c_msg.elems[0].tag, crate::capwap::MsgElemType::IMAGE_ID);
        assert_eq!(
            h3c_msg.elems[0].data,
            crate::vendor::h3c::image_id_all_version()
        );
        let h3c_fw = VendorProfile::H3c.reset_request(6, b"fw.bin");
        assert_eq!(
            h3c_fw.elems[0].data,
            crate::vendor::h3c::image_identifier(b"fw.bin")
        );

        // TP-Link carries the caller's name and the private reset mask.
        let tp = VendorProfile::TpLink.reset_request(5, b"sw-version 1.0");
        assert_eq!(tp.elems.len(), 2);
        assert_eq!(tp.elems[0].tag, crate::capwap::MsgElemType::IMAGE_ID);
        assert_eq!(
            tp.elems[1].tag,
            crate::capwap::MsgElemType::VENDOR_SPECIFIC_PAYLOAD
        );

        // The RFC form carries vendor id 0 and no terminator.
        let rfc = VendorProfile::Rfc.reset_request(5, b"fw");
        assert_eq!(rfc.elems.len(), 1);
        assert_eq!(rfc.elems[0].data, vec![0, 0, 0, 0, b'f', b'w']);
    }

    #[test]
    fn clear_config_request_is_vendor_neutral() {
        for p in [
            VendorProfile::H3c,
            VendorProfile::TpLink,
            VendorProfile::Ruijie,
            VendorProfile::Rfc,
        ] {
            let msg = p.clear_config_request(6);
            assert_eq!(msg.hdr.msg_type, MsgType::CLEAR_CONFIG_REQ);
            assert!(msg.elems.is_empty());
        }
    }

    #[test]
    fn discovery_response_per_profile() {
        // RFC-framed Discovery Request: 8-byte base header, Message Type 1 at
        // [8..12], 1-byte sequence 0x2a at [12].
        let req = [
            0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // base header
            0x00, 0x00, 0x00, 0x01, // Discovery Request
            0x2a, // seq
            0x00, 0x00, 0x00, // MsgElemLen + Flags
        ];
        let ac_ip = Ipv4Addr::new(192, 168, 0, 2);

        let rfc = VendorProfile::Rfc
            .discovery_response(&req, &[ac_ip], b"miniac")
            .expect("rfc response");
        // RFC base header, Message Type 2 and the echoed sequence.
        assert_eq!(&rfc[0..8], &[0x00, 0x10, 0x03, 0x00, 0, 0, 0, 0]);
        assert_eq!(&rfc[8..12], &[0, 0, 0, 2]);
        assert_eq!(rfc[12], 0x2a);
        // Elements start at offset 16 (8B base + 8B control header).
        assert_eq!(&rfc[16..18], &crate::capwap::MsgElemType::AC_NAME.to_be_bytes());

        // The TP-Link form is the same shape but carries its enterprise number
        // in the AC Descriptor's AC Information sub-elements.
        let tp = VendorProfile::TpLink
            .discovery_response(&req, &[ac_ip], b"miniac")
            .expect("tplink response");
        let tp_msg = CtrlMsg::decode(CtrlFrame::Rfc, &tp[8..]).expect("decode");
        let desc = tp_msg
            .find_elems(crate::capwap::MsgElemType::AC_DESCRIPTOR)
            .next()
            .expect("descriptor");
        assert_eq!(&desc.data[12..16], &tplink::VENDOR_ID.to_be_bytes());

        // A malformed request (not a Discovery Request) is rejected.
        let mut bad = req;
        bad[11] = 3;
        assert!(VendorProfile::Rfc
            .discovery_response(&bad, &[ac_ip], b"miniac")
            .is_none());
    }

    #[test]
    fn join_response_per_profile() {
        let ac_ip = Ipv4Addr::new(192, 168, 0, 2);
        // H3C keeps its AX60 element set with a 6-byte tag-10 entry.
        let h3c = VendorProfile::H3c.join_response(3, ac_ip, b"miniac", true);
        assert_eq!(h3c.hdr.msg_type, MsgType::JOIN_RESP);
        assert_eq!(
            h3c.find_elems(crate::capwap::MsgElemType::CAPWAP_CTRL_IPV4_ADDR)
                .next()
                .unwrap()
                .data
                .len(),
            6
        );

        // The RFC form follows the standards element order.
        let rfc = VendorProfile::Rfc.join_response(3, ac_ip, b"miniac", true);
        let tags: Vec<u16> = rfc.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                crate::capwap::MsgElemType::RESULT_CODE,
                crate::capwap::MsgElemType::AC_NAME,
                crate::capwap::MsgElemType::AC_DESCRIPTOR,
                crate::capwap::MsgElemType::ECN_SUPPORT,
                crate::capwap::MsgElemType::CAPWAP_LOCAL_IPV4_ADDR,
                crate::capwap::MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
            ]
        );

        // TP-Link reproduces AC100's element set; the CAPWAP Local IPv6 Address
        // (50) carries the AC capability word the WTP latches for the session.
        let tp = VendorProfile::TpLink.join_response(3, ac_ip, b"miniac", true);
        let tags: Vec<u16> = tp.elems.iter().map(|e| e.tag).collect();
        assert_eq!(
            tags,
            vec![
                crate::capwap::MsgElemType::RESULT_CODE,
                crate::capwap::MsgElemType::AC_DESCRIPTOR,
                crate::capwap::MsgElemType::AC_NAME,
                crate::capwap::MsgElemType::CAPWAP_LOCAL_IPV6_ADDR,
                crate::capwap::MsgElemType::CAPWAP_CTRL_IPV4_ADDR,
                crate::capwap::MsgElemType::VENDOR_SPECIFIC_PAYLOAD,
            ]
        );
        assert_eq!(
            tp.find_elems(crate::capwap::MsgElemType::CAPWAP_LOCAL_IPV6_ADDR)
                .next()
                .unwrap()
                .data
                .len(),
            16
        );
    }
}
