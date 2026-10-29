//! Product capability registry and the fleet security arbiter.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! WLAN security has two orthogonal dimensions: key management ([`Akm`]) and
//! cipher ([`Cipher`]). A transition mode (WPA/WPA2, WPA2/WPA3) is not a
//! "stronger" successor to a single mode, it keeps an older client class
//! working; choosing one is a compatibility decision. This module records what
//! each product can express (`product_caps`) and arbitrates a fleet-wide
//! recommendation: the strongest policy that every characterized AP can express
//! while still serving the target client group, and never below the
//! WPA-PSK+AES floor.

use std::sync::Arc;

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::config::{Akm, Cipher, Pmf, SecurityPolicy};
use crate::db::Db;
use crate::vendor::profile::VendorProfile;

/// Client generations a policy must keep working. The target group is a
/// fleet-level parameter, not a per-client registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientGroup {
    /// Legacy mixed fleet: WPA (TKIP) clients must still associate. They need a
    /// separate SSID, because the AES floor cannot serve them.
    Legacy,
    /// WPA2 and newer, the common case for current client devices.
    #[default]
    Wpa2Plus,
    /// WPA3 only.
    Wpa3Only,
}

impl ClientGroup {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientGroup::Legacy => "legacy",
            ClientGroup::Wpa2Plus => "wpa2+",
            ClientGroup::Wpa3Only => "wpa3",
        }
    }

    pub fn from_str(s: &str) -> Option<ClientGroup> {
        match s {
            "legacy" => Some(ClientGroup::Legacy),
            "wpa2+" | "wpa2" => Some(ClientGroup::Wpa2Plus),
            "wpa3" => Some(ClientGroup::Wpa3Only),
            _ => None,
        }
    }
}

impl SecurityPolicy {
    /// Whether this policy keeps the given client group associating.
    pub fn covers(&self, group: ClientGroup) -> bool {
        match group {
            ClientGroup::Legacy => self.covers_wpa1(),
            ClientGroup::Wpa2Plus => self.covers_wpa2(),
            ClientGroup::Wpa3Only => self.covers_wpa3(),
        }
    }

    /// WPA1 (TKIP-era PSK) clients: needs PSK key management and a TKIP offer.
    fn covers_wpa1(&self) -> bool {
        matches!(self.akm, Akm::Psk | Akm::PskSae)
            && matches!(self.cipher, Cipher::Tkip | Cipher::TkipCcmp)
    }

    /// WPA2 clients: anything except a pure-WPA3 network.
    fn covers_wpa2(&self) -> bool {
        !matches!(self.akm, Akm::Sae)
    }

    /// WPA3 clients: the AKM must offer SAE.
    fn covers_wpa3(&self) -> bool {
        matches!(self.akm, Akm::PskSae | Akm::Sae)
    }

    /// Total security strength, used to pick the strongest policy that still
    /// covers the target group. The AKM dominates; among equal AKMs a pure-AES
    /// cipher outranks the TKIP-bearing modes.
    pub fn strength(&self) -> (u8, u8) {
        let c = match self.cipher {
            Cipher::Tkip => 0,
            Cipher::TkipCcmp => 1,
            Cipher::Ccmp => 2,
        };
        (self.akm.rank(), c)
    }

    /// Whether the policy is a secured network at or above WPA-PSK+AES. TKIP
    /// modes stay usable but sit below the floor and are never recommended.
    pub fn meets_floor(&self) -> bool {
        // Floor strength: AKM Psk (rank 1) with the pure-AES cipher (2).
        self.secured() && self.strength() >= (Akm::Psk.rank(), 2)
    }
}

/// Inclusive per-SSID client-count range a product can express. A `min` of 0
/// means the product also accepts "no limit" (miniac stores 0); otherwise 0 is
/// not expressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRange {
    pub min: u32,
    pub max: u32,
}

impl ClientRange {
    /// Clamp a requested limit (0 = no limit) into what this product can
    /// express. "No limit" becomes the maximum when the product cannot express
    /// it, so the user's intent degrades to "as many as the device allows".
    pub fn clamp(self, requested: u32) -> u32 {
        if requested == 0 {
            if self.min == 0 {
                0
            } else {
                self.max
            }
        } else {
            requested.clamp(self.min, self.max)
        }
    }

    /// The range both products can express (a fleet can only express what every
    /// member of it can).
    pub fn intersect(self, other: Self) -> Self {
        ClientRange {
            min: self.min.max(other.min),
            max: self.max.min(other.max),
        }
    }
}

/// What a product can express, keyed by (vendor, model, version). The masks are
/// bit sets over [`Akm`]/[`Cipher`]/[`Pmf`]; a zero mask means
/// "uncharacterized", which imposes no constraint rather than "unsupported".
/// Empty `model`/`version` are wildcards (any model / any version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductCaps {
    pub vendor: String,
    pub model: String,
    pub version: String,
    pub akm_mask: u8,
    pub cipher_mask: u8,
    pub pmf_mask: u8,
    pub source: String,
    pub notes: String,
    /// Per-SSID client-count range; `None` when uncharacterized.
    pub client_range: Option<ClientRange>,
}

/// The adaptation-time capability text, embedded so initialization can import it
/// without a live network. See `data/product_caps.txt` for the format.
pub const PRODUCT_CAPS_TEXT: &str = include_str!("../data/product_caps.txt");

/// Parse the capability text into rows. One record per line,
/// `vendor | model | version | akm | cipher | pmf | limits | source | notes`,
/// `'|'`-separated; blank lines and `#` comments are skipped; the capability
/// fields are comma lists of [`Akm`]/[`Cipher`]/[`Pmf`] names (empty =
/// uncharacterized) and `limits` is a comma list of `key=value` limits.
pub fn parse_product_caps(text: &str) -> Result<Vec<ProductCaps>> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.splitn(9, '|').map(str::trim).collect();
        if f.len() < 9 {
            anyhow::bail!(
                "product_caps.txt line {}: expected 9 '|'-separated fields, got {}",
                n + 1,
                f.len()
            );
        }
        out.push(ProductCaps {
            vendor: f[0].to_string(),
            model: f[1].to_string(),
            version: f[2].to_string(),
            akm_mask: akm_mask_from_list(f[3])
                .map_err(|e| anyhow::anyhow!("product_caps.txt line {}: {e}", n + 1))?,
            cipher_mask: cipher_mask_from_list(f[4])
                .map_err(|e| anyhow::anyhow!("product_caps.txt line {}: {e}", n + 1))?,
            pmf_mask: pmf_mask_from_list(f[5])
                .map_err(|e| anyhow::anyhow!("product_caps.txt line {}: {e}", n + 1))?,
            client_range: client_range_from_limits(f[6])
                .map_err(|e| anyhow::anyhow!("product_caps.txt line {}: {e}", n + 1))?,
            source: f[7].to_string(),
            notes: f[8].to_string(),
        });
    }
    Ok(out)
}

fn names(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn akm_mask_from_list(list: &str) -> Result<u8> {
    let mut m = 0u8;
    for n in names(list) {
        m |= Akm::from_str(n).ok_or_else(|| anyhow::anyhow!("unknown akm '{n}'"))?.bit();
    }
    Ok(m)
}

fn cipher_mask_from_list(list: &str) -> Result<u8> {
    let mut m = 0u8;
    for n in names(list) {
        m |= Cipher::from_str(n).ok_or_else(|| anyhow::anyhow!("unknown cipher '{n}'"))?.bit();
    }
    Ok(m)
}

fn pmf_mask_from_list(list: &str) -> Result<u8> {
    let mut m = 0u8;
    for n in names(list) {
        m |= Pmf::from_str(n).ok_or_else(|| anyhow::anyhow!("unknown pmf '{n}'"))?.bit();
    }
    Ok(m)
}

/// Parse the `limits` field: a comma list of `key=value` pairs. Only
/// `max_clients=MIN-MAX` (or `N`) is recognized today; unknown keys are ignored
/// so new limits can be added without a format change.
fn client_range_from_limits(list: &str) -> Result<Option<ClientRange>> {
    let mut out = None;
    for item in names(list) {
        let Some((key, value)) = item.split_once('=') else {
            continue;
        };
        if key.trim() != "max_clients" {
            continue;
        }
        let value = value.trim();
        let (min, max) = match value.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (value, value),
        };
        let min: u32 = min
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid max_clients '{value}'"))?;
        let max: u32 = max
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid max_clients '{value}'"))?;
        if min > max {
            anyhow::bail!("max_clients range {min}-{max} is inverted");
        }
        out = Some(ClientRange { min, max });
    }
    Ok(out)
}

impl ProductCaps {
    /// Whether the product can express `akm` (an uncharacterized mask allows
    /// anything).
    pub fn supports_akm(&self, akm: Akm) -> bool {
        self.akm_mask == 0 || self.akm_mask & akm.bit() != 0
    }

    pub fn supports_cipher(&self, cipher: Cipher) -> bool {
        self.cipher_mask == 0 || self.cipher_mask & cipher.bit() != 0
    }

    /// Whether any capability has been characterized at all.
    pub fn characterized(&self) -> bool {
        self.akm_mask != 0 || self.cipher_mask != 0
    }

    /// Whether the product can express the full policy (AKM and cipher).
    pub fn supports_policy(&self, policy: &SecurityPolicy) -> bool {
        self.supports_akm(policy.akm) && self.supports_cipher(policy.cipher)
    }

    /// Human label for messages: vendor, then any model/version qualifier.
    pub fn label(&self) -> String {
        let mut parts = vec![self.vendor.clone()];
        if !self.model.is_empty() {
            parts.push(self.model.clone());
        }
        if !self.version.is_empty() {
            parts.push(self.version.clone());
        }
        parts.join(" ")
    }
}

/// SQLite-backed product capability registry.
pub struct ProductCapsStore {
    db: Arc<Db>,
}

impl ProductCapsStore {
    pub fn new(db: Arc<Db>) -> Self {
        ProductCapsStore { db }
    }

    /// Capability row for a vendor profile (the model/version-agnostic row).
    pub fn for_profile(&self, profile: VendorProfile) -> Result<Option<ProductCaps>> {
        self.get(profile.caps_token(), "", "")
    }

    /// Capability row for a learned device, falling back from the specific
    /// (vendor, model, version) row to narrower wildcard forms. Device rows
    /// carry the display name `tp-link` while the registry keys `tplink`.
    pub fn for_device(
        &self,
        vendor: &str,
        model: &str,
        version: &str,
    ) -> Result<Option<ProductCaps>> {
        let vendor = match vendor {
            "tp-link" => "tplink",
            other => other,
        };
        for (m, v) in [(model, version), (model, ""), ("", version), ("", "")] {
            if let Some(c) = self.get(vendor, m, v)? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// Look up a specific (vendor, model, version) row; empty `model`/`version`
    /// match the vendor's wildcard row.
    pub fn get(&self, vendor: &str, model: &str, version: &str) -> Result<Option<ProductCaps>> {
        let conn = self.db.lock();
        conn.query_row(
            "SELECT vendor,model,version,akm_mask,cipher_mask,pmf_mask, \
                    client_min,client_max,source,notes \
             FROM product_caps WHERE vendor=?1 AND model=?2 AND version=?3",
            params![vendor, model, version],
            row_to_caps,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list(&self) -> Result<Vec<ProductCaps>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT vendor,model,version,akm_mask,cipher_mask,pmf_mask, \
                    client_min,client_max,source,notes \
             FROM product_caps ORDER BY vendor,model,version",
        )?;
        let rows = stmt.query_map([], row_to_caps)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

fn row_to_caps(r: &rusqlite::Row) -> rusqlite::Result<ProductCaps> {
    let client_min: Option<i64> = r.get(6)?;
    let client_max: Option<i64> = r.get(7)?;
    Ok(ProductCaps {
        vendor: r.get(0)?,
        model: r.get(1)?,
        version: r.get(2)?,
        akm_mask: r.get::<_, i64>(3)? as u8,
        cipher_mask: r.get::<_, i64>(4)? as u8,
        pmf_mask: r.get::<_, i64>(5)? as u8,
        source: r.get(8)?,
        notes: r.get(9)?,
        client_range: match (client_min, client_max) {
            (Some(min), Some(max)) => Some(ClientRange {
                min: min as u32,
                max: max as u32,
            }),
            _ => None,
        },
    })
}

/// A client range plus the products that shaped each bound, so a caveat can
/// name the actual constraint ("TP-Link cannot express no limit", "H3C caps at
/// 32") instead of blaming one product for both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetClientRange {
    pub range: ClientRange,
    /// Product that raised the lower bound.
    pub min_source: String,
    /// Product that lowered the upper bound.
    pub max_source: String,
}

/// Effective per-SSID client-count range across a set of products: the
/// intersection of their characterized ranges. `None` when no product has a
/// characterized range (nothing to enforce).
pub fn effective_client_range(
    caps: &ProductCapsStore,
    devices: &[(String, String, String)],
) -> Result<Option<FleetClientRange>> {
    let mut acc: Option<FleetClientRange> = None;
    for (vendor, model, version) in devices {
        let Some(c) = caps.for_device(vendor, model, version)? else {
            continue;
        };
        let Some(range) = c.client_range else {
            continue;
        };
        let label = if model.is_empty() {
            vendor.clone()
        } else {
            format!("{vendor} {model}")
        };
        acc = Some(match acc {
            None => FleetClientRange {
                range,
                min_source: label.clone(),
                max_source: label,
            },
            Some(cur) => FleetClientRange {
                range: cur.range.intersect(range),
                min_source: if range.min > cur.range.min {
                    label.clone()
                } else {
                    cur.min_source
                },
                max_source: if range.max < cur.range.max {
                    label
                } else {
                    cur.max_source
                },
            },
        });
    }
    Ok(acc)
}

/// Verdict level of an assessment, ordered so a merge keeps the worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Error,
}

/// An assessment of a policy choice plus the messages behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub level: Level,
    pub messages: Vec<String>,
}

impl Assessment {
    pub fn ok() -> Self {
        Assessment {
            level: Level::Ok,
            messages: Vec::new(),
        }
    }

    pub fn warn(message: impl Into<String>) -> Self {
        Assessment {
            level: Level::Warn,
            messages: vec![message.into()],
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Assessment {
            level: Level::Error,
            messages: vec![message.into()],
        }
    }

    /// Append `level`/`message`, raising the overall level to the worse of the
    /// two.
    fn push(&mut self, level: Level, message: impl Into<String>) {
        self.level = self.level.max(level);
        self.messages.push(message.into());
    }
}

/// The policy a fleet can use and the caveats around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recommendation {
    pub policy: SecurityPolicy,
    /// A separate legacy SSID (WPA/WPA2 mixed) when WPA1 clients must be kept.
    pub legacy: Option<SecurityPolicy>,
    pub assessment: Assessment,
}

/// Evaluate a chosen policy against the target client group and the floor.
pub fn assess_policy(policy: &SecurityPolicy, group: ClientGroup) -> Assessment {
    let mut a = Assessment::ok();
    if !policy.secured() {
        a.push(Level::Error, "Open network: use at least WPA-PSK + AES");
        return a;
    }
    if !policy.meets_floor() {
        a.push(
            Level::Warn,
            format!(
                "Below the WPA-PSK+AES floor ({} + {}); TKIP is usable for legacy clients only",
                policy.akm.as_str(),
                policy.cipher.as_str()
            ),
        );
    }
    if !policy.covers(group) {
        a.push(
            Level::Warn,
            format!(
                "Target client group ({}) may not be able to associate with this policy",
                group.as_str()
            ),
        );
    }
    a
}

/// Evaluate a chosen policy against a single AP's product capabilities.
pub fn assess_ap(policy: &SecurityPolicy, caps: Option<&ProductCaps>) -> Assessment {
    let Some(caps) = caps.filter(|c| c.characterized()) else {
        return Assessment::ok();
    };
    let floor = SecurityPolicy {
        akm: Akm::Psk,
        cipher: Cipher::Ccmp,
        psk: None,
        pmf: Pmf::Disabled,
    };
    if !caps.supports_policy(&floor) {
        return Assessment::error(format!(
            "{} cannot reach the WPA-PSK+AES floor; put legacy devices on a separate SSID",
            caps.label()
        ));
    }
    if !caps.supports_policy(policy) {
        return Assessment::warn(format!(
            "{} cannot express {} + {}; the closest supported mode will be pushed",
            caps.label(),
            policy.akm.as_str(),
            policy.cipher.as_str()
        ));
    }
    Assessment::ok()
}

/// Assess a chosen policy against the floor, the target client group and every
/// characterized product in `caps`. This is the set-time check: it warns about
/// client-compatibility risk and about any registered product that would have
/// to push a substituted mode.
pub fn assess_choice(policy: &SecurityPolicy, group: ClientGroup, caps: &[ProductCaps]) -> Assessment {
    let mut a = assess_policy(policy, group);
    for c in caps.iter().filter(|c| c.characterized()) {
        let per = assess_ap(policy, Some(c));
        for m in per.messages {
            a.push(per.level, m);
        }
    }
    a
}

/// Candidate secured policies a fleet may choose, strongest first. The list is
/// built from the two dimensions so no combination is silently dropped.
fn candidates() -> Vec<SecurityPolicy> {
    let mut out = Vec::new();
    for akm in [Akm::Psk, Akm::PskSae, Akm::Sae] {
        for cipher in [Cipher::Ccmp, Cipher::TkipCcmp, Cipher::Tkip] {
            out.push(SecurityPolicy {
                akm,
                cipher,
                psk: None,
                pmf: Pmf::Disabled,
            });
        }
    }
    out
}

/// The strongest floor-meeting policy expressible by every characterized AP
/// that still serves `group`.
fn best_for(
    caps: &ProductCapsStore,
    profiles: &[VendorProfile],
    group: ClientGroup,
) -> Result<(Option<SecurityPolicy>, Assessment)> {
    let mut a = Assessment::ok();
    // Capabilities of the characterized products in the fleet.
    let fleet: Vec<ProductCaps> = profiles
        .iter()
        .filter_map(|p| caps.for_profile(*p).ok().flatten())
        .filter(|c| c.characterized())
        .collect();
    if fleet.is_empty() {
        a.push(
            Level::Warn,
            "No characterized AP in the fleet; recommendation assumes generic support",
        );
    }
    let mut best: Option<SecurityPolicy> = None;
    for c in candidates() {
        if !c.meets_floor() || !c.covers(group) {
            continue;
        }
        if !fleet.iter().all(|caps| caps.supports_policy(&c)) {
            continue;
        }
        if best.as_ref().map_or(true, |b| c.strength() > b.strength()) {
            best = Some(c);
        }
    }
    Ok((best, a))
}

/// Arbitrate a fleet-wide recommendation for the target client group.
///
/// `profiles` are the vendor profiles of the APs actually in the fleet. The
/// result carries the recommended policy (always at or above the WPA-PSK+AES
/// floor), the caveats, and — for a legacy group — the separate legacy SSID the
/// WPA1 clients need.
pub fn recommend(
    caps: &ProductCapsStore,
    profiles: &[VendorProfile],
    group: ClientGroup,
) -> Result<Recommendation> {
    if group == ClientGroup::Legacy {
        // The secure floor (AES) cannot serve WPA1 clients, so keep the main
        // SSID at the WPA2 floor or above and give legacy devices their own.
        let mut rec = recommend(caps, profiles, ClientGroup::Wpa2Plus)?;
        rec.legacy = Some(SecurityPolicy {
            akm: Akm::Psk,
            cipher: Cipher::TkipCcmp,
            psk: rec.policy.psk.clone(),
            pmf: Pmf::Disabled,
        });
        rec.assessment.push(
            Level::Warn,
            "Legacy WPA (TKIP) clients need a separate SSID; the main SSID stays at the WPA2 floor or above",
        );
        return Ok(rec);
    }

    let (best, mut assessment) = best_for(caps, profiles, group)?;
    let policy = match best {
        Some(p) => p,
        None => {
            // All APs reach the floor, but none can serve this client group while
            // staying at or above it (e.g. a WPA3-only group on WPA2-only APs).
            assessment.push(
                Level::Error,
                format!(
                    "No policy at or above the WPA-PSK+AES floor serves the {} client group",
                    group.as_str()
                ),
            );
            return Ok(Recommendation {
                policy: SecurityPolicy {
                    akm: Akm::Psk,
                    cipher: Cipher::Ccmp,
                    psk: None,
                    pmf: Pmf::Disabled,
                },
                legacy: None,
                assessment,
            });
        }
    };
    Ok(Recommendation {
        policy,
        legacy: None,
        assessment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Akm;

    fn policy(akm: Akm, cipher: Cipher) -> SecurityPolicy {
        SecurityPolicy {
            akm,
            cipher,
            psk: Some("person0finterest".into()),
            pmf: Pmf::Disabled,
        }
    }

    #[test]
    fn floor_and_coverage() {
        assert!(policy(Akm::Psk, Cipher::Ccmp).meets_floor());
        assert!(!policy(Akm::Psk, Cipher::Tkip).meets_floor());
        assert!(!policy(Akm::Psk, Cipher::TkipCcmp).meets_floor());
        assert!(policy(Akm::PskSae, Cipher::Ccmp).meets_floor());
        assert!(policy(Akm::Sae, Cipher::Ccmp).meets_floor());
        assert!(!policy(Akm::Open, Cipher::Ccmp).meets_floor());

        // Transition modes stay backwards-compatible.
        assert!(policy(Akm::PskSae, Cipher::Ccmp).covers(ClientGroup::Wpa2Plus));
        assert!(policy(Akm::PskSae, Cipher::Ccmp).covers(ClientGroup::Wpa3Only));
        assert!(!policy(Akm::Sae, Cipher::Ccmp).covers(ClientGroup::Wpa2Plus));
        assert!(policy(Akm::Sae, Cipher::Ccmp).covers(ClientGroup::Wpa3Only));
        assert!(policy(Akm::Psk, Cipher::TkipCcmp).covers(ClientGroup::Legacy));
        assert!(!policy(Akm::Psk, Cipher::Ccmp).covers(ClientGroup::Legacy));
    }

    #[test]
    fn straddling_strength_orders_cipher() {
        assert!(policy(Akm::Psk, Cipher::Ccmp).strength() > policy(Akm::Psk, Cipher::TkipCcmp).strength());
        assert!(policy(Akm::PskSae, Cipher::Ccmp).strength() > policy(Akm::Psk, Cipher::Ccmp).strength());
    }

    #[test]
    fn product_caps_text_parses_expected_masks() {
        let caps = parse_product_caps(PRODUCT_CAPS_TEXT).unwrap();
        let h3c = caps.iter().find(|c| c.vendor == "h3c").expect("h3c row");
        assert_eq!(h3c.akm_mask, 0b0111); // open|psk|psk-sae
        assert_eq!(h3c.cipher_mask, 0b0111); // tkip|ccmp|tkip+ccmp
        assert_eq!(h3c.pmf_mask, 0); // uncharacterized
        assert_eq!(h3c.client_range, Some(ClientRange { min: 0, max: 32 }));
        let tl = caps.iter().find(|c| c.vendor == "tplink").expect("tplink row");
        assert_eq!(tl.akm_mask, 0b0011); // open|psk
        assert_eq!(tl.cipher_mask, 0b0010); // ccmp
        assert_eq!(tl.client_range, Some(ClientRange { min: 1, max: 100 }));
        assert_eq!(tl.model, "");
        assert_eq!(tl.version, "");
    }

    #[test]
    fn client_range_clamps_and_intersects() {
        let h3c = ClientRange { min: 0, max: 32 };
        let tl = ClientRange { min: 1, max: 100 };
        // H3C expresses "no limit"; TP-Link does not, so it degrades to its max.
        assert_eq!(h3c.clamp(0), 0);
        assert_eq!(h3c.clamp(64), 32);
        assert_eq!(tl.clamp(0), 100);
        assert_eq!(tl.clamp(1), 1);
        assert_eq!(tl.clamp(200), 100);

        let both = h3c.intersect(tl);
        assert_eq!(both, ClientRange { min: 1, max: 32 });
        assert_eq!(both.clamp(0), 32);
    }

    #[test]
    fn effective_client_range_intersects_fleet() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let store = ProductCapsStore::new(db);
        let keys = vec![
            ("h3c".to_string(), String::new(), String::new()),
            // Device rows spell the vendor `tp-link`; the registry keys `tplink`.
            ("tp-link".to_string(), String::new(), String::new()),
        ];
        let fleet = effective_client_range(&store, &keys).unwrap().unwrap();
        assert_eq!(fleet.range, ClientRange { min: 1, max: 32 });
        // TP-Link raises the lower bound (no "no limit"), H3C lowers the ceiling.
        assert_eq!(fleet.min_source, "tp-link");
        assert_eq!(fleet.max_source, "h3c");
    }

    #[test]
    fn product_caps_text_rejects_unknown_name_and_short_line() {
        let bad_akm = "h3c | | | wpa2 | ccmp | | | src | note\n";
        assert!(parse_product_caps(bad_akm).is_err());
        let short = "h3c | | | open,psk\n";
        assert!(parse_product_caps(short).is_err());
    }

    #[test]
    fn recommend_intersects_fleet_capabilities() {
        // A mixed H3C + TP-Link fleet: H3C can express the WPA2/WPA3 mixed mode
        // but TP-Link is WPA2-AES only, so the common secure choice is WPA2-PSK.
        let db = Arc::new(Db::open_in_memory().unwrap());
        let store = ProductCapsStore::new(db);
        let rec = recommend(
            &store,
            &[VendorProfile::H3c, VendorProfile::TpLink],
            ClientGroup::Wpa2Plus,
        )
        .unwrap();
        assert_eq!(rec.policy.akm, Akm::Psk);
        assert_eq!(rec.policy.cipher, Cipher::Ccmp);
        assert_eq!(rec.assessment.level, Level::Ok);
    }

    #[test]
    fn recommend_prefers_mixed_wpa2_wpa3_for_h3c_only() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let store = ProductCapsStore::new(db);
        let rec = recommend(&store, &[VendorProfile::H3c], ClientGroup::Wpa2Plus).unwrap();
        // H3C's strongest WPA2-compatible mode is the WPA2/WPA3 mixed one.
        assert_eq!(rec.policy.akm, Akm::PskSae);
        assert_eq!(rec.policy.cipher, Cipher::Ccmp);
    }

    #[test]
    fn legacy_group_splits_off_a_separate_ssid() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let store = ProductCapsStore::new(db);
        let rec = recommend(&store, &[VendorProfile::H3c], ClientGroup::Legacy).unwrap();
        assert!(rec.policy.meets_floor());
        let legacy = rec.legacy.expect("legacy SSID suggested");
        assert!(legacy.covers(ClientGroup::Legacy));
        assert_eq!(rec.assessment.level, Level::Warn);
    }
}
