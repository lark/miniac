//! Device (WTP) model and persistent store, keyed by the 6-byte MAC address.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! `name` and `description` are user-managed (settable via the management UI);
//! the remaining fields are learned from the CAPWAP flow (discovery/join).

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use crate::db::Db;

pub type Mac = [u8; 6];

/// A known WTP device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub mac: Mac,
    /// User-assigned display name (editable).
    pub name: String,
    /// User-assigned free-text description (editable).
    pub description: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub hw_version: Option<String>,
    pub sw_version: Option<String>,
    pub ip_addr: Option<String>,
    /// Static DB lifecycle state (e.g. "registered"). The runtime CAPWAP FSM
    /// (Join/Run/...) is deliberately NOT persisted; it lives only in memory
    /// in `WtpContext::state`.
    pub state: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub joined_at: Option<u64>,
    /// Admin approval: false = pending (visible but not yet managed).
    pub approved: bool,
}

/// Format a MAC as `aa:bb:cc:dd:ee:ff`.
pub fn mac_to_str(m: Mac) -> String {
    let mut s = String::with_capacity(17);
    let mut first = true;
    for b in m {
        if !first {
            s.push(':');
        }
        let _ = write!(s, "{:02x}", b);
        first = false;
    }
    s
}

/// Parse a MAC from `aa:bb:cc:dd:ee:ff` (colons optional).
pub fn mac_from_str(s: &str) -> Result<Mac> {
    let hex: String = s.chars().filter(|c| *c != ':').collect();
    if hex.len() != 12 {
        return Err(anyhow!("invalid MAC: {s}"));
    }
    let mut m = [0u8; 6];
    for (i, c) in m.iter_mut().enumerate() {
        let byte = hex
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| anyhow!("invalid MAC"))?;
        *c = u8::from_str_radix(byte, 16).map_err(|_| anyhow!("invalid MAC: {s}"))?;
    }
    Ok(m)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Row {
    mac: Vec<u8>,
    name: String,
    description: String,
    vendor: Option<String>,
    model: Option<String>,
    hw_version: Option<String>,
    sw_version: Option<String>,
    ip_addr: Option<String>,
    state: String,
    first_seen: i64,
    last_seen: i64,
    joined_at: Option<i64>,
    approved: bool,
}

fn row_to_device(r: Row) -> Result<Device> {
    let mut mac = [0u8; 6];
    if r.mac.len() != 6 {
        return Err(anyhow!("stored mac has length {}", r.mac.len()));
    }
    mac.copy_from_slice(&r.mac);
    Ok(Device {
        mac,
        name: r.name,
        description: r.description,
        vendor: r.vendor,
        model: r.model,
        hw_version: r.hw_version,
        sw_version: r.sw_version,
        ip_addr: r.ip_addr,
        state: r.state,
        first_seen: r.first_seen as u64,
        last_seen: r.last_seen as u64,
        joined_at: r.joined_at.map(|v| v as u64),
        approved: r.approved,
    })
}

const COLS: &str = "mac,name,description,vendor,model,hw_version,sw_version,ip_addr,state,first_seen,last_seen,joined_at,approved";

/// Operations over the device table.
pub struct DeviceStore {
    db: Arc<Db>,
}

impl DeviceStore {
    pub fn new(db: Arc<Db>) -> Self {
        DeviceStore { db }
    }

    /// Upsert device learned from the CAPWAP flow (`None` sw/ip leave existing
    /// values intact). `state` records a static, DB-lifecycle value (e.g.
    /// "registered"); the runtime CAPWAP FSM (join/run) is not persisted.
    /// Returns `Ok(true)` when the device was newly created.
    pub fn register(
        &self,
        mac: Mac,
        ip: Option<&str>,
        sw_version: Option<&str>,
        vendor: Option<&str>,
        model: Option<&str>,
        state: &str,
    ) -> Result<bool> {
        let ts = now_unix() as i64;
        let conn = self.db.lock();
        let existing = conn
            .query_row(
                "SELECT mac FROM devices WHERE mac = ?1",
                params![&mac[..]],
                |_| Ok(()),
            )
            .optional()?;
        let created = existing.is_none();

        if created {
            conn.execute(
                "INSERT INTO devices (mac,name,description,vendor,model,hw_version,sw_version,ip_addr,state,first_seen,last_seen,joined_at)
                 VALUES (?1,'','',?2,?3,NULL,?4,?5,?6,?7,?7,NULL)",
                params![&mac[..], vendor, model, sw_version, ip, state, ts],
            )?;
        } else {
            conn.execute(
                "UPDATE devices SET state=?1, last_seen=?2,
                    ip_addr = COALESCE(COALESCE(?3, ip_addr), ip_addr),
                    sw_version = COALESCE(COALESCE(?4, sw_version), sw_version),
                    vendor = COALESCE(COALESCE(?5, vendor), vendor)
                 WHERE mac=?6",
                params![state, ts, ip, sw_version, vendor, &mac[..]],
            )?;
        }
        Ok(created)
    }

    /// Mark a device online (join) — record `joined_at` if absent.
    pub fn mark_joined(&self, mac: Mac) -> Result<()> {
        let ts = now_unix() as i64;
        let conn = self.db.lock();
        conn.execute(
            "UPDATE devices SET joined_at = COALESCE(joined_at, ?2), last_seen = ?2 WHERE mac = ?1",
            params![&mac[..], ts],
        )?;
        Ok(())
    }

    /// Record the identity learned from the join exchange: the vendor family,
    /// the WTP model and the descriptor's hardware/software version strings.
    /// Only the fields passed as `Some` are written, so a repeat join never
    /// clears what an earlier one learned.
    pub fn set_identity(
        &self,
        mac: Mac,
        vendor: Option<&str>,
        model: Option<&str>,
        hw_version: Option<&str>,
        sw_version: Option<&str>,
    ) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "UPDATE devices SET vendor=COALESCE(?2,vendor), model=COALESCE(?3,model),
                hw_version=COALESCE(?4,hw_version), sw_version=COALESCE(?5,sw_version)
             WHERE mac=?1",
            params![&mac[..], vendor, model, hw_version, sw_version],
        )?;
        Ok(())
    }

    /// Set the user-managed metadata: `name` and `description`.
    pub fn set_metadata(&self, mac: Mac, name: &str, description: &str) -> Result<()> {
        let conn = self.db.lock();
        let n = conn.execute(
            "UPDATE devices SET name=?2, description=?3 WHERE mac=?1",
            params![&mac[..], name, description],
        )?;
        if n == 0 {
            return Err(anyhow!("device {} not found", mac_to_str(mac)));
        }
        Ok(())
    }

    /// Approve a pending device so it becomes managed. Idempotent.
    pub fn approve(&self, mac: Mac) -> Result<()> {
        let conn = self.db.lock();
        let n = conn.execute(
            "UPDATE devices SET approved=1 WHERE mac=?1",
            params![&mac[..]],
        )?;
        if n == 0 {
            return Err(anyhow!("device {} not found", mac_to_str(mac)));
        }
        Ok(())
    }

    /// Look up a single device.
    pub fn get(&self, mac: Mac) -> Result<Option<Device>> {
        let conn = self.db.lock();
        let row = conn
            .query_row(
                &format!("SELECT {COLS} FROM devices WHERE mac=?1"),
                params![&mac[..]],
                |r| {
                    Ok(Row {
                        mac: r.get(0)?,
                        name: r.get(1)?,
                        description: r.get(2)?,
                        vendor: r.get(3)?,
                        model: r.get(4)?,
                        hw_version: r.get(5)?,
                        sw_version: r.get(6)?,
                        ip_addr: r.get(7)?,
                        state: r.get(8)?,
                        first_seen: r.get(9)?,
                        last_seen: r.get(10)?,
                        joined_at: r.get(11)?,
                        approved: r.get::<_, i64>(12)? != 0,
                    })
                },
            )
            .optional()?;
        row.map(row_to_device).transpose()
    }

    /// List all known devices.
    pub fn list(&self) -> Result<Vec<Device>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM devices ORDER BY first_seen"))?;
        let rows = stmt.query_map([], |r| {
            Ok(Row {
                mac: r.get(0)?,
                name: r.get(1)?,
                description: r.get(2)?,
                vendor: r.get(3)?,
                model: r.get(4)?,
                hw_version: r.get(5)?,
                sw_version: r.get(6)?,
                ip_addr: r.get(7)?,
                state: r.get(8)?,
                first_seen: r.get(9)?,
                last_seen: r.get(10)?,
                joined_at: r.get(11)?,
                approved: r.get::<_, i64>(12)? != 0,
            })
        })?;
        rows.map(|r| row_to_device(r?)).collect()
    }

    /// Remove a device.
    pub fn delete(&self, mac: Mac) -> Result<()> {
        let conn = self.db.lock();
        conn.execute("DELETE FROM devices WHERE mac=?1", params![&mac[..]])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> DeviceStore {
        DeviceStore::new(Arc::new(Db::open_in_memory().unwrap()))
    }

    #[test]
    fn mac_parse_format_roundtrip() {
        let m = mac_from_str("a1:b2:c3:d4:e5:f6").unwrap();
        assert_eq!(m, [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        assert_eq!(mac_to_str(m), "a1:b2:c3:d4:e5:f6");
        assert!(mac_from_str("zz:yy").is_err());
    }

    #[test]
    fn register_then_metadata() {
        let s = store();
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(s
            .register(mac, Some("10.0.0.2"), Some("v1.0"), None, None, "registered")
            .unwrap());
        assert!(!s
            .register(mac, Some("10.0.0.2"), Some("v1.0"), None, None, "registered")
            .unwrap());

        s.set_metadata(mac, "Living-Room-AP", "Ground floor WAP")
            .unwrap();

        let d = s.get(mac).unwrap().unwrap();
        assert_eq!(d.name, "Living-Room-AP");
        assert_eq!(d.description, "Ground floor WAP");
        assert_eq!(d.state, "registered");
        assert_eq!(d.ip_addr.as_deref(), Some("10.0.0.2"));
        assert_eq!(d.sw_version.as_deref(), Some("v1.0"));

        let all = s.list().unwrap();
        assert_eq!(all.len(), 1);
    }

    /// A second device joining must not rewrite the first one's row.
    #[test]
    fn register_second_device_leaves_first_intact() {
        let s = store();
        let first = [0x00, 0x00, 0x00, 0x00, 0x00, 0x11];
        let second = [0x00, 0x00, 0x00, 0x00, 0x00, 0x22];
        s.register(first, Some("10.0.0.10"), Some("v1"), Some("a"), None, "registered")
            .unwrap();
        s.register(second, Some("10.0.0.20"), Some("v2"), Some("b"), None, "registered")
            .unwrap();

        let a = s.get(first).unwrap().unwrap();
        assert_eq!(a.ip_addr.as_deref(), Some("10.0.0.10"));
        assert_eq!(a.sw_version.as_deref(), Some("v1"));
        assert_eq!(a.vendor.as_deref(), Some("a"));
        assert_eq!(a.state, "registered");
        let b = s.get(second).unwrap().unwrap();
        assert_eq!(b.ip_addr.as_deref(), Some("10.0.0.20"));
    }

    #[test]
    fn register_then_approve() {
        let s = store();
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        s.register(mac, None, None, None, None, "join").unwrap();

        // New devices start pending (not approved).
        let d = s.get(mac).unwrap().unwrap();
        assert!(!d.approved);

        s.approve(mac).unwrap();
        assert!(s.get(mac).unwrap().unwrap().approved);

        // Approving again is idempotent.
        s.approve(mac).unwrap();
        assert!(s.get(mac).unwrap().unwrap().approved);

        // Approving an unknown device fails.
        assert!(s.approve([0xff; 6]).is_err());
    }
}
