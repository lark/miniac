//! Radio (RF) model and persistent store, keyed by (WTP MAC, radio id).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Fields are learned from the RFC 5416 WTP Radio Information / Radio Config
//! elements (admin/op state, band, channel, TX power). The store is wired once
//! radio-info parsing lands; tests pin the schema/CRUD behavior now.

#![allow(dead_code)] // store; wired once radio-info parsing lands

use std::sync::Arc;

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::db::Db;
use crate::device::{mac_to_str, Mac};

/// A radio within a WTP device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Radio {
    pub mac: Mac,
    pub radio_id: u8,
    pub band: Option<String>,
    pub admin_state: u8,
    pub op_state: u8,
    pub channel: Option<u32>,
    pub tx_power: Option<i32>,
    pub last_seen: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Operations over the radios table.
pub struct RadioStore {
    db: Arc<Db>,
}

impl RadioStore {
    pub fn new(db: Arc<Db>) -> Self {
        RadioStore { db }
    }

    /// Upsert a radio's learned state. Returns `Ok(true)` when newly created.
    pub fn upsert(
        &self,
        mac: Mac,
        radio_id: u8,
        band: Option<&str>,
        admin_state: u8,
        op_state: u8,
        channel: Option<u32>,
        tx_power: Option<i32>,
    ) -> Result<bool> {
        let ts = now_unix() as i64;
        let conn = self.db.lock();
        let existing = conn
            .query_row(
                "SELECT radio_id FROM radios WHERE mac=?1 AND radio_id=?2",
                params![&mac[..], radio_id],
                |_| Ok(()),
            )
            .optional()?;
        let created = existing.is_none();

        if created {
            conn.execute(
                "INSERT INTO radios (mac,radio_id,band,admin_state,op_state,channel,tx_power,last_seen)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![&mac[..], radio_id, band, admin_state, op_state, channel, tx_power, ts],
            )?;
        } else {
            conn.execute(
                "UPDATE radios SET band=COALESCE(?3,band), admin_state=?4, op_state=?5,
                    channel=COALESCE(?6,channel), tx_power=COALESCE(?7,tx_power), last_seen=?8
                 WHERE mac=?1 AND radio_id=?2",
                params![
                    &mac[..],
                    radio_id,
                    band,
                    admin_state,
                    op_state,
                    channel,
                    tx_power,
                    ts
                ],
            )?;
        }
        Ok(created)
    }

    /// All radios owned by a device.
    pub fn list_by_device(&self, mac: Mac) -> Result<Vec<Radio>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT mac,radio_id,band,admin_state,op_state,channel,tx_power,last_seen
             FROM radios WHERE mac=?1 ORDER BY radio_id",
        )?;
        let rows = stmt.query_map(params![&mac[..]], |r| {
            Ok(Radio {
                mac: r
                    .get::<_, Vec<u8>>(0)?
                    .try_into()
                    .map_err(|e: Vec<u8>| rusqlite::Error::InvalidColumnIndex(0))?,
                radio_id: r.get::<_, i64>(1)? as u8,
                band: r.get(2)?,
                admin_state: r.get::<_, i64>(3)? as u8,
                op_state: r.get::<_, i64>(4)? as u8,
                channel: r.get(5)?,
                tx_power: r.get(6)?,
                last_seen: r.get::<_, i64>(7)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Total radios across all devices.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.lock();
        let n = conn.query_row("SELECT COUNT(*) FROM radios", [], |r| r.get::<_, i64>(0))?;
        Ok(n as u64)
    }

    /// All radios across all devices.
    pub fn list_all(&self) -> Result<Vec<Radio>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT mac,radio_id,band,admin_state,op_state,channel,tx_power,last_seen
             FROM radios ORDER BY mac, radio_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Radio {
                mac: r
                    .get::<_, Vec<u8>>(0)?
                    .try_into()
                    .map_err(|e: Vec<u8>| rusqlite::Error::InvalidColumnIndex(0))?,
                radio_id: r.get::<_, i64>(1)? as u8,
                band: r.get(2)?,
                admin_state: r.get::<_, i64>(3)? as u8,
                op_state: r.get::<_, i64>(4)? as u8,
                channel: r.get(5)?,
                tx_power: r.get(6)?,
                last_seen: r.get::<_, i64>(7)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> RadioStore {
        RadioStore::new(Arc::new(Db::open_in_memory().unwrap()))
    }

    fn mac(id: u8) -> Mac {
        [0, 0, 0, 0, 0, id]
    }

    #[test]
    fn upsert_and_list() {
        let s = store();
        let w = mac(1);
        assert!(s
            .upsert(w, 0, Some("2.4G"), 1, 1, Some(1), Some(20))
            .unwrap());
        assert!(!s
            .upsert(w, 0, Some("2.4G"), 1, 1, Some(6), Some(20))
            .unwrap());

        let radios = s.list_by_device(w).unwrap();
        assert_eq!(radios.len(), 1);
        assert_eq!(radios[0].channel, Some(6));
        assert_eq!(s.count().unwrap(), 1);
        assert!(s.list_by_device(mac(2)).unwrap().is_empty());
        let _ = mac_to_str(w); // keep import used in non-test path
    }
}
