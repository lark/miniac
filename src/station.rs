//! Client station model and persistent store, keyed by (WTP MAC, client MAC).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Filled from CAPWAP Station Configuration Request (Add/Delete Station) and,
//! later, from associated 802.1X / roaming states. `name`/`ip`/`ssid` are
//! informative; association/reachability timestamps drive the web view.

use std::sync::Arc;

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::db::Db;
use crate::device::Mac;

/// A client station associated to a WTP device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    pub wmac: Mac,
    pub mac: Mac,
    pub radio_id: u8,
    pub wlan_id: u8,
    pub state: String,
    pub ip_addr: Option<String>,
    pub ssid: Option<String>,
    pub rssi: Option<i32>,
    pub associated_at: Option<u64>,
    pub last_seen: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Operations over the stations table.
pub struct StationStore {
    db: Arc<Db>,
}

impl StationStore {
    pub fn new(db: Arc<Db>) -> Self {
        StationStore { db }
    }

    /// Add or update a station (association/state refresh).
    pub fn upsert(
        &self,
        wmac: Mac,
        mac: Mac,
        radio_id: u8,
        wlan_id: u8,
        state: &str,
        ip: Option<&str>,
        ssid: Option<&str>,
        rssi: Option<i32>,
    ) -> Result<bool> {
        let ts = now_unix() as i64;
        let conn = self.db.lock();
        let existing = conn
            .query_row(
                "SELECT mac FROM stations WHERE wmac=?1 AND mac=?2",
                params![&wmac[..], &mac[..]],
                |_| Ok(()),
            )
            .optional()?;
        let created = existing.is_none();

        if created {
            conn.execute(
                "INSERT INTO stations (wmac,mac,radio_id,wlan_id,state,ip_addr,ssid,rssi,associated_at,last_seen)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
                params![&wmac[..], &mac[..], radio_id, wlan_id, state, ip, ssid, rssi, ts],
            )?;
        } else {
            conn.execute(
                "UPDATE stations SET radio_id=?3, wlan_id=?4, state=?5,
                    ip_addr=COALESCE(?6,ip_addr), ssid=COALESCE(?7,ssid),
                    rssi=COALESCE(?8,rssi), last_seen=?9
                 WHERE wmac=?1 AND mac=?2",
                params![
                    &wmac[..],
                    &mac[..],
                    radio_id,
                    wlan_id,
                    state,
                    ip,
                    ssid,
                    rssi,
                    ts
                ],
            )?;
        }
        Ok(created)
    }

    /// All stations on a device.
    pub fn list_by_wtp(&self, wmac: Mac) -> Result<Vec<Station>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(SELECT_BY_WTP)?;
        let rows = stmt.query_map(params![&wmac[..]], row_from)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// All stations across devices.
    pub fn list_all(&self) -> Result<Vec<Station>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(SELECT_ALL)?;
        let rows = stmt.query_map([], |r| row_from(r))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Look up a single station.
    pub fn get(&self, wmac: Mac, mac: Mac) -> Result<Option<Station>> {
        let conn = self.db.lock();
        let s = conn
            .query_row(SELECT_ONE, params![&wmac[..], &mac[..]], row_from)
            .optional()?;
        Ok(s)
    }

    /// Remove a station (disassociation / Delete Station).
    pub fn delete(&self, wmac: Mac, mac: Mac) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "DELETE FROM stations WHERE wmac=?1 AND mac=?2",
            params![&wmac[..], &mac[..]],
        )?;
        Ok(())
    }
}

const SELECT_ALL: &str = "SELECT wmac,mac,radio_id,wlan_id,state,ip_addr,ssid,rssi,associated_at,last_seen FROM stations ORDER BY wmac, mac";
const SELECT_BY_WTP: &str = "SELECT wmac,mac,radio_id,wlan_id,state,ip_addr,ssid,rssi,associated_at,last_seen FROM stations WHERE wmac=?1 ORDER BY mac";
const SELECT_ONE: &str = "SELECT wmac,mac,radio_id,wlan_id,state,ip_addr,ssid,rssi,associated_at,last_seen FROM stations WHERE wmac=?1 AND mac=?2";

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<Station> {
    let wmac: Vec<u8> = r.get(0)?;
    let mac: Vec<u8> = r.get(1)?;
    Ok(Station {
        wmac: to_mac(wmac)?,
        mac: to_mac(mac)?,
        radio_id: r.get::<_, i64>(2)? as u8,
        wlan_id: r.get::<_, i64>(3)? as u8,
        state: r.get(4)?,
        ip_addr: r.get(5)?,
        ssid: r.get(6)?,
        rssi: r.get(7)?,
        associated_at: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        last_seen: r.get::<_, i64>(9)? as u64,
    })
}

fn to_mac(bytes: Vec<u8>) -> rusqlite::Result<Mac> {
    bytes
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidColumnIndex(0)) // length mismatch mapped as conversion error
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> StationStore {
        StationStore::new(Arc::new(Db::open_in_memory().unwrap()))
    }

    fn mac(id: u8) -> Mac {
        [0, 0, 0, 0, 0, id]
    }

    #[test]
    fn associate_update_list_delete() {
        use crate::device::mac_to_str;

        let s = store();
        let w = mac(1);
        let c = mac(2);
        assert!(s
            .upsert(
                w,
                c,
                0,
                1,
                "associated",
                Some("10.0.0.9"),
                Some("MySSID"),
                None
            )
            .unwrap());
        assert!(!s
            .upsert(
                w,
                c,
                0,
                1,
                "associated",
                Some("10.0.0.9"),
                Some("MySSID"),
                Some(-60)
            )
            .unwrap());

        let st = s.get(w, c).unwrap().unwrap();
        assert_eq!(st.state, "associated");
        assert_eq!(st.rssi, Some(-60));
        assert_eq!(s.list_by_wtp(w).unwrap().len(), 1);
        assert_eq!(s.list_all().unwrap().len(), 1);

        s.delete(w, c).unwrap();
        assert!(s.get(w, c).unwrap().is_none());
        let _ = mac_to_str(w);
    }
}
