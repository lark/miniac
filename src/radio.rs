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

/// A per-radio WLAN configuration the AC pushes to a WTP during the Configure
/// phase. Keyed by (WTP MAC, radio id, wlan id) so the 2.4G and 5G radios carry
/// independent SSID and security settings. The trailing fields are the H3C
/// 0xfde8 record fields, stored per WLAN and emitted verbatim on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioWlan {
    pub mac: Mac,
    pub radio_id: u8,
    pub wlan_id: u8,
    pub ssid: String,
    /// Security policy: "open" | "wpa2" | "wpa3" | "wpa2-wpa3".
    pub security: String,
    /// WPA passphrase (8..63 chars); `None` for open networks.
    pub psk: Option<String>,
    /// Record slot up (CFG_SetWifiSsidEnable), client isolate, SSID visibility
    /// (broadcast 1 / hidden 0), client limit, VLAN id, WPA cipher
    /// (1 TKIP / 2 AES / 3 TKIP+AES) and WPA rekey period.
    pub wlan_enable: bool,
    pub isolate: bool,
    pub broadcast: bool,
    pub client_count: u32,
    pub vlan_id: u32,
    pub cipher: u32,
    pub rekey_period: u32,
}

impl Default for RadioWlan {
    fn default() -> Self {
        RadioWlan {
            mac: [0; 6],
            radio_id: 0,
            wlan_id: 1,
            ssid: String::new(),
            security: "open".into(),
            psk: None,
            wlan_enable: true,
            isolate: false,
            broadcast: true,
            client_count: 0,
            vlan_id: 0,
            cipher: 2,
            rekey_period: 0,
        }
    }
}

/// H3C per-band radio header settings carried by the leading 7 x u32 of each
/// band's 0xfde8 section: enable (word0), power (word2), mode (word3) and
/// channel (word5). `channel` is the AX60 5G channel *index* (0..12 ->
/// 149/153/157/161/165/36/40/44/48/52/56/60/64 MHz), not a frequency. Stored
/// per (mac, radio_id); radio_id 1 = 2.4G, 2 = 5G.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3cRadioHeader {
    pub radio_id: u8,
    pub enable: bool,
    pub power: u32,
    pub mode: u32,
    pub channel: u32,
}

impl Default for H3cRadioHeader {
    fn default() -> Self {
        H3cRadioHeader {
            radio_id: 1,
            enable: true,
            power: 6,
            mode: 0,
            channel: 0,
        }
    }
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

    /// Set (insert or overwrite) a per-radio WLAN configuration, including the
    /// H3C 0xfde8 record fields. `security` is a validated policy string; the
    /// empty set is allowed so a radio can be reconfigured (e.g. cleared)
    /// through the API.
    pub fn set_wlan(&self, w: &RadioWlan) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO radio_wlans (mac,radio_id,wlan_id,ssid,security,psk,
                wlan_enable,isolate,broadcast,client_count,vlan_id,cipher,rekey_period)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(mac,radio_id,wlan_id) DO UPDATE SET
                ssid=excluded.ssid, security=excluded.security, psk=excluded.psk,
                wlan_enable=excluded.wlan_enable, isolate=excluded.isolate,
                broadcast=excluded.broadcast, client_count=excluded.client_count,
                vlan_id=excluded.vlan_id, cipher=excluded.cipher,
                rekey_period=excluded.rekey_period",
            params![
                &w.mac[..],
                w.radio_id,
                w.wlan_id,
                w.ssid,
                w.security,
                w.psk,
                i64::from(w.wlan_enable),
                i64::from(w.isolate),
                i64::from(w.broadcast),
                w.client_count as i64,
                w.vlan_id as i64,
                w.cipher as i64,
                w.rekey_period as i64,
            ],
        )?;
        Ok(())
    }

    /// All WLAN configurations pushed to a WTP, ordered by (radio, wlan).
    pub fn list_wlans(&self, mac: Mac) -> Result<Vec<RadioWlan>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT mac,radio_id,wlan_id,ssid,security,psk,
                wlan_enable,isolate,broadcast,client_count,vlan_id,cipher,rekey_period
             FROM radio_wlans WHERE mac=?1 ORDER BY radio_id, wlan_id",
        )?;
        let rows = stmt.query_map(params![&mac[..]], row_wlan)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// WLANs actually pushed during the Configure phase: `wlan_enable != 0`
    /// only. Disabling a WLAN in the DB (without deleting the row) drops it
    /// from the next config push; the management view still shows every row.
    pub fn list_wlans_enabled(&self, mac: Mac) -> Result<Vec<RadioWlan>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT mac,radio_id,wlan_id,ssid,security,psk,
                wlan_enable,isolate,broadcast,client_count,vlan_id,cipher,rekey_period
             FROM radio_wlans WHERE mac=?1 AND wlan_enable != 0
             ORDER BY radio_id, wlan_id",
        )?;
        let rows = stmt.query_map(params![&mac[..]], row_wlan)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Look up a single per-radio WLAN configuration.
    pub fn get_wlan(&self, mac: Mac, radio_id: u8, wlan_id: u8) -> Result<Option<RadioWlan>> {
        let conn = self.db.lock();
        let w = conn
            .query_row(
                "SELECT mac,radio_id,wlan_id,ssid,security,psk,
                    wlan_enable,isolate,broadcast,client_count,vlan_id,cipher,rekey_period
                 FROM radio_wlans
                 WHERE mac=?1 AND radio_id=?2 AND wlan_id=?3",
                params![&mac[..], radio_id, wlan_id],
                row_wlan,
            )
            .optional()?;
        Ok(w)
    }

    /// The H3C band-header config for a radio. Falls back to per-band defaults
    /// when no row has been stored yet: both bands up (enable=1, power=6,
    /// mode=0); 5G (radio 2) pins channel index 4 (165 MHz) so the band comes
    /// up on a stable channel without extra configuration.
    pub fn h3c_header(&self, mac: Mac, radio_id: u8) -> Result<H3cRadioHeader> {
        let conn = self.db.lock();
        let h = conn
            .query_row(
                "SELECT radio_enable,radio_power,radio_mode,radio_channel FROM radios
                 WHERE mac=?1 AND radio_id=?2",
                params![&mac[..], radio_id],
                |r| {
                    Ok(H3cRadioHeader {
                        radio_id,
                        enable: r.get::<_, i64>(0)? != 0,
                        power: r.get::<_, i64>(1)? as u32,
                        mode: r.get::<_, i64>(2)? as u32,
                        channel: r.get::<_, i64>(3)? as u32,
                    })
                },
            )
            .optional()?;
        Ok(h.unwrap_or(H3cRadioHeader {
            radio_id,
            enable: true,
            power: 6,
            mode: 0,
            channel: if radio_id == 2 { 4 } else { 0 },
        }))
    }

    /// Store the H3C band-header config for a radio. Inserts a row with the
    /// learned fields defaulted when the radio has not been seen yet.
    pub fn set_h3c_header(&self, mac: Mac, hdr: &H3cRadioHeader) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO radios (mac,radio_id,radio_enable,radio_power,radio_mode,radio_channel,last_seen)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(mac,radio_id) DO UPDATE SET
                radio_enable=excluded.radio_enable, radio_power=excluded.radio_power,
                radio_mode=excluded.radio_mode, radio_channel=excluded.radio_channel",
            params![
                &mac[..],
                hdr.radio_id,
                i64::from(hdr.enable),
                hdr.power as i64,
                hdr.mode as i64,
                hdr.channel as i64,
                now_unix() as i64,
            ],
        )?;
        Ok(())
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

fn row_wlan(r: &rusqlite::Row) -> rusqlite::Result<RadioWlan> {
    let mac: Vec<u8> = r.get(0)?;
    Ok(RadioWlan {
        mac: mac
            .try_into()
            .map_err(|e: Vec<u8>| rusqlite::Error::InvalidColumnIndex(0))?,
        radio_id: r.get::<_, i64>(1)? as u8,
        wlan_id: r.get::<_, i64>(2)? as u8,
        ssid: r.get(3)?,
        security: r.get(4)?,
        psk: r.get(5)?,
        wlan_enable: r.get::<_, i64>(6)? != 0,
        isolate: r.get::<_, i64>(7)? != 0,
        broadcast: r.get::<_, i64>(8)? != 0,
        client_count: r.get::<_, i64>(9)? as u32,
        vlan_id: r.get::<_, i64>(10)? as u32,
        cipher: r.get::<_, i64>(11)? as u32,
        rekey_period: r.get::<_, i64>(12)? as u32,
    })
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

    #[test]
    fn radio_wlan_set_and_list() {
        let s = store();
        let w = mac(1);
        s.set_wlan(&RadioWlan {
            mac: w,
            radio_id: 1,
            wlan_id: 1,
            ssid: "minimac".into(),
            security: "wpa2-wpa3".into(),
            psk: Some("person0finterest".into()),
            ..RadioWlan::default()
        })
        .unwrap();
        s.set_wlan(&RadioWlan {
            mac: w,
            radio_id: 2,
            wlan_id: 1,
            ssid: "minimac".into(),
            security: "wpa3".into(),
            psk: Some("person0finterest".into()),
            ..RadioWlan::default()
        })
        .unwrap();
        let wlans = s.list_wlans(w).unwrap();
        assert_eq!(wlans.len(), 2);
        assert_eq!(wlans[0].radio_id, 1);
        assert_eq!(wlans[0].security, "wpa2-wpa3");
        assert_eq!(wlans[0].psk.as_deref(), Some("person0finterest"));
        // H3C record defaults: SSID visible, AES cipher.
        assert!(wlans[0].broadcast);
        assert_eq!(wlans[0].cipher, 2);
        assert!(wlans[0].wlan_enable);
        assert_eq!(wlans[1].radio_id, 2);
        assert_eq!(wlans[1].ssid, "minimac");
        // Overwrite (upsert) keeps a single row per (radio, wlan).
        s.set_wlan(&RadioWlan {
            mac: w,
            radio_id: 1,
            wlan_id: 1,
            ssid: "renamed".into(),
            security: "open".into(),
            psk: None,
            broadcast: false,
            cipher: 0,
            ..RadioWlan::default()
        })
        .unwrap();
        let one = s.get_wlan(w, 1, 1).unwrap().unwrap();
        assert_eq!(one.ssid, "renamed");
        assert_eq!(one.security, "open");
        assert!(one.psk.is_none());
        assert!(!one.broadcast);
        assert_eq!(one.cipher, 0);
        assert_eq!(s.list_wlans(w).unwrap().len(), 2);
    }

    #[test]
    fn h3c_header_default_and_set() {
        let s = store();
        let w = mac(1);
        // No stored row -> per-band defaults (5G pins channel index 4).
        let g24 = s.h3c_header(w, 1).unwrap();
        assert!(g24.enable);
        assert_eq!(g24.power, 6);
        assert_eq!(g24.channel, 0);
        let g5 = s.h3c_header(w, 2).unwrap();
        assert!(g5.enable);
        assert_eq!(g5.channel, 4);
        // Stored row wins.
        s.set_h3c_header(
            w,
            &H3cRadioHeader {
                radio_id: 2,
                enable: true,
                power: 5,
                mode: 10,
                channel: 9,
            },
        )
        .unwrap();
        let g5 = s.h3c_header(w, 2).unwrap();
        assert_eq!(g5.power, 5);
        assert_eq!(g5.mode, 10);
        assert_eq!(g5.channel, 9);
    }
}
