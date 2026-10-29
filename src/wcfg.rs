//! Global wireless configuration (AC-wide, per band) with per-AP overrides and
//! a pending-sync set, materialized into the per-WTP radio rows.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! `band` matches the AX60 radio-id mapping (`band = radio_id - 1`, 0x3ff20):
//! 1 = 2.4G, 2 = 5G. The global layer is a template; a per-AP override
//! (channel / power / mode) wins over it. Editing either layer marks the
//! affected WTPs as *pending*; a commit pushes a Configuration Update Request
//! and clears the entry when the WTP acknowledges.

use std::sync::Arc;

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::config::{Akm, Cipher, Pmf, SecurityPolicy};
use crate::db::Db;
use crate::device::Mac;
use crate::radio::{H3cRadioHeader, RadioStore, RadioWlan};
use crate::vendor::profile::VendorProfile;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Wireless band; the discriminant equals the AX60 radio id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    Ghz24 = 1,
    Ghz5 = 2,
}

impl Band {
    pub const ALL: [Band; 2] = [Band::Ghz24, Band::Ghz5];

    /// AX60 radio id (1 = 2.4G, 2 = 5G).
    pub fn radio_id(self) -> u8 {
        self as u8
    }

    /// Map an AX60 radio id back to a band.
    pub fn from_radio_id(id: u8) -> Option<Band> {
        match id {
            1 => Some(Band::Ghz24),
            2 => Some(Band::Ghz5),
            _ => None,
        }
    }
}

/// Global radio template for a band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalRadio {
    pub band: u8,
    pub enable: bool,
    /// IEEE channel number; 0 = auto (ACS / the vendor's stable band default).
    pub channel: u32,
    pub power: u32,
    pub mode: u32,
}

impl Default for GlobalRadio {
    fn default() -> Self {
        GlobalRadio {
            band: Band::Ghz24 as u8,
            enable: true,
            channel: 0,
            power: 6,
            mode: 0,
        }
    }
}

/// Global WLAN (SSID) template for a band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalWlan {
    pub band: u8,
    pub wlan_id: u8,
    pub ssid: String,
    /// Key-management and cipher policy (orthogonal dimensions) plus the WPA
    /// passphrase for a secured network.
    pub security: SecurityPolicy,
    pub wlan_enable: bool,
    pub isolate: bool,
    pub broadcast: bool,
    pub client_count: u32,
    pub vlan_id: u32,
    pub rekey_period: u32,
}

impl GlobalWlan {
    /// Materialize this template into a per-WTP row.
    pub fn to_radio_wlan(&self, mac: Mac) -> RadioWlan {
        RadioWlan {
            mac,
            radio_id: self.band,
            wlan_id: self.wlan_id,
            ssid: self.ssid.clone(),
            security: self.security.clone(),
            wlan_enable: self.wlan_enable,
            isolate: self.isolate,
            broadcast: self.broadcast,
            client_count: self.client_count,
            vlan_id: self.vlan_id,
            rekey_period: self.rekey_period,
        }
    }
}

/// WLAN-only VLAN definition. SSIDs reference it by `vlan_id`; `name` is a
/// local label and is never pushed to an AP (the vendors only carry the id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiVlan {
    pub vlan_id: u16,
    pub name: String,
}

/// Per-AP override of the global radio settings; `None` inherits the global.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApOverride {
    pub mac: Mac,
    pub band: u8,
    pub channel: Option<u32>,
    pub power: Option<u32>,
    pub mode: Option<u32>,
}

/// Global wireless configuration store: templates, overrides and pending set.
pub struct WirelessConfigStore {
    db: Arc<Db>,
}

impl WirelessConfigStore {
    pub fn new(db: Arc<Db>) -> Self {
        WirelessConfigStore { db }
    }

    // --- global radio ---

    /// The global radio template for a band. The row is seeded at DB init
    /// (`db::SCHEMA`/seed), so a missing row is an error rather than a silent
    /// default.
    pub fn get_global_radio(&self, band: u8) -> Result<GlobalRadio> {
        if Band::from_radio_id(band).is_none() {
            anyhow::bail!("invalid band {band}");
        }
        let conn = self.db.lock();
        let g = conn
            .query_row(
                "SELECT band,enable,channel,power,mode FROM global_radio WHERE band=?1",
                params![band],
                |r| {
                    Ok(GlobalRadio {
                        band: r.get::<_, i64>(0)? as u8,
                        enable: r.get::<_, i64>(1)? != 0,
                        channel: r.get::<_, i64>(2)? as u32,
                        power: r.get::<_, i64>(3)? as u32,
                        mode: r.get::<_, i64>(4)? as u32,
                    })
                },
            )
            .optional()?;
        g.ok_or_else(|| anyhow::anyhow!("global_radio band {band} not initialized"))
    }

    /// Both bands' global radio templates, 2.4G first.
    pub fn list_global_radios(&self) -> Result<Vec<GlobalRadio>> {
        Band::ALL
            .iter()
            .map(|b| self.get_global_radio(b.radio_id()))
            .collect()
    }

    pub fn set_global_radio(&self, g: &GlobalRadio) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO global_radio (band,enable,channel,power,mode)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(band) DO UPDATE SET enable=excluded.enable,
                channel=excluded.channel,
                power=excluded.power, mode=excluded.mode",
            params![g.band, i64::from(g.enable), g.channel, g.power, g.mode],
        )?;
        Ok(())
    }

    // --- global WLAN ---

    /// Global WLAN templates for a band, ordered by wlan id.
    pub fn list_global_wlans(&self, band: u8) -> Result<Vec<GlobalWlan>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT band,wlan_id,ssid,akm,cipher,pmf,psk,wlan_enable,isolate,broadcast,
                client_count,vlan_id,rekey_period
             FROM global_wlan WHERE band=?1 ORDER BY wlan_id",
        )?;
        let rows = stmt.query_map(params![band], |r| {
            let akm: String = r.get(3)?;
            let cipher: i64 = r.get(4)?;
            let pmf: String = r.get(5)?;
            Ok(GlobalWlan {
                band: r.get::<_, i64>(0)? as u8,
                wlan_id: r.get::<_, i64>(1)? as u8,
                ssid: r.get(2)?,
                security: SecurityPolicy {
                    akm: Akm::from_str(&akm).unwrap_or_default(),
                    cipher: Cipher::from_wire(cipher as u32).unwrap_or_default(),
                    psk: r.get(6)?,
                    pmf: Pmf::from_str(&pmf).unwrap_or_default(),
                },
                wlan_enable: r.get::<_, i64>(7)? != 0,
                isolate: r.get::<_, i64>(8)? != 0,
                broadcast: r.get::<_, i64>(9)? != 0,
                client_count: r.get::<_, i64>(10)? as u32,
                vlan_id: r.get::<_, i64>(11)? as u32,
                rekey_period: r.get::<_, i64>(12)? as u32,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn set_global_wlan(&self, w: &GlobalWlan) -> Result<()> {
        if Band::from_radio_id(w.band).is_none() {
            anyhow::bail!("invalid band {}", w.band);
        }
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO global_wlan (band,wlan_id,ssid,akm,cipher,pmf,psk,wlan_enable,isolate,
                broadcast,client_count,vlan_id,rekey_period)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(band,wlan_id) DO UPDATE SET ssid=excluded.ssid,
                akm=excluded.akm, cipher=excluded.cipher, pmf=excluded.pmf,
                psk=excluded.psk,
                wlan_enable=excluded.wlan_enable, isolate=excluded.isolate,
                broadcast=excluded.broadcast, client_count=excluded.client_count,
                vlan_id=excluded.vlan_id, rekey_period=excluded.rekey_period",
            params![
                w.band,
                w.wlan_id,
                w.ssid,
                w.security.akm.as_str(),
                w.security.cipher.wire() as i64,
                w.security.pmf.as_str(),
                w.security.psk,
                i64::from(w.wlan_enable),
                i64::from(w.isolate),
                i64::from(w.broadcast),
                w.client_count as i64,
                w.vlan_id as i64,
                w.rekey_period as i64,
            ],
        )?;
        Ok(())
    }

    pub fn delete_global_wlan(&self, band: u8, wlan_id: u8) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "DELETE FROM global_wlan WHERE band=?1 AND wlan_id=?2",
            params![band, wlan_id],
        )?;
        Ok(())
    }

    // --- WLAN-only VLAN definitions ---

    /// Every defined VLAN, ascending by id.
    pub fn list_vlans(&self) -> Result<Vec<WifiVlan>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare("SELECT vlan_id,name FROM wifi_vlan ORDER BY vlan_id")?;
        let rows = stmt.query_map([], |r| {
            Ok(WifiVlan {
                vlan_id: r.get::<_, i64>(0)? as u16,
                name: r.get(1)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn vlan_exists(&self, vlan_id: u16) -> Result<bool> {
        let conn = self.db.lock();
        let n = conn.query_row(
            "SELECT COUNT(*) FROM wifi_vlan WHERE vlan_id=?1",
            params![vlan_id],
            |r| r.get::<_, i64>(0),
        )?;
        Ok(n > 0)
    }

    /// Insert a definition, or update the one at `old_id`. Re-keying an id
    /// also moves every SSID that referenced the old id, so a VLAN stays
    /// attached to its SSIDs.
    pub fn set_vlan(&self, old_id: Option<u16>, v: &WifiVlan) -> Result<()> {
        if v.vlan_id == 0 {
            anyhow::bail!("VLAN id 0 means untagged and cannot be defined");
        }
        let conn = self.db.lock();
        let defined = |id: u16| -> Result<bool> {
            let n = conn.query_row(
                "SELECT COUNT(*) FROM wifi_vlan WHERE vlan_id=?1",
                params![id],
                |r| r.get::<_, i64>(0),
            )?;
            Ok(n > 0)
        };
        match old_id {
            Some(old) => {
                if !defined(old)? {
                    anyhow::bail!("VLAN {old} is not defined");
                }
                if old == v.vlan_id {
                    conn.execute(
                        "UPDATE wifi_vlan SET name=?1 WHERE vlan_id=?2",
                        params![v.name, v.vlan_id],
                    )?;
                } else {
                    if defined(v.vlan_id)? {
                        anyhow::bail!("VLAN {} is already defined", v.vlan_id);
                    }
                    let tx = conn.unchecked_transaction()?;
                    tx.execute(
                        "UPDATE global_wlan SET vlan_id=?1 WHERE vlan_id=?2",
                        params![v.vlan_id, old],
                    )?;
                    tx.execute(
                        "UPDATE wifi_vlan SET vlan_id=?1, name=?2 WHERE vlan_id=?3",
                        params![v.vlan_id, v.name, old],
                    )?;
                    tx.commit()?;
                }
            }
            None => {
                if defined(v.vlan_id)? {
                    anyhow::bail!("VLAN {} is already defined", v.vlan_id);
                }
                conn.execute(
                    "INSERT INTO wifi_vlan (vlan_id,name) VALUES (?1,?2)",
                    params![v.vlan_id, v.name],
                )?;
            }
        }
        Ok(())
    }

    /// Delete an unused definition. A VLAN still referenced by any SSID is
    /// refused so no SSID is left pointing at a missing id.
    pub fn delete_vlan(&self, vlan_id: u16) -> Result<()> {
        let conn = self.db.lock();
        let used = conn.query_row(
            "SELECT COUNT(*) FROM global_wlan WHERE vlan_id=?1",
            params![vlan_id],
            |r| r.get::<_, i64>(0),
        )?;
        if used > 0 {
            anyhow::bail!("VLAN {vlan_id} is still used by {used} SSID(s)");
        }
        conn.execute("DELETE FROM wifi_vlan WHERE vlan_id=?1", params![vlan_id])?;
        Ok(())
    }

    // --- per-AP override ---

    /// Every stored per-AP override.
    pub fn list_overrides(&self) -> Result<Vec<ApOverride>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT mac,band,channel,power,mode FROM ap_override ORDER BY mac, band",
        )?;
        let rows = stmt.query_map([], |r| {
            let mac: Vec<u8> = r.get(0)?;
            Ok(ApOverride {
                mac: mac
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidColumnIndex(0))?,
                band: r.get::<_, i64>(1)? as u8,
                channel: r.get(2)?,
                power: r.get(3)?,
                mode: r.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_override(&self, mac: Mac, band: u8) -> Result<Option<ApOverride>> {
        let conn = self.db.lock();
        let o = conn
            .query_row(
                "SELECT mac,band,channel,power,mode FROM ap_override WHERE mac=?1 AND band=?2",
                params![&mac[..], band],
                |r| {
                    let m: Vec<u8> = r.get(0)?;
                    Ok(ApOverride {
                        mac: m
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidColumnIndex(0))?,
                        band: r.get::<_, i64>(1)? as u8,
                        channel: r.get(2)?,
                        power: r.get(3)?,
                        mode: r.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(o)
    }

    pub fn set_override(&self, o: &ApOverride) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO ap_override (mac,band,channel,power,mode) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(mac,band) DO UPDATE SET channel=excluded.channel,
                power=excluded.power, mode=excluded.mode",
            params![&o.mac[..], o.band, o.channel, o.power, o.mode],
        )?;
        Ok(())
    }

    pub fn clear_override(&self, mac: Mac, band: u8) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "DELETE FROM ap_override WHERE mac=?1 AND band=?2",
            params![&mac[..], band],
        )?;
        Ok(())
    }

    // --- pending set ---

    pub fn list_pending(&self) -> Result<Vec<Mac>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare("SELECT mac FROM cfg_pending ORDER BY marked_at")?;
        let rows = stmt.query_map([], |r| {
            let mac: Vec<u8> = r.get(0)?;
            mac.try_into()
                .map_err(|_| rusqlite::Error::InvalidColumnIndex(0))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn is_pending(&self, mac: Mac) -> Result<bool> {
        let conn = self.db.lock();
        let n = conn.query_row(
            "SELECT COUNT(*) FROM cfg_pending WHERE mac=?1",
            params![&mac[..]],
            |r| r.get::<_, i64>(0),
        )?;
        Ok(n > 0)
    }

    pub fn mark_pending(&self, mac: Mac) -> Result<()> {
        let conn = self.db.lock();
        conn.execute(
            "INSERT INTO cfg_pending (mac,marked_at) VALUES (?1,?2)
             ON CONFLICT(mac) DO UPDATE SET marked_at=excluded.marked_at",
            params![&mac[..], now_unix()],
        )?;
        Ok(())
    }

    pub fn clear_pending(&self, mac: Mac) -> Result<()> {
        let conn = self.db.lock();
        conn.execute("DELETE FROM cfg_pending WHERE mac=?1", params![&mac[..]])?;
        Ok(())
    }

    // --- effective config + materialization ---

    /// The IEEE channel number governing a band on one WTP: a per-AP override
    /// pinned channel wins over the global template, otherwise the global
    /// `channel` applies. `0` means auto (ACS). This is the one place the
    /// auto/fixed decision is made; each vendor maps the number to its own wire
    /// field (`VendorProfile::radio_channel_field`).
    pub fn effective_channel(&self, mac: Mac, band: u8) -> Result<u32> {
        if let Some(c) = self.get_override(mac, band)?.and_then(|o| o.channel) {
            return Ok(c);
        }
        Ok(self.get_global_radio(band)?.channel)
    }

    /// The effective H3C radio header for a WTP: the global template merged with
    /// any per-AP override, with the channel number mapped to the H3C 0xfde8
    /// header's channel field (the IEEE number, 0 = auto).
    pub fn effective_radio(&self, mac: Mac, band: u8) -> Result<H3cRadioHeader> {
        let g = self.get_global_radio(band)?;
        let o = self.get_override(mac, band)?;
        let channel = self.effective_channel(mac, band)?;
        Ok(H3cRadioHeader {
            radio_id: band,
            enable: g.enable,
            power: o.as_ref().and_then(|o| o.power).unwrap_or(g.power),
            mode: o.as_ref().and_then(|o| o.mode).unwrap_or(g.mode),
            channel: VendorProfile::H3c.radio_channel_field(band, channel),
        })
    }

    /// Write the effective configuration for one WTP into the per-WTP
    /// `radios` / `radio_wlans` rows the Configure push reads.
    ///
    /// For each band that has global WLAN templates the WTP's rows for that band
    /// are replaced (so deletions propagate); a band with no global templates is
    /// left untouched (legacy per-AP configuration / not yet configured).
    pub fn materialize(&self, radios: &RadioStore, mac: Mac) -> Result<()> {
        for b in Band::ALL {
            let hdr = self.effective_radio(mac, b.radio_id())?;
            radios.set_h3c_header(mac, &hdr)?;
            let globals = self.list_global_wlans(b.radio_id())?;
            if globals.is_empty() {
                continue;
            }
            radios.delete_wlans_for_band(mac, b.radio_id())?;
            for g in &globals {
                radios.set_wlan(&g.to_radio_wlan(mac))?;
            }
        }
        Ok(())
    }

    /// Materialize for several WTPs and mark them pending. Returns the MACs.
    pub fn materialize_all(&self, radios: &RadioStore, macs: &[Mac]) -> Result<Vec<Mac>> {
        for m in macs {
            self.materialize(radios, *m)?;
            self.mark_pending(*m)?;
        }
        Ok(macs.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (Arc<Db>, WirelessConfigStore, RadioStore) {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let w = WirelessConfigStore::new(db.clone());
        let r = RadioStore::new(db.clone());
        (db, w, r)
    }

    fn mac(id: u8) -> Mac {
        [0, 0, 0, 0, 0, id]
    }

    fn gw(band: u8, wlan_id: u8, ssid: &str) -> GlobalWlan {
        GlobalWlan {
            band,
            wlan_id,
            ssid: ssid.into(),
            security: SecurityPolicy {
                akm: Akm::Psk,
                cipher: Cipher::Ccmp,
                psk: Some("passphrase0".into()),
                pmf: Pmf::Disabled,
            },
            wlan_enable: true,
            isolate: false,
            broadcast: true,
            client_count: 0,
            vlan_id: 0,
            rekey_period: 0,
        }
    }

    #[test]
    fn vlan_rekey_follows_ssids_and_referenced_delete_is_refused() {
        let (_db, w, _r) = store();
        let v = |id: u16, name: &str| WifiVlan {
            vlan_id: id,
            name: name.into(),
        };
        w.set_vlan(None, &v(10, "office")).unwrap();
        let mut g = gw(1, 1, "miniac");
        g.vlan_id = 10;
        w.set_global_wlan(&g).unwrap();
        // Duplicate id and the untagged id 0 are refused.
        assert!(w.set_vlan(None, &v(10, "dup")).is_err());
        assert!(w.set_vlan(None, &v(0, "x")).is_err());
        // Re-keying moves the referencing SSID to the new id.
        w.set_vlan(Some(10), &v(20, "office")).unwrap();
        assert_eq!(w.list_global_wlans(1).unwrap()[0].vlan_id, 20);
        assert!(!w.vlan_exists(10).unwrap());
        // A referenced VLAN cannot be deleted; after untagging it can.
        assert!(w.delete_vlan(20).is_err());
        g.vlan_id = 0;
        w.set_global_wlan(&g).unwrap();
        w.delete_vlan(20).unwrap();
        assert!(w.list_vlans().unwrap().is_empty());
    }

    #[test]
    fn global_radio_defaults_and_set() {
        let (_db, w, _r) = store();
        assert_eq!(w.get_global_radio(1).unwrap().power, 6);
        assert_eq!(w.get_global_radio(1).unwrap().channel, 0);
        assert_eq!(w.list_global_radios().unwrap().len(), 2);
        w.set_global_radio(&GlobalRadio {
            band: 2,
            enable: true,
            channel: 9,
            power: 3,
            mode: 5,
        })
        .unwrap();
        let g = w.get_global_radio(2).unwrap();
        assert_eq!((g.channel, g.power, g.mode), (9, 3, 5));
    }

    #[test]
    fn override_wins_over_global() {
        let (_db, w, _r) = store();
        w.set_global_radio(&GlobalRadio {
            band: 1,
            enable: true,
            channel: 6,
            power: 6,
            mode: 0,
        })
        .unwrap();
        // No override: global channel applies.
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().channel, 6);
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().power, 6);
        // Override power only: channel still inherited (global 6).
        w.set_override(&ApOverride {
            mac: mac(1),
            band: 1,
            channel: None,
            power: Some(2),
            mode: None,
        })
        .unwrap();
        let e = w.effective_radio(mac(1), 1).unwrap();
        assert_eq!(e.channel, 6);
        assert_eq!(e.power, 2);
        // Override channel: wins; and another AP is unaffected.
        w.set_override(&ApOverride {
            mac: mac(1),
            band: 1,
            channel: Some(11),
            power: Some(2),
            mode: None,
        })
        .unwrap();
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().channel, 11);
        assert_eq!(w.effective_radio(mac(2), 1).unwrap().channel, 6);
        // Override channel 0 pins auto for that AP.
        w.set_override(&ApOverride {
            mac: mac(1),
            band: 1,
            channel: Some(0),
            power: Some(2),
            mode: None,
        })
        .unwrap();
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().channel, 0);
        // Clearing the override returns to the global template.
        w.clear_override(mac(1), 1).unwrap();
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().channel, 6);
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().power, 6);
    }

    #[test]
    fn auto_channel_passes_through_as_zero() {
        let (_db, w, _r) = store();
        // The DB channel is the IEEE number with 0 = auto; the H3C header carries
        // it verbatim (0 = AUTO on both bands).
        assert_eq!(w.effective_radio(mac(1), 1).unwrap().channel, 0);
        assert_eq!(w.effective_radio(mac(1), 2).unwrap().channel, 0);
    }

    #[test]
    fn materialize_replaces_band_rows_and_marks_pending() {
        let (_db, w, r) = store();
        // Legacy per-AP row that must be replaced once a global template exists.
        r.set_wlan(&RadioWlan {
            mac: mac(1),
            radio_id: 1,
            wlan_id: 9,
            ssid: "legacy".into(),
            ..RadioWlan::default()
        })
        .unwrap();
        // 2.4G global is replaced with two SSIDs; 5G keeps its seeded template.
        w.set_global_wlan(&gw(1, 1, "corp")).unwrap();
        w.set_global_wlan(&gw(1, 2, "guest")).unwrap();
        w.materialize_all(&r, &[mac(1)]).unwrap();

        let wl = r.list_wlans(mac(1)).unwrap();
        // 2.4G: corp + guest; 5G: the seeded default SSID.
        assert_eq!(wl.len(), 3, "each band materialized from its global templates");
        let g24: Vec<_> = wl.iter().filter(|w| w.radio_id == 1).collect();
        assert_eq!(g24.len(), 2);
        assert_eq!(g24[0].ssid, "corp");
        assert_eq!(g24[1].ssid, "guest");
        assert_eq!(wl.iter().filter(|w| w.radio_id == 2).count(), 1);
        // Effective radio header persisted (auto channel -> H3C AUTO 0).
        assert_eq!(r.h3c_header(mac(1), 1).unwrap().channel, 0);
        assert_eq!(r.h3c_header(mac(1), 2).unwrap().channel, 0);
        // Marked pending.
        assert!(w.is_pending(mac(1)).unwrap());
        assert_eq!(w.list_pending().unwrap(), vec![mac(1)]);
        w.clear_pending(mac(1)).unwrap();
        assert!(!w.is_pending(mac(1)).unwrap());
    }
}
