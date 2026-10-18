//! SQLite access layer for persistent miniac data (devices, later radios/clients).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! A single `Mutex<Connection>` guards the SQLite connection; each operation locks
//! it for a single statement. Frequencies are low (device join/leave), so this is
//! sufficient without pulling in a full pool/async-sqlite stack.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

/// Table layouts. Created idempotently on open.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    mac         BLOB PRIMARY KEY NOT NULL,  -- 6 raw bytes
    name        TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    vendor      TEXT,
    model       TEXT,
    hw_version  TEXT,
    sw_version  TEXT,
    ip_addr     TEXT,
    state       TEXT NOT NULL DEFAULT 'unknown',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    joined_at   INTEGER,
    approved    INTEGER NOT NULL DEFAULT 0  -- 0=pending(awaiting admin), 1=managed
);

CREATE TABLE IF NOT EXISTS radios (
    mac         BLOB NOT NULL,             -- owning WTP MAC (6 raw bytes)
    radio_id    INTEGER NOT NULL,
    band        TEXT,                      -- learned: 2.4G / 5G / 6G
    admin_state INTEGER NOT NULL DEFAULT 0,
    op_state    INTEGER NOT NULL DEFAULT 0,
    channel     INTEGER,
    tx_power    INTEGER,
    -- H3C 0xfde8 per-band header config (radio_enable -> word0, power -> word2,
    -- mode -> word3, radio_channel -> word5; channel is the IEEE channel number,
    -- 0 = auto).
    radio_enable   INTEGER NOT NULL DEFAULT 1,
    radio_power    INTEGER NOT NULL DEFAULT 6,
    radio_mode     INTEGER NOT NULL DEFAULT 0,
    radio_channel  INTEGER NOT NULL DEFAULT 0,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (mac, radio_id)
);

CREATE TABLE IF NOT EXISTS stations (
    wmac         BLOB NOT NULL,            -- owning WTP MAC (parent device)
    mac          BLOB NOT NULL,            -- client MAC (6 raw bytes)
    radio_id     INTEGER NOT NULL DEFAULT 0,
    wlan_id      INTEGER NOT NULL DEFAULT 0,
    state        TEXT NOT NULL DEFAULT 'unknown',
    ip_addr      TEXT,
    ssid         TEXT,
    rssi         INTEGER,
    associated_at INTEGER,
    last_seen    INTEGER NOT NULL,
    PRIMARY KEY (wmac, mac)
);

CREATE TABLE IF NOT EXISTS security_profiles (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL UNIQUE,          -- AC-side WLAN security policy name
    method  TEXT NOT NULL DEFAULT '',      -- "wpa2-psk" | "wpa3-sae" | "802.1x" ...
    cipher  TEXT NOT NULL DEFAULT '',      -- "ccmp" | "tkip" ...
    caps    INTEGER NOT NULL DEFAULT 0     -- RsnCaps bitmask
);

CREATE TABLE IF NOT EXISTS firmware_upgrades (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    wmac        BLOB NOT NULL,             -- target WTP MAC (6 raw bytes)
    image       TEXT NOT NULL,             -- firmware identifier sent to the WTP
    size        INTEGER NOT NULL,          -- image file size in bytes
    hash        BLOB,                      -- 16-byte MD5 image hash (RFC 5415)
    state       TEXT NOT NULL DEFAULT 'downloading',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS firmware_images (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor      TEXT NOT NULL,
    model       TEXT NOT NULL,
    hw_version  TEXT NOT NULL,
    file_name   TEXT NOT NULL,             -- e.g. "ac100v3-1.3.bin"
    size        INTEGER NOT NULL,
    hash        BLOB NOT NULL,             -- 16-byte MD5 image hash (RFC 5415)
    stored_path TEXT NOT NULL,             -- relative path under the firmware root
    uploaded_at INTEGER NOT NULL,
    UNIQUE(vendor, model, hw_version, file_name)
);

-- Stage-1 discovery address pool: a single config row describing the
-- allocatable IPv4 range the AC leases to FIT-APs (DHCP-like). IPs are stored
-- as big-endian network-order u32 (u32::from(Ipv4Addr)).
CREATE TABLE IF NOT EXISTS address_pool (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    start_ip INTEGER NOT NULL,             -- first allocatable host address
    end_ip   INTEGER NOT NULL,             -- last allocatable host address
    gateway  INTEGER NOT NULL,
    netmask  INTEGER NOT NULL,
    ac_ip    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ap_leases (
    mac        BLOB PRIMARY KEY NOT NULL,  -- WTP board MAC (6 raw bytes)
    ip         INTEGER NOT NULL,           -- leased IPv4 within [start_ip, end_ip]
    leased_at  INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

-- Per-radio WLAN configuration pushed to a WTP (AC -> WTP forward direction).
-- Keyed by (mac, radio_id, wlan_id); the 2.4G and 5G radios carry independent
-- SSID/security settings. The security policy keeps its two orthogonal
-- dimensions in separate columns: `akm` ("open" | "psk" | "psk-sae" | "sae")
-- and `cipher` (1 TKIP / 2 AES / 3 TKIP+AES). `psk` holds the WPA passphrase
-- (8..63 chars) for a secured akm; `pmf` is the 802.11w policy.
CREATE TABLE IF NOT EXISTS radio_wlans (
    mac      BLOB NOT NULL,                -- owning WTP MAC (6 raw bytes)
    radio_id INTEGER NOT NULL,
    wlan_id  INTEGER NOT NULL DEFAULT 1,
    ssid     TEXT NOT NULL DEFAULT '',
    akm      TEXT NOT NULL DEFAULT 'open',
    cipher   INTEGER NOT NULL DEFAULT 2,
    pmf      TEXT NOT NULL DEFAULT 'disabled',
    psk      TEXT,
    -- H3C 0xfde8 record fields: wlan_enable (record slot up), isolate,
    -- broadcast (SSID visible when 1), client_count limit, vlan_id, cipher
    -- (1 TKIP / 2 AES / 3 TKIP+AES) and rekey_period.
    wlan_enable  INTEGER NOT NULL DEFAULT 1,
    isolate      INTEGER NOT NULL DEFAULT 0,
    broadcast    INTEGER NOT NULL DEFAULT 1,
    client_count INTEGER NOT NULL DEFAULT 0,
    vlan_id      INTEGER NOT NULL DEFAULT 0,
    rekey_period INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, radio_id, wlan_id)
);

-- Global (AC-wide) radio settings per band. band: 1 = 2.4G, 2 = 5G (matches the
-- AX60 radio-id-to-band mapping `band = radio_id - 1`, 0x3ff20). These are
-- templates materialized into each WTP's `radios` row.
CREATE TABLE IF NOT EXISTS global_radio (
    band         INTEGER PRIMARY KEY,
    enable       INTEGER NOT NULL DEFAULT 1,
    channel      INTEGER NOT NULL DEFAULT 0,  -- IEEE channel number; 0 = auto
    power        INTEGER NOT NULL DEFAULT 6,
    mode         INTEGER NOT NULL DEFAULT 0
);

-- Global WLAN (SSID) templates per band, materialized into `radio_wlans`.
-- Columns mirror radio_wlans' H3C 0xfde8 record fields.
CREATE TABLE IF NOT EXISTS global_wlan (
    band         INTEGER NOT NULL,
    wlan_id      INTEGER NOT NULL DEFAULT 1,
    ssid         TEXT NOT NULL DEFAULT '',
    akm          TEXT NOT NULL DEFAULT 'open',
    cipher       INTEGER NOT NULL DEFAULT 2,
    pmf          TEXT NOT NULL DEFAULT 'disabled',
    psk          TEXT,
    wlan_enable  INTEGER NOT NULL DEFAULT 1,
    isolate      INTEGER NOT NULL DEFAULT 0,
    broadcast    INTEGER NOT NULL DEFAULT 1,
    client_count INTEGER NOT NULL DEFAULT 0,
    vlan_id      INTEGER NOT NULL DEFAULT 0,
    rekey_period INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (band, wlan_id)
);

-- Product capability registry (`product_caps`) is created and imported
-- separately by `init_product_caps` from the embedded adaptation text.

-- Per-AP overrides of the global radio settings. A NULL column inherits the
-- global value; a non-NULL one wins. Keyed by (mac, band).
CREATE TABLE IF NOT EXISTS ap_override (
    mac     BLOB NOT NULL,                -- owning WTP MAC (6 raw bytes)
    band    INTEGER NOT NULL,
    channel INTEGER,
    power   INTEGER,
    mode    INTEGER,
    PRIMARY KEY (mac, band)
);

-- APs whose configuration has diverged from what was last pushed, awaiting a
-- Configuration Update (mtype 7) commit. Cleared on the WTP's response.
CREATE TABLE IF NOT EXISTS cfg_pending (
    mac       BLOB PRIMARY KEY NOT NULL,
    marked_at INTEGER NOT NULL
);
"#;

/// Initialization defaults, applied idempotently on open. These fill the
/// required configuration the AC needs to serve a WTP; queries never fall back
/// to hardcoded defaults, so a row missing here is a sanity-check failure at
/// startup rather than a silent default at query time.
///
/// global_radio: both bands up (enable=1), auto channel (0 = ACS / the vendor's
/// stable band default), power 6. global_wlan: one secured SSID per band.
/// Product capabilities are not seeded here; see `init_product_caps`.
const SEED: &str = r#"
INSERT OR IGNORE INTO global_radio (band,enable,channel,power,mode) VALUES
    (1,1,0,6,0),
    (2,1,0,6,0);

INSERT OR IGNORE INTO global_wlan
    (band,wlan_id,ssid,akm,cipher,pmf,psk,wlan_enable,isolate,broadcast,
     client_count,vlan_id,rekey_period) VALUES
    (1,1,'miniac','psk-sae',2,'disabled','person0finterest',1,0,1,0,0,0),
    (2,1,'miniac','psk-sae',2,'disabled','person0finterest',1,0,1,0,0,0);
"#;

/// Capability registry layout. Keyed by (vendor, model, version) so data
/// collected during device adaptation can pin a firmware/hardware revision;
/// empty `model`/`version` are wildcards. The masks are bit sets over
/// config::{Akm,Cipher,Pmf}; a zero mask means "uncharacterized" rather than
/// "unsupported".
const PRODUCT_CAPS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS product_caps (
    vendor      TEXT NOT NULL,
    model       TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    akm_mask    INTEGER NOT NULL DEFAULT 0,
    cipher_mask INTEGER NOT NULL DEFAULT 0,
    pmf_mask    INTEGER NOT NULL DEFAULT 0,
    source      TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (vendor, model, version)
);
"#;

/// SQLite-backed persistent store.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Open (or create) a database file and ensure the schema exists.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path.as_ref()).context("open sqlite db")?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (tests, CLI smoke runs). No persistence.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory sqlite db")?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.lock();
        conn.execute_batch(SCHEMA).context("create schema")?;
        // Migrations: add columns to pre-existing databases where the
        // CREATE TABLE IF NOT EXISTS above is a no-op.
        ensure_columns(&conn, "devices", &[("approved", "INTEGER NOT NULL DEFAULT 0")])
            .context("migrate devices.approved")?;
        ensure_columns(
            &conn,
            "radios",
            &[
                ("radio_enable", "INTEGER NOT NULL DEFAULT 1"),
                ("radio_power", "INTEGER NOT NULL DEFAULT 6"),
                ("radio_mode", "INTEGER NOT NULL DEFAULT 0"),
                ("radio_channel", "INTEGER NOT NULL DEFAULT 0"),
            ],
        )
        .context("migrate radios h3c header")?;
        // Pre-split databases stored the policy in one `security` string and the
        // cipher in the integer `cipher` column (same 1/2/3 numbering). Detect the
        // missing `akm` column before adding it, so the one-time split runs
        // exactly once and the stale `security` column can never overwrite a
        // later edit.
        let split_wlans = !has_column(&conn, "radio_wlans", "akm")?;
        ensure_columns(
            &conn,
            "radio_wlans",
            &[
                ("akm", "TEXT NOT NULL DEFAULT 'open'"),
                ("pmf", "TEXT NOT NULL DEFAULT 'disabled'"),
                ("wlan_enable", "INTEGER NOT NULL DEFAULT 1"),
                ("isolate", "INTEGER NOT NULL DEFAULT 0"),
                ("broadcast", "INTEGER NOT NULL DEFAULT 1"),
                ("client_count", "INTEGER NOT NULL DEFAULT 0"),
                ("vlan_id", "INTEGER NOT NULL DEFAULT 0"),
                ("cipher", "INTEGER NOT NULL DEFAULT 2"),
                ("rekey_period", "INTEGER NOT NULL DEFAULT 0"),
            ],
        )
        .context("migrate radio_wlans h3c record")?;
        if split_wlans {
            split_legacy_security(&conn, "radio_wlans").context("split radio_wlans security")?;
        }
        let split_global = !has_column(&conn, "global_wlan", "akm")?;
        ensure_columns(
            &conn,
            "global_wlan",
            &[
                ("akm", "TEXT NOT NULL DEFAULT 'open'"),
                ("pmf", "TEXT NOT NULL DEFAULT 'disabled'"),
            ],
        )
        .context("migrate global_wlan security")?;
        if split_global {
            split_legacy_security(&conn, "global_wlan").context("split global_wlan security")?;
        }
        // Initialization defaults, then the capability registry imported from
        // the embedded adaptation text, then a sanity check: required config
        // that has no reasonable default must exist or startup fails.
        conn.execute_batch(SEED).context("seed defaults")?;
        init_product_caps(&conn).context("import product capabilities")?;
        self.sanity_check(&conn)?;
        Ok(())
    }

    /// Fail when configuration the AC cannot reasonably default (and whose
    /// absence would leave a band unserviceable) is not initialized. The seeds
    /// above satisfy this on a fresh database; only a corrupted or partially
    /// migrated one fails, which is preferable to querying into a silent default.
    fn sanity_check(&self, conn: &Connection) -> Result<()> {
        for table in ["global_radio", "global_wlan"] {
            for band in [1i64, 2] {
                let n: i64 = conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE band=?1"),
                    [band],
                    |r| r.get(0),
                )?;
                if n == 0 {
                    anyhow::bail!(
                        "sanity check failed: {table} has no row for band {band}; \
                         db initialization did not provide the required default"
                    );
                }
            }
        }
        Ok(())
    }

    /// Acquire the underlying connection (single-statement transactional use).
    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// (Re)import the capability registry from the embedded adaptation text. The
/// table is fully derived data, so it is rebuilt on every initialization: a
/// schema predating the `version` dimension is dropped and recreated, then the
/// text is parsed and inserted fresh.
fn init_product_caps(conn: &Connection) -> Result<()> {
    if !has_column(conn, "product_caps", "version")? {
        conn.execute("DROP TABLE IF EXISTS product_caps", [])?;
    }
    conn.execute_batch(PRODUCT_CAPS_SCHEMA)?;
    conn.execute("DELETE FROM product_caps", [])?;
    for c in crate::fleet::parse_product_caps(crate::fleet::PRODUCT_CAPS_TEXT)? {
        conn.execute(
            "INSERT INTO product_caps
                (vendor,model,version,akm_mask,cipher_mask,pmf_mask,source,notes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                c.vendor,
                c.model,
                c.version,
                c.akm_mask as i64,
                c.cipher_mask as i64,
                c.pmf_mask as i64,
                c.source,
                c.notes
            ],
        )?;
    }
    Ok(())
}

/// Whether `table` already has a column named `col`.
fn has_column(conn: &Connection, table: &str, col: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(names.iter().any(|c| c == col))
}

/// One-time migration from the legacy single-string `security` policy to the
/// orthogonal `akm` column. The cipher already lives in the integer `cipher`
/// column with the same 1/2/3 (TKIP/AES/TKIP+AES) numbering, so only the AKM
/// needs backfilling. A no-op when the legacy column is absent (fresh DB).
fn split_legacy_security(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    if !has_column(conn, table, "security")? {
        return Ok(());
    }
    conn.execute_batch(&format!(
        "UPDATE {table} SET akm = CASE security
            WHEN 'wpa2' THEN 'psk'
            WHEN 'wpa2-wpa3' THEN 'psk-sae'
            WHEN 'wpa3' THEN 'sae'
            ELSE 'open' END"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_caps_imported_on_init() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let rows: Vec<(String, String, String, i64, i64)> = conn
            .prepare(
                "SELECT vendor,model,version,akm_mask,cipher_mask \
                 FROM product_caps ORDER BY vendor",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("h3c".to_string(), String::new(), String::new(), 7, 7),
                ("tplink".to_string(), String::new(), String::new(), 3, 2),
            ]
        );
    }

    #[test]
    fn legacy_product_caps_table_is_rebuilt_with_version() {
        // A table created before the `version` dimension is dropped and
        // recreated, then repopulated from the embedded text.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE product_caps (
                vendor TEXT, model TEXT, akm_mask INTEGER, cipher_mask INTEGER,
                pmf_mask INTEGER, source TEXT, notes TEXT, PRIMARY KEY (vendor, model));
             INSERT INTO product_caps VALUES ('h3c','',7,7,0,'x','y');",
        )
        .unwrap();
        init_product_caps(&conn).unwrap();
        assert!(has_column(&conn, "product_caps", "version").unwrap());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM product_caps", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn legacy_security_column_splits_into_akm() {
        // A pre-split table carried the policy in one `security` string.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE radio_wlans (
                wlan_id INTEGER NOT NULL, security TEXT NOT NULL DEFAULT 'open',
                akm TEXT NOT NULL DEFAULT 'open');
             INSERT INTO radio_wlans (wlan_id,security) VALUES
                (1,'wpa2'), (2,'wpa3'), (3,'wpa2-wpa3'), (4,'open');",
        )
        .unwrap();
        split_legacy_security(&conn, "radio_wlans").unwrap();
        let akms: Vec<String> = conn
            .prepare("SELECT akm FROM radio_wlans ORDER BY wlan_id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(akms, ["psk", "sae", "psk-sae", "open"]);

        // A table without the legacy column (fresh DB) is left untouched.
        let fresh = Connection::open_in_memory().unwrap();
        fresh
            .execute_batch("CREATE TABLE radio_wlans (wlan_id INTEGER NOT NULL, akm TEXT)")
            .unwrap();
        split_legacy_security(&fresh, "radio_wlans").unwrap();
    }
}

/// Add any missing columns to `table`, for databases created before the column
/// existed (the CREATE TABLE IF NOT EXISTS is a no-op there). `ddl` is the
/// full `type ... DEFAULT ...` clause used by both CREATE TABLE and ALTER.
fn ensure_columns(
    conn: &Connection,
    table: &str,
    cols: &[(&str, &str)],
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, ddl) in cols {
        if !existing.iter().any(|c| c == name) {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {name} {ddl}"))?;
        }
    }
    Ok(())
}
