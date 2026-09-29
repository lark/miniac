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
use rusqlite::Connection;

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
        // Migration: add the `approved` column to pre-existing databases where
        // CREATE TABLE IF NOT EXISTS above is a no-op.
        let mut stmt = conn
            .prepare("PRAGMA table_info(devices)")
            .context("pragma table_info")?;
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .context("read devices columns")?
            .collect::<rusqlite::Result<_>>()
            .context("collect devices columns")?;
        if !cols.iter().any(|c| c == "approved") {
            conn.execute_batch(
                "ALTER TABLE devices ADD COLUMN approved INTEGER NOT NULL DEFAULT 0",
            )
            .context("migrate devices.approved")?;
        }
        Ok(())
    }

    /// Acquire the underlying connection (single-statement transactional use).
    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }
}
