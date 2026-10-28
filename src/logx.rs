//! Logging layering infrastructure.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Distinguishes two log streams:
//! - Run/debug logs: for development and troubleshooting, via `tracing`
//!   (target `run`), written to console/log files.
//! - Management logs: auditable operational events (AP join/leave, radio /
//!   config changes, firmware upgrade, client events, etc.). They are both
//!   emitted via `tracing` (target `mgmt`) and appended to a bounded
//!   in-memory ring buffer for the management UI / persistence to consume.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Host-local wall-clock timestamp with microsecond precision and its UTC
/// offset, e.g. `2026-10-28T02:29:03.123456+08:00`.
///
/// Log lines and `-D` dumps both use it so the stamps match the clock of the
/// host running miniac instead of UTC. `localtime_r` is re-entrant and picks up
/// the host's current zone (and DST) on every call.
pub fn local_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as libc::time_t;
    let micros = now.subsec_micros();
    // SAFETY: `localtime_r` fills the caller-provided `tm` and returns it (or
    // null on failure); it does not touch shared state.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::localtime_r(&secs, &mut tm) };
    if ok.is_null() {
        // No usable local zone: fall back to UTC rather than drop the stamp.
        return format!("{secs}.{micros:06}+00:00");
    }
    let offset = tm.tm_gmtoff;
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}{}{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        micros,
        sign,
        abs / 3600,
        (abs % 3600) / 60,
    )
}

/// `tracing` timer that stamps every event with [`local_timestamp`], so log
/// files carry the host's local time instead of the default UTC clock.
pub struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(
        &self,
        w: &mut tracing_subscriber::fmt::format::Writer<'_>,
    ) -> std::fmt::Result {
        write!(w, "{}", local_timestamp())
    }
}

/// Management log event category (mirrors business modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // most variants are used as higher milestones land
pub enum Category {
    System,   // system self / startup / config load
    Device,   // WTP join, leave, status
    Radio,    // radio / RF
    Station,  // clients / stations
    Security, // 802.1X / authentication / encryption
    Firmware, // firmware upgrade
    Roaming,  // roaming events
    Admin,    // management-plane operations (web/CLI)
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Category::System => "system",
            Category::Device => "device",
            Category::Radio => "radio",
            Category::Station => "station",
            Category::Security => "security",
            Category::Firmware => "firmware",
            Category::Roaming => "roaming",
            Category::Admin => "admin",
        }
    }
}

/// A single management log event.
#[derive(Debug, Clone)]
pub struct MgmtEvent {
    /// Monotonic sequence number, assigned on record; lets the UI fetch
    /// incremental slices via `?since=`.
    pub seq: u64,
    pub ts_unix: u64,
    pub category: &'static str,
    pub level: &'static str,
    pub message: String,
}

const MGMT_CAP: usize = 2048;

static MGMT: Mutex<VecDeque<MgmtEvent>> = Mutex::new(VecDeque::new());
static MGMT_SEQ: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Record a management log: append to ring buffer and emit via `tracing` (target `mgmt`).
pub fn record(category: Category, level: tracing::Level, message: impl AsRef<str>) {
    let msg = message.as_ref().to_string();
    let cat = category.as_str();

    match level {
        tracing::Level::TRACE => tracing::trace!(target: "mgmt", category = cat, "{}", msg),
        tracing::Level::DEBUG => tracing::debug!(target: "mgmt", category = cat, "{}", msg),
        tracing::Level::INFO => tracing::info!(target: "mgmt", category = cat, "{}", msg),
        tracing::Level::WARN => tracing::warn!(target: "mgmt", category = cat, "{}", msg),
        tracing::Level::ERROR => tracing::error!(target: "mgmt", category = cat, "{}", msg),
    }

    let event = MgmtEvent {
        seq: MGMT_SEQ.fetch_add(1, Ordering::Relaxed) + 1,
        ts_unix: now_unix(),
        category: cat,
        level: level.as_str(),
        message: msg,
    };
    let mut guard = MGMT.lock().unwrap();
    guard.push_back(event);
    while guard.len() > MGMT_CAP {
        guard.pop_front();
    }
}

/// Non-destructive incremental read: events with `seq > since`, oldest first.
/// The ring buffer is left intact so repeated polls do not lose entries.
pub fn snapshot(since: u64) -> Vec<MgmtEvent> {
    let guard = MGMT.lock().unwrap();
    guard.iter().filter(|e| e.seq > since).cloned().collect()
}

/// Consume the buffered events for the web/callback layer (drain to bound growth).
pub fn drain() -> Vec<MgmtEvent> {
    let mut guard = MGMT.lock().unwrap();
    guard.drain(..).collect()
}

/// Number of currently buffered management logs.
pub fn len() -> usize {
    MGMT.lock().unwrap().len()
}

/// Convenience wrappers: info-level management logs per category.
pub fn device(msg: impl AsRef<str>) {
    record(Category::Device, tracing::Level::INFO, msg);
}
pub fn radio(msg: impl AsRef<str>) {
    record(Category::Radio, tracing::Level::INFO, msg);
}
pub fn station(msg: impl AsRef<str>) {
    record(Category::Station, tracing::Level::INFO, msg);
}
pub fn security(msg: impl AsRef<str>) {
    record(Category::Security, tracing::Level::INFO, msg);
}
pub fn firmware(msg: impl AsRef<str>) {
    record(Category::Firmware, tracing::Level::INFO, msg);
}
pub fn system(msg: impl AsRef<str>) {
    record(Category::System, tracing::Level::INFO, msg);
}
pub fn admin(msg: impl AsRef<str>) {
    record(Category::Admin, tracing::Level::INFO, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stamp is ISO 8601 with microseconds and an explicit UTC offset.
    #[test]
    fn local_timestamp_shape() {
        let ts = local_timestamp();
        assert_eq!(ts.len(), 32, "{ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
        let offset = &ts[26..];
        assert!(offset.starts_with('+') || offset.starts_with('-'), "{ts}");
        assert_eq!(&offset[3..4], ":");
    }

    // The shared static MGMT is affected by parallel tests; keep assertions in one test.
    #[test]
    fn ring_buffer_bounded_and_drained() {
        const MARKER: &str = "unique-marker-event";

        // 1) Ring buffer is bounded.
        for i in 0..MGMT_CAP + 100 {
            record(
                Category::System,
                tracing::Level::INFO,
                format!("event {}", i),
            );
        }
        assert!(len() <= MGMT_CAP);

        // 2) After drain the buffer is cleared.
        drain();
        assert_eq!(len(), 0);

        // 3) Drain returns the just-recorded event.
        record(Category::Device, tracing::Level::INFO, MARKER);
        let drained = drain();
        assert!(drained.iter().any(|e| e.message == MARKER));
        assert_eq!(len(), 0);

        // 4) snapshot(since) is incremental and non-destructive.
        let base = MGMT_SEQ.load(Ordering::Relaxed);
        record(Category::System, tracing::Level::INFO, "snap-1");
        record(Category::System, tracing::Level::INFO, "snap-2");
        let all = snapshot(base);
        assert_eq!(all.len(), 2);
        assert_eq!(snapshot(base).len(), 2, "snapshot must not consume");
        let tail = snapshot(base + 1);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].message, "snap-2");
    }
}
