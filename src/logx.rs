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
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub ts_unix: u64,
    pub category: &'static str,
    pub level: &'static str,
    pub message: String,
}

const MGMT_CAP: usize = 2048;

static MGMT: Mutex<VecDeque<MgmtEvent>> = Mutex::new(VecDeque::new());

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
    }
}
