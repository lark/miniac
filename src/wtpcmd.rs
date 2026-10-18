//! Management-plane WTP commands delivered into a live CAPWAP session.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! The web/API layer queues a Reset Request (mtype 17), a Clear Configuration
//! Request (mtype 23) or a Release Client by AC Request (mtype 139) for one WTP
//! identified by MAC; the session owning that WTP sends the message and matches
//! the WTP's response. Mirrors `config::ConfigUpdateRegistry` and
//! `firmware::UpgradeRegistry`.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;

use crate::device::Mac;

/// One command for a live WTP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WtpCmd {
    /// Restart the WTP on its current image (Reset Request, mtype 17).
    Reset,
    /// Restore factory defaults and restart: a Clear Configuration Request
    /// (mtype 23) first, then a Reset Request once the WTP acknowledges.
    Disable,
    /// Evict one station by MAC (Release Client by AC Request, mtype 139).
    ReleaseClient(Mac),
}

/// Registry mapping a WTP MAC to the channel its live session listens on.
pub struct WtpCmdRegistry {
    inner: Mutex<HashMap<Mac, Sender<WtpCmd>>>,
}

impl WtpCmdRegistry {
    pub fn new() -> Self {
        WtpCmdRegistry {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Associate a WTP MAC with the channel its session listens on.
    pub fn register(&self, mac: Mac, tx: Sender<WtpCmd>) {
        self.inner.lock().unwrap().insert(mac, tx);
    }

    /// Whether a live session for this WTP is currently registered.
    #[allow(dead_code)]
    pub fn is_active(&self, mac: Mac) -> bool {
        self.inner.lock().unwrap().contains_key(&mac)
    }

    /// Deliver a command to the WTP's session. Returns false when the session is
    /// absent or its channel closed (e.g. the WTP just went offline).
    pub fn trigger(&self, mac: Mac, cmd: WtpCmd) -> bool {
        match self.inner.lock().unwrap().get(&mac).cloned() {
            Some(tx) => tx.try_send(cmd).is_ok(),
            None => false,
        }
    }
}

impl Default for WtpCmdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn trigger_requires_live_session() {
        let mac = [1, 2, 3, 4, 5, 6];
        let reg = WtpCmdRegistry::new();
        assert!(!reg.trigger(mac, WtpCmd::Reset)); // no live session

        let (tx, mut rx) = mpsc::channel(1);
        reg.register(mac, tx);
        assert!(reg.is_active(mac));
        assert!(reg.trigger(mac, WtpCmd::ReleaseClient([9, 8, 7, 6, 5, 4])));
        match rx.blocking_recv() {
            Some(cmd) => assert_eq!(cmd, WtpCmd::ReleaseClient([9, 8, 7, 6, 5, 4])),
            None => panic!("command not delivered"),
        }
    }
}
