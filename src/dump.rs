//! Plaintext control-message dump for offline replay analysis (`-D <file>`).
//!
//! Copyright (c) 2026  Wang Jian
//!
//! One global append-only file opened at startup. `write` appends a single
//! `RX|TX <ts> <hex>` line where the hex is the full plaintext wire frame
//! (8-byte base header included). RX marks WTP->AC traffic (what a replay tool
//! would re-send), TX marks AC->WTP replies (the reference responses). `<ts>` is
//! the host's local wall-clock time in ISO 8601 with microseconds and the UTC
//! offset (`2026-10-28T02:29:03.123456+08:00`), so dump lines match the host
//! clock instead of UTC.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

static DUMP: Mutex<Option<File>> = Mutex::new(None);

/// Open the dump file in append mode, replacing any previous handle.
pub fn open(path: &str) -> std::io::Result<()> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    *DUMP.lock().unwrap() = Some(file);
    Ok(())
}

/// Append one `RX|TX <ts> <hex>` line for `io` / `payload`.
pub fn write(io: &str, payload: &[u8]) {
    let mut guard = DUMP.lock().unwrap();
    if let Some(file) = guard.as_mut() {
        let ts = crate::logx::local_timestamp();
        let mut hex = String::with_capacity(payload.len() * 2);
        for b in payload {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        let _ = writeln!(file, "{} {} {}", io, ts, hex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A global file that is not open must not panic (dump disabled).
    #[test]
    fn disabled_write_is_noop() {
        write("RX", &[0x00, 0x10, 0x02, 0x00]);
    }
}
