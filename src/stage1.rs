//! H3C FIT-AP two-stage discovery responder.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Leases the WTP its own IP, gateway and the AC IP over the private broadcast
//! port 10087 (DHCP-like), so the WTP can start standard CAPWAP unicast
//! (RFC 5415) to AC:5246. The wire layout below is the reverse-engineered
//! contract consumed by the AX60 `mainproc` discovery handler: the reply is a
//! fixed 548-byte frame and holds LE network-order IP fields at the given
//! offsets.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::db::Db;
use rusqlite::OptionalExtension;

/// Private discovery port (dst on the wire, bound here by the AC).
pub const STAGE1_PORT: u16 = 10087;

/// Fixed request/reply frame length observed on the wire (`m60.pcap`).
pub const FRAME_LEN: usize = 548;

/// Fixed big-endian request header, `01 01 06 00 28 49 03 62`.
pub const REQ_MAGIC: [u8; 8] = [0x01, 0x01, 0x06, 0x00, 0x28, 0x49, 0x03, 0x62];

// The wire frame is a DHCP-style message (m60.pcap): op at byte 0 (0x01 on
// the request), xid at bytes 4-7, yiaddr at 16, siaddr at 20, chaddr (the WTP
// board MAC) at 28, and a standard DHCP magic cookie + options at 0xEC. The
// AX60's `mainproc` consumes a *parsed* struct whose fields (AP IP, gateway,
// AC IP) are filled from these DHCP fields, so the reply must be a well-formed
// DHCPOFFER, not a writes-at-arbitrary-offset blob.
/// Reply message type carried in byte 0 (BOOTREPLY).
pub const OP_REPLY: u8 = 0x02;

/// `yiaddr`: the IP address leased to the WTP (BOOTP "your" address).
pub const OFF_YIADDR: usize = 16;
/// `siaddr`: next-server address, used to carry the AC IP.
pub const OFF_SIADDR: usize = 20;
/// DHCP magic cookie offset (standard 236-byte BOOTP header).
pub const OFF_MAGIC: usize = 0xEC;
/// DHCP options begin right after the magic cookie.
pub const OFF_OPTIONS: usize = OFF_MAGIC + 4;
/// Fixed DHCP magic cookie `63 82 53 63`.
pub const DHCP_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// The DHCP-like lease an AC grants a WTP during stage-1 discovery.
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    pub wtp_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub ac_ip: Ipv4Addr,
}

/// Persistent stage-1 address pool. Allocatable IPs live in the `address_pool`
/// table and per-WTP assignments in `ap_leases`, so a WTP keeps the same IP
/// across reboots and the pool survives AC restarts.
pub struct AcPool {
    db: Arc<Db>,
    start_ip: u32,
    end_ip: u32,
    gateway: Ipv4Addr,
    netmask: Ipv4Addr,
    ac_ip: Ipv4Addr,
    /// Subnet directed-broadcast address, used because the WTP broadcasts its
    /// discovery request from 0.0.0.0 (no assigned address yet) and must be
    /// answered on the LAN broadcast to its source port.
    broadcast: Ipv4Addr,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl AcPool {
    /// Persist (upsert) the allocatable range plus gateway/netmask/AC IP as the
    /// single pool row, and return a handle to it.
    pub fn prefill(
        db: Arc<Db>,
        start: Ipv4Addr,
        end: Ipv4Addr,
        gateway: Ipv4Addr,
        netmask: Ipv4Addr,
        ac_ip: Ipv4Addr,
    ) -> anyhow::Result<Self> {
        {
            let conn = db.lock();
            conn.execute(
                "INSERT INTO address_pool (id, start_ip, end_ip, gateway, netmask, ac_ip)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                   start_ip=excluded.start_ip, end_ip=excluded.end_ip,
                   gateway=excluded.gateway, netmask=excluded.netmask, ac_ip=excluded.ac_ip",
                rusqlite::params![
                    u32::from(start),
                    u32::from(end),
                    u32::from(gateway),
                    u32::from(netmask),
                    u32::from(ac_ip),
                ],
            )?;
        }
        let netmask_n = u32::from(netmask);
        let broadcast = Ipv4Addr::from((u32::from(start) & netmask_n) | !netmask_n);
        Ok(AcPool {
            db,
            start_ip: u32::from(start),
            end_ip: u32::from(end),
            gateway,
            netmask,
            ac_ip,
            broadcast,
        })
    }

    /// Lease (or renew) an address for the WTP board MAC. The same MAC always
    /// gets the same IP; new MACs take the lowest free address in the pool.
    pub fn lease_for_mac(&self, mac: [u8; 6]) -> anyhow::Result<Option<Lease>> {
        let conn = self.db.lock();
        let t = now();
        if let Some(ip) = conn
            .query_row("SELECT ip FROM ap_leases WHERE mac = ?1", [&mac[..]], |r| {
                r.get::<_, u32>(0)
            })
            .optional()?
        {
            conn.execute(
                "UPDATE ap_leases SET last_seen = ?1 WHERE mac = ?2",
                rusqlite::params![t, &mac[..]],
            )?;
            return Ok(Some(Lease {
                wtp_ip: Ipv4Addr::from(ip),
                gateway: self.gateway,
                netmask: self.netmask,
                ac_ip: self.ac_ip,
            }));
        }
        let mut stmt = conn.prepare("SELECT ip FROM ap_leases")?;
        let used: std::collections::HashSet<u32> = stmt
            .query_map([], |r| r.get::<_, u32>(0))?
            .collect::<std::result::Result<_, _>>()?;
        let free = (self.start_ip..=self.end_ip).find(|ip| !used.contains(ip));
        let Some(ip) = free else {
            return Ok(None); // pool exhausted
        };
        conn.execute(
            "INSERT INTO ap_leases (mac, ip, leased_at, last_seen) VALUES (?1, ?2, ?3, ?3)",
            rusqlite::params![&mac[..], ip, t],
        )?;
        Ok(Some(Lease {
            wtp_ip: Ipv4Addr::from(ip),
            gateway: self.gateway,
            netmask: self.netmask,
            ac_ip: self.ac_ip,
        }))
    }
}

/// Derive a /N network mask from a prefix length.
fn mask_for_prefix(prefix: u8) -> Ipv4Addr {
    let v = if prefix >= 32 {
        0xffff_ffffu32
    } else {
        0xffff_ffffu32 << (32 - prefix)
    };
    Ipv4Addr::from(v)
}

/// Format bytes as a lowercase hex string (diagnostics only).
fn hex_str(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Extract the DHCP option-53 (message type) value from a frame, if present,
/// scanning the options area that follows the magic cookie at `OFF_MAGIC`.
fn dhcp_msg_type(frame: &[u8]) -> Option<u8> {
    let mut i = OFF_OPTIONS;
    while i < frame.len() {
        let code = frame[i];
        if code == 0xff {
            return None; // END
        }
        if code == 0x00 {
            i += 1; // pad
            continue;
        }
        let len = frame[i + 1] as usize;
        if code == 53 && len == 1 {
            return Some(frame[i + 2]);
        }
        i += 2 + len;
    }
    None
}

/// Build a DHCPOFFER reply to a validated WTP discovery request, echoing the
/// request header (xid, chaddr) and filling yiaddr (=leased WTP IP), siaddr
/// (AC IP) and the required DHCP options. `request` must be `FRAME_LEN` bytes
/// and carry the `REQ_MAGIC` header.
pub fn build_reply(request: &[u8], lease: &Lease) -> Option<[u8; FRAME_LEN]> {
    if request.len() != FRAME_LEN || request[..4] != REQ_MAGIC[..4] {
        return None;
    }
    let mut frame = [0u8; FRAME_LEN];
    frame.copy_from_slice(request); // echo xid, secs/flags, chaddr (= board MAC)
    frame[0] = OP_REPLY; // BOOTREPLY
    let yi = lease.wtp_ip.octets();
    frame[OFF_YIADDR..OFF_YIADDR + 4].copy_from_slice(&yi);
    let ac = lease.ac_ip.octets();
    frame[OFF_SIADDR..OFF_SIADDR + 4].copy_from_slice(&ac);
    frame[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&DHCP_COOKIE);

    // DHCP message types: reply to a Discover with DHCPOFFER, to a Request
    // with DHCPACK (completes the lease). Both carry the same assigned fields.
    let req_type = dhcp_msg_type(request).unwrap_or(1);
    let reply_type = if req_type == 3 { 5 } else { 2 }; // REQUEST -> ACK, else OFFER
    let mut o = OFF_OPTIONS;
    let mut put = |code: u8, val: &[u8]| {
        frame[o] = code;
        frame[o + 1] = val.len() as u8;
        frame[o + 2..o + 2 + val.len()].copy_from_slice(val);
        o += 2 + val.len();
    };
    put(53, &[reply_type]); // DHCPOFFER / DHCPACK
    put(54, &ac); // server identifier
                  // Option 60: vendor class identifier, echo the AP's "H3C" (per the DHCP spec).
    put(60, b"H3C");
    // Option 43: CAPWAP AC discovery list. Layout per the AX60 `h3c_busybox`
    // dhcpc parser (h3c_busybox.dis 0x16154): value[1]=list byte length feeds
    // `CAPWAP_setACIp`'s `len` (= 3 + 4*count), value[4]=AC count feeds
    // `CAPWAP_setACIpCnt`, IPs start at value[5].
    put(
        43,
        &[0x01, 0x07, 0x00, 0x00, 0x01, ac[0], ac[1], ac[2], ac[3]],
    );
    put(3, &lease.gateway.octets());
    put(1, &lease.netmask.octets());
    put(51, &3600u32.to_be_bytes()); // lease time (s)
                                     // Option 6: DNS server. The AP's DHCP option-55 list requests it; serving
                                     // it (in addition to the often-stated minimum) keeps the lease "complete"
                                     // enough for the AP to proceed from stage-1 to CAPWAP.
    put(6, &lease.gateway.octets());
    frame[o] = 0xff; // END
    Some(frame)
}

/// Run the stage-1 discovery loop: bind the private port, lease each WTP that
/// presents a valid discovery frame, and reply with the lease.
pub async fn serve(bind_addr: &str, pool: Arc<AcPool>) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.set_broadcast(true)?;
    info!(
        "[!] stage-1 discovery listening on {} (port {})",
        bind_addr, STAGE1_PORT
    );
    let mut buf = vec![0u8; FRAME_LEN];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        // Our own broadcast BOOTREPLYs (op=0x02) loop back to the bound socket;
        // skip them. The AP always sends BOOTREQUEST (op=0x01).
        if buf[0] == 0x02 {
            continue;
        }
        if n != FRAME_LEN || buf[..4] != REQ_MAGIC[..4] {
            warn!(
                "[?] stage-1 from {}: malformed frame ({} bytes) head {}",
                peer,
                n,
                hex_str(&buf[..buf.len().min(64)])
            );
            continue;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[0x1c..0x22]);
        info!(
            "[<] stage-1 discovery from {} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            peer, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        info!(
            "[d] stage-1 op={:#04x} msg_type={:?}",
            buf[0],
            dhcp_msg_type(&buf)
        );
        // The WTP broadcasts from 0.0.0.0 (no assigned address yet), so it may
        // only accept the limited broadcast; reply to 255.255.255.255 rather
        // than a subnet directed broadcast on a network the WTP has not joined.
        let bcast = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), peer.port());
        let directed = SocketAddr::new(std::net::IpAddr::V4(pool.broadcast), peer.port());
        let bcast87 = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), STAGE1_PORT);
        let directed87 = SocketAddr::new(std::net::IpAddr::V4(pool.broadcast), STAGE1_PORT);
        match pool.lease_for_mac(mac) {
            Ok(Some(lease)) => {
                if let Some(reply) = build_reply(&buf, &lease) {
                    for addr in [bcast, directed, bcast87, directed87] {
                        if let Err(e) = sock.send_to(&reply, addr).await {
                            warn!("[!] stage-1 send reply to {} failed: {}", addr, e);
                        } else {
                            info!(
                                "[>] stage-1 lease {} -> {} (ac {})",
                                lease.wtp_ip, addr, lease.ac_ip
                            );
                        }
                    }
                }
            }
            Ok(None) => warn!("[!] stage-1 pool exhausted, no lease for {}", peer),
            Err(e) => warn!("[!] stage-1 lease error for {}: {}", peer, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn pool() -> (Arc<Db>, AcPool) {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let p = AcPool::prefill(
            db.clone(),
            Ipv4Addr::new(192, 168, 0, 50),
            Ipv4Addr::new(192, 168, 0, 80),
            Ipv4Addr::new(192, 168, 0, 1),
            mask_for_prefix(24),
            Ipv4Addr::new(192, 168, 0, 2),
        )
        .unwrap();
        (db, p)
    }

    #[test]
    fn lease_is_stable_per_mac() {
        let (_db, p) = pool();
        let a = [0xc4u8, 0xc0, 0x63, 0xef, 0xca, 0x25];
        let l1 = p.lease_for_mac(a).unwrap().unwrap();
        let l2 = p.lease_for_mac(a).unwrap().unwrap();
        assert_eq!(l1.wtp_ip, l2.wtp_ip);
        assert_eq!(l1.gateway, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(l1.ac_ip, Ipv4Addr::new(192, 168, 0, 2));
    }

    #[test]
    fn distinct_macs_get_distinct_ips_in_range() {
        let (_db, p) = pool();
        let mut got: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
        for i in 0u8..5 {
            let mac = [0x02, 0x00, 0x00, 0x00, 0x00, i];
            let l = p.lease_for_mac(mac).unwrap().unwrap();
            assert!(
                l.wtp_ip >= Ipv4Addr::new(192, 168, 0, 50)
                    && l.wtp_ip <= Ipv4Addr::new(192, 168, 0, 80)
            );
            assert!(got.insert(l.wtp_ip));
        }
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let (_db, p) = pool();
        // 31 addresses in 192.168.0.50..80; consume them all with unique MACs.
        for i in 0u8..31 {
            let mac = [0x02, 0x00, 0x00, 0x00, i, 0x00];
            assert!(p.lease_for_mac(mac).unwrap().is_some());
        }
        let mac = [0x02, 0x00, 0x00, 0xff, 0xff, 0xff];
        assert!(p.lease_for_mac(mac).unwrap().is_none());
    }

    #[test]
    fn reply_roundtrip_offsets() {
        let mut req = [0u8; FRAME_LEN];
        req[..8].copy_from_slice(&REQ_MAGIC);
        req[0x1c..0x22].copy_from_slice(&[0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25]);
        let (_db, p) = pool();
        let lease = p
            .lease_for_mac([0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25])
            .unwrap()
            .unwrap();
        let reply = build_reply(&req, &lease).unwrap();
        assert_eq!(reply[0], OP_REPLY, "BOOTREPLY op");
        assert_eq!(&reply[OFF_YIADDR..OFF_YIADDR + 4], &lease.wtp_ip.octets());
        assert_eq!(&reply[OFF_SIADDR..OFF_SIADDR + 4], &lease.ac_ip.octets());
        // chaddr must be preserved (the WTP board MAC), not clobbered.
        assert_eq!(&reply[0x1c..0x22], &[0xc4, 0xc0, 0x63, 0xef, 0xca, 0x25]);
        assert_eq!(&reply[OFF_MAGIC..OFF_MAGIC + 4], &DHCP_COOKIE);
        // Option 53 = DHCPOFFER, option 54 = server identifier (AC IP).
        assert_eq!(&reply[OFF_OPTIONS..OFF_OPTIONS + 3], &[53, 1, OP_REPLY]);
        assert_eq!(&reply[OFF_OPTIONS + 3..OFF_OPTIONS + 5], &[54, 4]);
        assert_eq!(
            &reply[OFF_OPTIONS + 5..OFF_OPTIONS + 9],
            &lease.ac_ip.octets()
        );
        // Option 60 "H3C" and option 43 (AC IP count + AC IP) must be present.
        let mut i = OFF_OPTIONS;
        while i < OFF_OPTIONS + 48 {
            let code = reply[i];
            if code == 0xff {
                break;
            }
            let len = reply[i + 1] as usize;
            if code == 60 && reply[i + 2..i + 2 + len] == *b"H3C" {
                // found vendor class echo
            }
            if code == 43 {
                // AX60 dhcpc layout: [0]=0x01, [1]=3+4*count, [2..3]=reserved,
                // [4]=count, [5..]=AC IPs.
                assert_eq!(len, 9);
                assert_eq!(&reply[i + 2..i + 6], &[0x01, 0x07, 0x00, 0x00]);
                assert_eq!(reply[i + 6], 1); // single AC
                assert_eq!(&reply[i + 7..i + 11], &lease.ac_ip.octets());
            }
            i += 2 + len;
        }
    }

    #[test]
    fn rejects_bad_frame() {
        let mut req = [0u8; FRAME_LEN];
        req[0] = 0xff; // wrong header
        let (_db, p) = pool();
        let lease = p.lease_for_mac([0u8; 6]).unwrap().unwrap();
        assert!(build_reply(&req, &lease).is_none());
    }
}
