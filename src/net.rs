//! UDP helpers: socket options, ancillary PKTINFO reception, address lookup.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! A CAPWAP AC may listen on the wildcard address while the machine has many
//! interfaces, and a WTP may discover it by broadcast. The address the AC
//! should advertise is therefore the packet's destination (unicast) or the
//! ingress interface's own address (broadcast/multicast), which the kernel
//! reports through `IP_PKTINFO` / `IPV6_PKTINFO`.

use std::{
    ffi::CStr,
    io,
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::AsRawFd,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::Interest, net::UdpSocket};

/// Address metadata of one received datagram.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecvInfo {
    /// Header destination: a local unicast address, a broadcast address, or a
    /// multicast group.
    pub dst: Option<IpAddr>,
    /// Local address the kernel used (IPv4 `ipi_spec_dst`; for IPv6 unicast the
    /// destination itself). This is the address to advertise when it differs
    /// from `dst`, i.e. on broadcast.
    pub local: Option<IpAddr>,
    /// Ingress interface index.
    pub ifindex: u32,
}

/// Create a UDP socket with the options miniac needs before binding:
/// `IPV6_V6ONLY` (so v4/v6 wildcard binds coexist), `SO_REUSEADDR` when a
/// device is pinned (so several instances can share the port on their own
/// interfaces), `SO_BINDTODEVICE`, and PKTINFO reception.
pub fn bind_udp(addr: SocketAddr, iface: Option<&str>) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Without V6ONLY the v6 wildcard bind would also claim the v4 port.
        sock.set_only_v6(true)?;
    }
    if iface.is_some() {
        sock.set_reuse_address(true)?;
    }
    set_pktinfo(&sock, addr.is_ipv6())?;
    if let Some(name) = iface {
        sock.bind_device(Some(name.as_bytes()))
            .map_err(|e| match e.kind() {
                io::ErrorKind::PermissionDenied => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("binding to interface {name} requires root or CAP_NET_RAW: {e}"),
                ),
                _ => e,
            })?;
    }
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

fn set_pktinfo(sock: &Socket, ipv6: bool) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let one: libc::c_int = 1;
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &one as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one datagram together with its destination / ingress metadata.
pub async fn recv_from(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, RecvInfo)> {
    sock.async_io(Interest::READABLE, || recv_msg(sock, buf))
        .await
}

fn recv_msg(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, RecvInfo)> {
    let fd = sock.as_raw_fd();
    let mut src: libc::sockaddr_storage = unsafe { zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut control = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = &mut src as *mut libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut info = RecvInfo::default();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            match ((*cmsg).cmsg_level, (*cmsg).cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    let pi = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                    let dst = Ipv4Addr::from(u32::from_be((*pi).ipi_addr.s_addr));
                    if !dst.is_unspecified() {
                        info.dst = Some(IpAddr::V4(dst));
                    }
                    let local = Ipv4Addr::from(u32::from_be((*pi).ipi_spec_dst.s_addr));
                    if !local.is_unspecified() {
                        info.local = Some(IpAddr::V4(local));
                    }
                    info.ifindex = (*pi).ipi_ifindex as u32;
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    let pi = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                    let dst = Ipv6Addr::from((*pi).ipi6_addr.s6_addr);
                    if !dst.is_unspecified() {
                        info.dst = Some(IpAddr::V6(dst));
                        // For a unicast v6 packet the destination is the local
                        // address; a multicast destination is a group.
                        if !dst.is_multicast() {
                            info.local = Some(IpAddr::V6(dst));
                        }
                    }
                    info.ifindex = (*pi).ipi6_ifindex as u32;
                }
                _ => {}
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let peer = sockaddr_to_std(&src)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unexpected peer address"))?;
    Ok((n as usize, peer, info))
}

fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                u32::from_be(sin6.sin6_flowinfo),
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// All addresses of the interface with `ifindex` (empty on failure).
pub fn iface_ip_addrs(ifindex: u32) -> Vec<IpAddr> {
    let Some(name) = iface_name(ifindex) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut cur = list;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && CStr::from_ptr(ifa.ifa_name).to_bytes() == name.as_bytes()
            {
                if !ifa.ifa_addr.is_null() {
                    match (*ifa.ifa_addr).sa_family as libc::c_int {
                        libc::AF_INET => {
                            let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                        }
                        libc::AF_INET6 => {
                            let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                            out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                        }
                        _ => {}
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(list);
    }
    out
}

fn iface_name(ifindex: u32) -> Option<String> {
    if ifindex == 0 {
        return None;
    }
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    Some(name)
}

/// Whether `dst` is a definite unicast destination (not wildcard / broadcast /
/// multicast groups).
pub fn unicast_dst(dst: Option<IpAddr>, local: Option<IpAddr>) -> Option<Ipv4Addr> {
    match (dst, local) {
        (Some(IpAddr::V4(d)), Some(IpAddr::V4(l))) if d == l => {
            is_unicast_v4(d).then_some(d)
        }
        (Some(IpAddr::V4(d)), None) => is_unicast_v4(d).then_some(d),
        _ => None,
    }
}

fn is_unicast_v4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()
}

/// IPv4 addresses to advertise as the AC address list.
///
/// A unicast request yields exactly its destination address (the one the WTP
/// already reached). A broadcast/multicast request yields the ingress
/// interface's addresses, since there is no single destination address to
/// echo. `bound` is the socket's own address, used only as a last resort when
/// the interface cannot be resolved.
pub fn ac_ipv4_list(info: &RecvInfo, bound: Option<SocketAddr>) -> Vec<Ipv4Addr> {
    if let Some(dst) = unicast_dst(info.dst, info.local) {
        return vec![dst];
    }
    let mut out: Vec<Ipv4Addr> = iface_ip_addrs(info.ifindex)
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v) => Some(v),
            IpAddr::V6(_) => None,
        })
        .collect();
    if out.is_empty() {
        if let Some(IpAddr::V4(local)) = info.local {
            if !local.is_unspecified() {
                out.push(local);
            }
        }
    }
    if out.is_empty() {
        if let Some(SocketAddr::V4(a)) = bound {
            if !a.ip().is_unspecified() {
                out.push(*a.ip());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Pick the AC address from `candidates`, preferring one inside `net`.
pub fn select_ipv4(candidates: &[Ipv4Addr], net: Option<(Ipv4Addr, u8)>) -> Option<Ipv4Addr> {
    if let Some((base, prefix)) = net {
        if let Some(ip) = candidates
            .iter()
            .find(|ip| crate::settings::v4_in_net(**ip, base, prefix))
        {
            return Some(*ip);
        }
    }
    candidates.first().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicast_detection_uses_destination_and_ignores_broadcast() {
        let local = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 254)));
        let dst = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 254)));
        assert_eq!(
            unicast_dst(dst, local),
            Some(Ipv4Addr::new(192, 168, 0, 254))
        );
        // Broadcast: destination differs from the local address.
        let bcast = Some(IpAddr::V4(Ipv4Addr::BROADCAST));
        assert_eq!(unicast_dst(bcast, local), None);
        // Limited broadcast with no local information is still broadcast.
        assert_eq!(unicast_dst(bcast, None), None);
        // Multicast is not a unicast destination.
        let mcast = Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)));
        assert_eq!(unicast_dst(mcast, None), None);
    }

    #[test]
    fn select_prefers_net_address() {
        let candidates = [
            Ipv4Addr::new(203, 0, 113, 5),
            Ipv4Addr::new(192, 168, 0, 254),
        ];
        assert_eq!(
            select_ipv4(&candidates, Some((Ipv4Addr::new(192, 168, 0, 0), 24))),
            Some(Ipv4Addr::new(192, 168, 0, 254))
        );
        assert_eq!(
            select_ipv4(&candidates, Some((Ipv4Addr::new(10, 0, 0, 0), 8))),
            Some(Ipv4Addr::new(203, 0, 113, 5))
        );
        assert_eq!(select_ipv4(&[], None), None);
    }

    #[test]
    fn ac_list_falls_back_to_bound_address() {
        let info = RecvInfo {
            dst: Some(IpAddr::V4(Ipv4Addr::BROADCAST)),
            local: None,
            ifindex: 0,
        };
        assert_eq!(
            ac_ipv4_list(&info, Some("192.168.0.2:5246".parse().unwrap())),
            vec![Ipv4Addr::new(192, 168, 0, 2)]
        );
    }
}
