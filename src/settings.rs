//! Startup settings: CLI flags, an optional INI file, and the merged policy.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! Precedence is CLI flag, then INI value, then built-in default. The defaults
//! are deliberately conservative: CAPWAP only answers peers from private /
//! loopback networks, and the web UI listens on loopback only.
//!
//! CLI:
//!   -a <cidr[,..]>   CAPWAP peer allow list (repeatable; replaces the default)
//!   -b <ip[,..]>     CAPWAP unicast bind address (repeatable; disables broadcast
//!                    discovery because a unicast bind receives no broadcast)
//!   -i <iface>       bind CAPWAP and stage-1 sockets to one interface
//!   -w [addr:]port   HTTP web UI (default 127.0.0.1:8246)
//!   -W [addr:]port   HTTPS web UI (default 127.0.0.1:8443 when enabled)
//!   -c <file>        INI file (default ./miniac.ini when present)
//!   -D <file>        plaintext CAPWAP control dump
//!
//! INI:
//!   [capwap] allow, bind, iface
//!   [stage1] enabled, net, pool_start, pool_end, gateway
//!   [web]    http_addr, http_port, https_addr, https_port, https_cert, https_key
//!   [h3c]    ofdma, mumimo, band_navigation

use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use tracing::info;

use crate::net::RecvInfo;

/// CAPWAP control port (RFC 5415): fixed, only the bind address is configurable.
pub const CTRL_PORT: u16 = 5246;
pub const HTTP_DEFAULT_PORT: u16 = 8246;
pub const HTTPS_DEFAULT_PORT: u16 = 8443;
pub const DEFAULT_INI: &str = "miniac.ini";

/// One CIDR block used by the CAPWAP source allow list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d[/n]` or `v6[/n]`; a bare address means a host route.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let addr: IpAddr = a
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid address {a:?} in CIDR {s:?}"))?;
                let prefix: u8 = p
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid prefix {p:?} in CIDR {s:?}"))?;
                (addr, Some(prefix))
            }
            None => (
                s.parse()
                    .with_context(|| format!("invalid address in CIDR {s:?}"))?,
                None,
            ),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            bail!("prefix /{prefix} too large for {addr} in CIDR {s:?}");
        }
        Ok(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => v4_in_net(ip, net, self.prefix),
            // A v4-mapped v6 peer (dual-stack sockets) is matched as its IPv4
            // address when the block itself is IPv4.
            (IpAddr::V4(net), IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(ip) => v4_in_net(ip, net, self.prefix),
                None => false,
            },
            (IpAddr::V6(net), IpAddr::V6(ip)) => v6_in_net(ip, net, self.prefix),
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// True when IPv4 `ip` lies inside `net/prefix`.
pub fn v4_in_net(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn v6_in_net(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix.min(128))
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

/// Default CAPWAP peer allow list: IPv4 private / loopback and IPv6 ULA /
/// link-local / loopback. Anything else is dropped without a reply.
pub fn default_allow() -> Vec<Cidr> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    ]
    .iter()
    .map(|s| Cidr::parse(s).expect("built-in CIDR"))
    .collect()
}

/// CAPWAP source filter derived from the allow list.
#[derive(Debug, Clone, Default)]
pub struct SourceFilter {
    pub allow: Vec<Cidr>,
}

impl SourceFilter {
    /// Whether a datagram from `peer` may be answered.
    ///
    /// A WTP that has no address yet (stage-1 / broadcast discovery) sends from
    /// the unspecified address; for those the ingress interface address decides,
    /// so a broadcast on a private link is accepted while the same datagram on a
    /// public interface is not.
    pub fn permits(&self, peer: IpAddr, info: &RecvInfo) -> bool {
        if self.allow.is_empty() {
            return true;
        }
        if !peer.is_unspecified() {
            return self.matches(peer);
        }
        let local = info
            .local
            .or_else(|| info.dst.filter(is_unicast_addr));
        if let Some(local) = local {
            return self.matches(local);
        }
        crate::net::iface_ip_addrs(info.ifindex)
            .into_iter()
            .any(|ip| self.matches(ip))
            || info.dst.map(|d| self.matches(d)).unwrap_or(false)
    }

    fn matches(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|c| c.contains(ip))
    }
}

fn is_unicast_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !v.is_unspecified() && !v.is_broadcast() && !v.is_multicast(),
        IpAddr::V6(v) => !v.is_unspecified() && !v.is_multicast(),
    }
}

/// CAPWAP bind policy.
#[derive(Debug, Clone)]
pub struct CapwapSettings {
    pub binds: Vec<SocketAddr>,
    pub iface: Option<String>,
}

/// H3C-specific advertised radio features (formerly MINIAC_H3C_* variables).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H3cSettings {
    pub ofdma: u32,
    pub mumimo: u32,
    pub band_navigation: u32,
}

/// Stage-1 (private port 10087) DHCP-like lease settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1Settings {
    pub enabled: bool,
    /// WTP subnet used to pick the ingress address and to derive pool defaults.
    pub net: (Ipv4Addr, u8),
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    /// Lease gateway; `None` means "the AC address the request arrived on".
    pub gateway: Option<Ipv4Addr>,
}

impl Stage1Settings {
    fn defaults(net: (Ipv4Addr, u8)) -> Self {
        Stage1Settings {
            enabled: true,
            net,
            pool_start: add_v4(net.0, 50),
            pool_end: add_v4(net.0, 80),
            gateway: None,
        }
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(if self.net.1 >= 32 {
            0xffff_ffffu32
        } else {
            0xffff_ffffu32 << (32 - self.net.1.min(32))
        })
    }
}

/// One HTTP(S) listen address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenAddr {
    pub addr: IpAddr,
    pub port: u16,
}

impl ListenAddr {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }

    pub fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }
}

impl std::fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.socket_addr())
    }
}

#[derive(Debug, Clone)]
pub struct WebSettings {
    pub http: ListenAddr,
    pub https: Option<ListenAddr>,
    pub https_cert: Option<PathBuf>,
    pub https_key: Option<PathBuf>,
}

impl WebSettings {
    /// Security warnings raised at startup for non-default exposure. The web
    /// plane has no authentication, so anything beyond loopback is exposed.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.http.is_loopback() {
            out.push(format!(
                "web UI on http://{} is reachable beyond loopback and has no authentication; \
                 keep it on 127.0.0.1 or firewall the port",
                self.http
            ));
        }
        if let Some(https) = &self.https {
            if !https.is_loopback() {
                out.push(format!(
                    "web UI on https://{} is reachable beyond loopback and has no authentication; \
                     keep it on 127.0.0.1 or firewall the port",
                    https
                ));
            }
        }
        out
    }
}

/// Fully merged runtime settings.
#[derive(Debug, Clone)]
pub struct Settings {
    pub capwap: CapwapSettings,
    pub source: SourceFilter,
    pub stage1: Stage1Settings,
    pub web: WebSettings,
    pub h3c: H3cSettings,
    pub dump_file: Option<PathBuf>,
}

/// Raw `-flag` values before merging with the INI file.
#[derive(Debug, Default)]
struct Cli {
    allow: Option<Vec<Cidr>>,
    binds: Vec<String>,
    iface: Option<String>,
    http: Option<String>,
    https: Option<String>,
    ini: Option<PathBuf>,
    dump_file: Option<PathBuf>,
}

fn parse_cli() -> Result<Cli> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-a" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow!("-a requires a CIDR list"))?;
                let list = parse_allow(&v)?;
                cli.allow.get_or_insert_with(Vec::new).extend(list);
            }
            "-b" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow!("-b requires an address"))?;
                cli.binds.extend(split_list(&v));
            }
            "-i" => {
                cli.iface = Some(args.next().ok_or_else(|| anyhow!("-i requires an interface"))?)
            }
            "-w" => cli.http = Some(args.next().ok_or_else(|| anyhow!("-w requires a value"))?),
            "-W" => cli.https = Some(args.next().ok_or_else(|| anyhow!("-W requires a value"))?),
            "-c" => {
                cli.ini = Some(PathBuf::from(
                    args.next().ok_or_else(|| anyhow!("-c requires a file"))?,
                ))
            }
            "-D" => {
                cli.dump_file = Some(PathBuf::from(
                    args.next().ok_or_else(|| anyhow!("-D requires a file"))?,
                ))
            }
            // Unknown flags are ignored, as before, so old invocations do not
            // abort on a stray argument.
            _ => {}
        }
    }
    Ok(cli)
}

/// Parse a comma/whitespace separated allow list.
fn parse_allow(value: &str) -> Result<Vec<Cidr>> {
    split_list(value)
        .iter()
        .map(|s| Cidr::parse(s))
        .collect()
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Load settings: CLI over the optional INI file over defaults.
pub fn load() -> Result<Settings> {
    let cli = parse_cli()?;
    let ini_path = match &cli.ini {
        Some(path) => Some(path.clone()),
        None => {
            let path = PathBuf::from(DEFAULT_INI);
            path.is_file().then_some(path)
        }
    };
    let ini = match &ini_path {
        Some(path) => {
            info!("[*] settings: reading {}", path.display());
            let text = fs::read_to_string(path)
                .with_context(|| format!("read settings file {}", path.display()))?;
            Some(parse_ini(&text))
        }
        None => None,
    };
    merge(cli, ini)
}

/// Merge CLI values over INI values over defaults.
fn merge(cli: Cli, ini: Option<Ini>) -> Result<Settings> {
    let get = |section: &str, key: &str| ini.as_ref().and_then(|i| i.get(section, key));

    // CAPWAP peer allow list: explicit CLI entries replace the INI list which
    // replaces the private-range default.
    let allow = match &cli.allow {
        Some(list) => list.clone(),
        None => match get("capwap", "allow") {
            Some(v) => parse_allow(v)?,
            None => default_allow(),
        },
    };

    // CAPWAP binds: an explicit unicast bind disables broadcast discovery.
    let bind_specs = if !cli.binds.is_empty() {
        cli.binds.clone()
    } else {
        get("capwap", "bind").map(split_list).unwrap_or_default()
    };
    let binds = if bind_specs.is_empty() {
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), CTRL_PORT),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), CTRL_PORT),
        ]
    } else {
        bind_specs
            .iter()
            .map(|s| parse_bind(s))
            .collect::<Result<Vec<_>>>()?
    };

    let iface = cli
        .iface
        .clone()
        .or_else(|| get("capwap", "iface").map(str::to_string))
        .filter(|s| !s.is_empty());

    let capwap = CapwapSettings { binds, iface };

    // Stage-1 lease settings.
    let net = match get("stage1", "net") {
        Some(v) => parse_v4_net(v)?,
        None => (Ipv4Addr::new(192, 168, 0, 0), 24),
    };
    let mut stage1 = Stage1Settings::defaults(net);
    if let Some(v) = get("stage1", "enabled") {
        stage1.enabled = parse_bool(v)?;
    }
    if let Some(v) = get("stage1", "pool_start") {
        stage1.pool_start = parse_v4(v)?;
    }
    if let Some(v) = get("stage1", "pool_end") {
        stage1.pool_end = parse_v4(v)?;
    }
    if let Some(v) = get("stage1", "gateway").map(str::trim).filter(|v| !v.is_empty()) {
        stage1.gateway = Some(parse_v4(v)?);
    }
    if stage1.pool_start > stage1.pool_end {
        bail!(
            "stage-1 pool_start {} is after pool_end {}",
            stage1.pool_start,
            stage1.pool_end
        );
    }

    // Web plane: HTTP always on; HTTPS only when explicitly configured.
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let http = match &cli.http {
        Some(v) => parse_listen(v, loopback, HTTP_DEFAULT_PORT)?,
        None => ListenAddr {
            addr: match get("web", "http_addr") {
                Some(v) => parse_ip(v)?,
                None => loopback,
            },
            port: match get("web", "http_port") {
                Some(v) => parse_port(v)?,
                None => HTTP_DEFAULT_PORT,
            },
        },
    };
    let https = match &cli.https {
        Some(v) => Some(parse_listen(v, loopback, HTTPS_DEFAULT_PORT)?),
        None => {
            let addr = match get("web", "https_addr") {
                Some(v) => Some(parse_ip(v)?),
                None => None,
            };
            let port = match get("web", "https_port") {
                Some(v) => Some(parse_port(v)?),
                None => None,
            };
            match (addr, port) {
                (None, None) => None,
                (addr, port) => Some(ListenAddr {
                    addr: addr.unwrap_or(loopback),
                    port: port.unwrap_or(HTTPS_DEFAULT_PORT),
                }),
            }
        }
    };
    let https_cert = get("web", "https_cert").map(PathBuf::from);
    let https_key = get("web", "https_key").map(PathBuf::from);
    let web = WebSettings {
        http,
        https,
        https_cert,
        https_key,
    };

    let h3c = H3cSettings {
        ofdma: parse_opt_u32(get("h3c", "ofdma"))?.unwrap_or(0),
        mumimo: parse_opt_u32(get("h3c", "mumimo"))?.unwrap_or(0),
        band_navigation: parse_opt_u32(get("h3c", "band_navigation"))?.unwrap_or(0),
    };

    Ok(Settings {
        capwap,
        source: SourceFilter { allow },
        stage1,
        web,
        h3c,
        dump_file: cli.dump_file,
    })
}

/// Add a host offset to an IPv4 address.
pub fn add_v4(ip: Ipv4Addr, delta: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip).wrapping_add(delta))
}

fn parse_bind(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let ip: IpAddr = s
        .parse()
        .with_context(|| format!("invalid CAPWAP bind address {s:?}"))?;
    Ok(SocketAddr::new(ip, CTRL_PORT))
}

fn parse_listen(value: &str, default_addr: IpAddr, default_port: u16) -> Result<ListenAddr> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(ListenAddr {
            addr: default_addr,
            port: default_port,
        });
    }
    if let Ok(port) = v.parse::<u16>() {
        return Ok(ListenAddr {
            addr: default_addr,
            port,
        });
    }
    if let Ok(addr) = v.parse::<IpAddr>() {
        return Ok(ListenAddr {
            addr,
            port: default_port,
        });
    }
    if let Some(rest) = v.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("unbalanced '[' in listen address {v:?}"))?;
        let addr = parse_ip(host)?;
        let port = match tail.strip_prefix(':') {
            Some(p) if !p.is_empty() => parse_port(p)?,
            _ => default_port,
        };
        return Ok(ListenAddr { addr, port });
    }
    match v.rsplit_once(':') {
        Some((host, port)) => Ok(ListenAddr {
            addr: if host.is_empty() {
                default_addr
            } else {
                parse_ip(host)?
            },
            port: parse_port(port)?,
        }),
        None => Ok(ListenAddr {
            addr: default_addr,
            port: parse_port(v)?,
        }),
    }
}

fn parse_v4(s: &str) -> Result<Ipv4Addr> {
    s.trim()
        .parse()
        .with_context(|| format!("invalid IPv4 address {s:?}"))
}

fn parse_ip(s: &str) -> Result<IpAddr> {
    s.trim()
        .parse()
        .with_context(|| format!("invalid IP address {s:?}"))
}

fn parse_port(s: &str) -> Result<u16> {
    s.trim()
        .parse()
        .with_context(|| format!("invalid port {s:?}"))
}

fn parse_v4_net(s: &str) -> Result<(Ipv4Addr, u8)> {
    let c = Cidr::parse(s)?;
    match c.addr {
        IpAddr::V4(v) => Ok((v, c.prefix)),
        IpAddr::V6(_) => bail!("stage-1 net must be IPv4, got {s:?}"),
    }
}

fn parse_bool(s: &str) -> Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other:?}"),
    }
}

fn parse_opt_u32(v: Option<&str>) -> Result<Option<u32>> {
    match v {
        Some(v) => Ok(Some(
            v.trim()
                .parse()
                .with_context(|| format!("invalid number {v:?}"))?,
        )),
        None => Ok(None),
    }
}

/// Minimal INI reader: `[section]` headers and `key = value` lines. Comments
/// start with `#` or `;` at the beginning of a line.
#[derive(Debug, Default)]
struct Ini {
    sections: HashMap<String, HashMap<String, String>>,
}

impl Ini {
    fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .get(section)
            .and_then(|s| s.get(key))
            .map(String::as_str)
    }
}

fn parse_ini(text: &str) -> Ini {
    let mut ini = Ini::default();
    let mut current = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                current = name.trim().to_ascii_lowercase();
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            ini.sections
                .entry(current.clone())
                .or_default()
                .insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    ini
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matches_ipv4_and_ipv6() {
        let net = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(net.contains("192.168.1.5".parse().unwrap()));
        assert!(!net.contains("10.1.2.3".parse().unwrap()));
        // v4-mapped v6 peer is matched as IPv4.
        assert!(net.contains("::ffff:192.168.1.5".parse().unwrap()));
        let v6 = Cidr::parse("fc00::/7").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_bad_prefix() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
        // A bare address is a host route.
        let host = Cidr::parse("10.1.2.3").unwrap();
        assert_eq!(host.prefix, 32);
    }

    #[test]
    fn default_allow_is_private() {
        let f = SourceFilter {
            allow: default_allow(),
        };
        let local = RecvInfo {
            dst: Some("192.168.0.254".parse().unwrap()),
            local: Some("192.168.0.254".parse().unwrap()),
            ifindex: 0,
        };
        for ok in ["192.168.1.5", "10.1.2.3", "172.20.0.9", "127.0.0.1"] {
            assert!(f.permits(ok.parse().unwrap(), &local), "{ok}");
        }
        for bad in ["8.8.8.8", "203.0.113.9", "2001:db8::1"] {
            assert!(!f.permits(bad.parse().unwrap(), &local), "{bad}");
        }
        assert!(f.permits("::1".parse().unwrap(), &local));
        assert!(f.permits("fe80::1".parse().unwrap(), &local));
    }

    #[test]
    fn unspecified_source_uses_ingress_address() {
        let f = SourceFilter {
            allow: vec![Cidr::parse("192.168.0.0/24").unwrap()],
        };
        let private = RecvInfo {
            dst: Some("255.255.255.255".parse().unwrap()),
            local: Some("192.168.0.254".parse().unwrap()),
            ifindex: 1,
        };
        assert!(f.permits("0.0.0.0".parse().unwrap(), &private));
        let public = RecvInfo {
            dst: Some("255.255.255.255".parse().unwrap()),
            local: Some("203.0.113.5".parse().unwrap()),
            ifindex: 2,
        };
        assert!(!f.permits("0.0.0.0".parse().unwrap(), &public));
    }

    #[test]
    fn listen_addr_forms() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            parse_listen("", lo, 8246).unwrap(),
            ListenAddr {
                addr: lo,
                port: 8246
            }
        );
        assert_eq!(
            parse_listen(":9000", lo, 8246).unwrap(),
            ListenAddr {
                addr: lo,
                port: 9000
            }
        );
        assert_eq!(
            parse_listen("9000", lo, 8246).unwrap(),
            ListenAddr {
                addr: lo,
                port: 9000
            }
        );
        assert_eq!(
            parse_listen("[::1]:8443", lo, 8246).unwrap(),
            ListenAddr {
                addr: "::1".parse().unwrap(),
                port: 8443
            }
        );
        assert_eq!(
            parse_listen("0.0.0.0:8080", lo, 8246).unwrap(),
            ListenAddr {
                addr: "0.0.0.0".parse().unwrap(),
                port: 8080
            }
        );
    }

    #[test]
    fn ini_is_parsed_and_cli_wins() {
        let text = "\
# comment
[capwap]
allow = 10.0.0.0/8, 172.16.0.0/12
bind = 192.168.0.2
[stage1]
net = 10.9.0.0/16
pool_start = 10.9.0.10
gateway = 10.9.0.1
[web]
http_port = 9001
[h3c]
ofdma = 7
";
        let ini = parse_ini(text);
        assert_eq!(ini.get("capwap", "allow"), Some("10.0.0.0/8, 172.16.0.0/12"));
        assert_eq!(ini.get("stage1", "pool_start"), Some("10.9.0.10"));
        assert_eq!(ini.get("web", "http_port"), Some("9001"));
        assert_eq!(ini.get("h3c", "ofdma"), Some("7"));

        let settings = merge(Cli::default(), Some(parse_ini(text))).unwrap();
        assert_eq!(settings.source.allow.len(), 2);
        assert_eq!(settings.capwap.binds.len(), 1);
        assert_eq!(settings.stage1.net, (Ipv4Addr::new(10, 9, 0, 0), 16));
        assert_eq!(settings.stage1.pool_start, Ipv4Addr::new(10, 9, 0, 10));
        assert_eq!(settings.stage1.pool_end, Ipv4Addr::new(10, 9, 0, 80));
        assert_eq!(settings.stage1.gateway, Some(Ipv4Addr::new(10, 9, 0, 1)));
        assert_eq!(settings.web.http.port, 9001);
        assert_eq!(settings.h3c.ofdma, 7);

        // An explicit CLI allow/bind/listen replaces the INI value.
        let cli = Cli {
            allow: Some(vec![Cidr::parse("192.0.2.0/24").unwrap()]),
            binds: vec!["127.0.0.1".to_string()],
            http: Some(":9999".to_string()),
            ..Cli::default()
        };
        let settings = merge(cli, Some(parse_ini(text))).unwrap();
        assert_eq!(settings.source.allow.len(), 1);
        assert_eq!(settings.capwap.binds[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(settings.web.http.port, 9999);
        // Values not overridden still come from the INI.
        assert_eq!(settings.h3c.ofdma, 7);
    }

    #[test]
    fn stage1_netmask_and_pool_defaults() {
        let s = Stage1Settings::defaults((Ipv4Addr::new(192, 168, 0, 0), 24));
        assert_eq!(s.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(s.pool_start, Ipv4Addr::new(192, 168, 0, 50));
    }

    #[test]
    fn exposure_warning_only_off_loopback() {
        let safe = WebSettings {
            http: ListenAddr {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8246,
            },
            https: None,
            https_cert: None,
            https_key: None,
        };
        assert!(safe.warnings().is_empty());
        let risky = WebSettings {
            http: ListenAddr {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 8246,
            },
            https: None,
            https_cert: None,
            https_key: None,
        };
        assert_eq!(risky.warnings().len(), 1);
    }
}
