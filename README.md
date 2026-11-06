# miniac

A CAPWAP Access Controller for multi-vendor access points, written in Rust.

## Status

Early-stage but functional. The two AP families below have been tested on
real hardware through join, configuration and Run. Everything else should be
treated as experimental.

## Supported access points

| Vendor | Model | Status |
|---|---|---|
| H3C | AX60 (SWBA1B0) | Tested on hardware |
| TP-Link | TL-AP1300GI-PoE | Tested on hardware |

Other H3C and TP-Link AP models supporting FIT mode may work but have not been
verified.

## Features

- CAPWAP discovery over broadcast and unicast, plus a stage-1 discovery helper
  (UDP 10087, enabled by default) for APs that bootstrap before they have an
  address
- DTLS control channel with static-RSA cipher suites, automatic per-vendor
  identity selection and out-of-box default certificates
- Vendor-aware framing and private message elements: RFC 5415, H3C and TP-Link
- WLAN and radio configuration with AC-wide templates plus per-AP overrides
- Firmware upload and upgrade (H3C and TP-Link image formats)
- Client station tracking, forced disconnect, AP reset/disable and LED control
- Embedded web UI and REST API, with session-cookie authentication and a
  configurable lifetime
- SQLite persistence for devices, WLAN templates, firmware and upgrade history

## Quick start

Requirements: stable Rust and Linux. No root privileges are needed for the
CAPWAP control port.

```sh
cargo build --release
./target/release/miniac
```

Then open <http://127.0.0.1:8246>. By default the AC accepts CAPWAP peers only
from private and loopback networks, and the web UI listens on loopback only.

Typical deployment behind a management network:

```sh
./target/release/miniac -w 0.0.0.0:8246 -a 192.168.5.0/24
```

## Command line

| Flag | Meaning |
|---|---|
| `-a <cidr[,..]>` | CAPWAP peer allow list (repeatable; replaces the default) |
| `-b <ip[,..]>` | CAPWAP unicast bind address (repeatable; disables broadcast discovery) |
| `-i <iface>` | Bind CAPWAP and stage-1 sockets to one interface |
| `-w [addr:]port` | HTTP web UI (default `127.0.0.1:8246`) |
| `-W [addr:]port` | HTTPS web UI (default `127.0.0.1:8443` when enabled) |
| `-c <file>` | INI file (default `./miniac.ini` when present) |
| `-d <dir>` | Run directory (created if missing); relative runtime paths — `-c`, `-D`, `miniac.db`, `firmware/`, `certs/` — resolve against it |
| `-D <file>` | Plaintext CAPWAP control dump for debugging |

Precedence is CLI flag, then INI value, then built-in default.

## Configuration

Create `miniac.ini` in the run directory (the current directory by default; or
pass `-c`):

```ini
[capwap]
allow = 192.168.5.0/24
# bind = 192.168.5.10
# iface = eth0

[web]
http_addr = 127.0.0.1
http_port = 8246
auth_user = admin
auth_password = change-me
session_ttl_minutes = 480
# https_addr = 0.0.0.0
# https_port = 8443
# https_cert = /path/to/cert.pem
# https_key  = /path/to/key.pem

[stage1]
# enabled = true
# net = 192.168.5.0/24
# pool_start = 192.168.5.100
# pool_end = 192.168.5.200
# gateway = 192.168.5.1

[h3c]
# ofdma = 7
# mumimo = 7
# band_navigation = 1
```

## WTP DHCP with dnsmasq

MiniAC has no standard DHCP server: the stage-1 helper listens on UDP 10087
and only answers H3C's private bootstrap, so APs that learn the AC address
from DHCP options need a DHCP server on the WTP VLAN. That server must
identify the WTPs, lease them addresses and return the AC IPv4 address in the
option each AP understands — option 43 for H3C's vendor layout, option 138
for the RFC 5417 CAPWAP list. The dnsmasq configuration below does this with
tags:

```ini
# 1. Tag WTPs that request a CAPWAP discovery option. Some APs send option 43
#    (vendor-specific) or 138 (RFC 5417 CAPWAP AC list) themselves; others only
#    list them in the parameter request list (option 55), so match both forms.
dhcp-match=set:wtp,43
dhcp-match=set:wtp,138
dhcp-match=set:wtp,55,43
dhcp-match=set:wtp,55,138

# 2. Lease range used only by the tagged WTPs.
dhcp-range=tag:wtp,192.168.5.20,192.168.5.40,255.255.255.0,6h

# 3. CAPWAP AC address for the tagged WTPs. Option 138 carries the RFC 5417
#    address list used by TP-Link and other standard CAPWAP clients.
dhcp-option=tag:wtp,138,192.168.5.254

# 4. H3C AX60 reads vendor-specific option 43 instead: 01 07 00 00 01 followed
#    by the AC IPv4 address (one AC, count 1). Require the CAPWAP tag and the
#    H3C vendor class together, so "H3C" alone does not catch switches/phones.
dhcp-vendorclass=set:h3c,H3C
tag-if=set:wtp-h3c,tag:wtp,tag:h3c
dhcp-option=tag:wtp-h3c,43,01:07:00:00:01:C0:A8:05:FE

# 5. Gateway and DNS handed to the WTPs.
dhcp-option=tag:wtp,3,192.168.5.1
dhcp-option=tag:wtp,6,192.168.5.1
```

Notes:

- Replace `192.168.5.254` / `C0:A8:05:FE` with the AC address reachable from
  the WTP VLAN; the two spellings are the same address in text and hex form.
- The `01:07:00:00:01` prefix is the AX60 option-43 layout: sub-option 1,
  length 7 (3 + 4 addresses), two reserved bytes and an AC count of 1. Other
  vendors may use a different prefix or option 138 only.
- Matching option 43/138 presence can also tag non-AP clients on a busy
  network. `dhcp-vendorclass` is substring-based, so step 4 combines it with
  the CAPWAP tag via `tag-if`; apply the same pattern to `wtp` if the lease
  range itself must be restricted.
- `[h3c]` values are numeric flags consumed when an H3C AP joins: `0` omits
  the corresponding element, non-zero values are sent as-is (`band_navigation`
  is not a boolean, so use `1`, not `true`).
- If some APs still use miniac's stage-1 bootstrap, keep `[stage1] enabled`
  and make its `pool_start`/`pool_end` disjoint from the dnsmasq range;
  otherwise set `enabled = false` under `[stage1]`.
- dnsmasq needs root (or `CAP_NET_BIND_SERVICE`) for UDP 67. MiniAC itself
  needs no privileges for the CAPWAP control port (UDP 5246).

## Certificates

The repository ships a self-signed, redistributable DTLS identity under
`certs/default/server.pem` (RSA-2048, SHA-256). Both tested AP families — H3C
AX60 and TP-Link TL-AP1300GI — complete the static-RSA handshake with it.

Resolution order per AP profile:

1. `certs/<vendor>/server.pem` (optional field override)
2. `certs/default/server.pem`
3. Ephemeral Ed25519 fallback (cannot negotiate the static-RSA suites the tested
   APs require, so it is a startup safety net rather than a deployment identity)

WTPs do not verify the AC certificate, so no CA chain is shipped. Authentication
is server-only; the AC never requests or validates a client certificate. See
[doc/cert-param.md](doc/cert-param.md) for algorithms, cipher suites, coverage
rationale and regeneration commands.

## Runtime files

Relative paths are resolved against the run directory (`-d`, default: the
current directory):

`miniac.db`, SQLite database, created on first start
`miniac.ini`, Optional configuration file
`certs/`, DTLS identities
`firmware/`, Uploaded AP firmware images

## Web API

The UI is served from `/`; the REST API lives under `/api`:

- `GET /api/session`, `POST /api/login`, `POST /api/logout`
- `GET /api/devices`, `GET|PUT /api/devices/{mac}`, `POST /api/devices/{mac}/approve`
- `GET /api/devices/{mac}/wlans`, `POST` to apply a WLAN per AP
- `GET|PUT /api/devices/{mac}/radios/{radio_id}` for H3C per-radio headers
- `GET /api/stations`, `POST /api/devices/{mac}/stations/{smac}/disconnect`
- `GET|POST /api/profiles`, `GET /api/radios`
- `GET|POST /api/firmware`, `POST /api/devices/{mac}/upgrade`
- `POST /api/devices/{mac}/config-update`, `/reset`, `/disable`
- `GET /api/wcfg`, `PUT /api/wcfg/global/radio/{band}`, `POST /api/wcfg/commit`
- `GET /api/events`

The web server has optional cookie-based authentication. Set both `auth_user`
and `auth_password` under `[web]` to enable it. Unauthenticated browser requests
are redirected to `/login`; unauthenticated API requests get `401` with
`{"error":"authentication required"}`. A successful login sets an `HttpOnly`,
`SameSite=Strict` session cookie with `Max-Age` equal to `session_ttl_minutes`
(default 480). Sessions live in memory, so restarting the AC logs everyone out,
and logged-out or expired tokens are rejected immediately.

For scripts, keep a cookie jar:

```sh
curl -c cookies -d 'username=admin&password=change-me' \
  http://127.0.0.1:8246/api/login
curl -b cookies http://127.0.0.1:8246/api/devices
```

Without credentials the UI is unauthenticated, so keep it on loopback or behind
an authenticating reverse proxy. Login credentials and the session cookie are
only as safe as the transport: when exposing the UI beyond loopback, serve it
over HTTPS (`https_cert`/`https_key`; the cookie then also gets `Secure`) and
restrict the INI file to the service account (`chmod 600`).

## Documentation

- [doc/cert-param.md](doc/cert-param.md) — DTLS identity parameters and coverage
- [doc/radio-settings-coverage.md](doc/radio-settings-coverage.md) — vendor radio settings matrix
- [doc/vendor-messages-elements.md](doc/vendor-messages-elements.md) — H3C/TP-Link private messages
- [doc/rfc5415.txt](doc/rfc5415.txt), [doc/rfc5416.txt](doc/rfc5416.txt) — protocol references

## Development

```sh
cargo check
cargo test
cargo build --release
```

The release profile is tuned for binary size (`opt-level = "z"`, LTO,
`codegen-units = 1`, `panic = "abort"`, stripped symbols).

Layout:

| Path | Contents |
|---|---|
| `src/` | CAPWAP core, session handling, persistence, web plane |
| `src/vendor/` | RFC/H3C/TP-Link framing, profiles and private elements |
| `src/web/` | Axum routes and embedded frontend |
| `doc/` | Protocol notes, settings coverage and certificate documentation |

## Limitations

- Only the APs listed above have been tested on hardware.
- DTLS is server-only; static RSA provides no forward secrecy. Both are
  constraints of the tested firmware, not preferences.
- Protocol models for 802.11k/v/r roaming and 802.1X/RSN are present but not yet
  wired into the live configuration path.
- Web authentication is optional cookie-based auth; enable it and use HTTPS
  whenever the UI is reachable beyond loopback. Sessions are invalidated by a
  restart.

## License

GPL-2.0. See [LICENSE](LICENSE).
