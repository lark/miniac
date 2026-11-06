# CAPWAP DTLS Certificate Parameters

This document records the identities shipped under `certs/default/`, the DTLS
parameters the AC offers, and why this coverage is sufficient for the supported
WTP families.

## 1. Identity files and resolution order

The AC resolves one server identity per WTP profile, in this order:

1. `certs/<vendor>/server.pem` — optional field override (highest priority).
2. `certs/default/server.pem` — shared default identity.
3. Ephemeral self-signed Ed25519 identity — last resort only. It offers no
   static-RSA CBC suite, so a WTP that only proposes `0x002f`/`0x0035` cannot
   negotiate with it; the AC logs a warning when this path is taken.

| File | Purpose |
|---|---|
| `certs/default/server.pem` | Shared default identity (RSA-2048) |
| `certs/h3c/server.pem` | Optional H3C field override (not shipped) |
| `certs/tplink/server.pem` | Optional TP-Link field override (not shipped) |
| `certs/rfc/server.pem` | Optional generic-profile field override (not shipped) |

Each file is a PEM bundle containing the X.509 leaf certificate followed by the
matching private key. Both PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8
(`PRIVATE KEY`) keys are accepted. The certificate is self-signed; no
intermediate or root is shipped or sent.

## 2. Identity parameters

| Parameter | `certs/default/server.pem` |
|---|---|
| Public-key algorithm | RSA |
| Key size | 2048 bit |
| Certificate signature | `sha256WithRSAEncryption` |
| Subject | `C=CN, O=MiniAC, CN=miniac-ac` |
| Issuer | Self-signed (same as subject) |
| Validity | 2026-11-06 to 2046-11-01 (7300 days) |
| Chain | Leaf only |
| Private-key encoding | PKCS#8 RSA |

## 3. Handshake parameters

- **Authentication model**: server-only. The AC never sends a Certificate
  Request and never validates a client certificate. `with_insecure_verification`
  is enabled because the WTPs do not present a verifiable chain and do not
  verify the AC certificate either.
- **Key exchange**: static RSA. There is no ECDHE and therefore no forward
  secrecy; this is a firmware constraint, not a design choice (see below).
- **Cipher suites**, offered in this order:
  1. `TLS_RSA_WITH_AES_128_CBC_SHA` (`0x002f`)
  2. `TLS_RSA_WITH_AES_256_CBC_SHA` (`0x0035`)
- **Signature schemes**: `rsa_pkcs1_sha256`, then `rsa_pkcs1_sha1` as a legacy
  fallback. Insecure hashes are explicitly enabled for the benefit of older WTP
  stacks.

## 4. Coverage and rationale

### 4.1 Coverage matrix

| Peer | Selected identity | Evidence |
|---|---|---|
| TP-Link TL-AP1300GI-PoE | `certs/default/server.pem` (RSA-2048) | Lab-tested: DTLS, Join, Configure, Run |
| TP-Link 7AP3602HI-PoE | `certs/default/server.pem` (RSA-2048) | Same libcyassl 5.0.1 stack, static analysis only; not hardware-tested |
| H3C AX60 (SWBA1B0) | `certs/default/server.pem` (RSA-2048) | Lab-tested: DTLS, Join, Configure, Run |
| RFC / unknown WTP | `certs/default/server.pem` (RSA-2048) | Generic fallback |

Vendor override directories still win over the defaults, so a field unit that
needs the identity it was originally provisioned with can be served without
rebuilding the AC.

### 4.2 Why these parameters

- **RSA, not ECDSA or Ed25519.** The tested WTP firmware negotiates only
  static-RSA CBC suites. Those suites require an RSA certificate; an
  ECDSA/Ed25519 identity cannot complete the handshake even if the peer would
  otherwise accept it. The Ed25519 fallback exists only to let the AC start
  without a certificate tree.
- **RSA-2048.** Both tested families accept RSA-2048 with SHA-256 (the AX60
  was re-tested against this identity on 2026-11-12), and 2048 bits avoids
  shipping a weak default. No per-vendor identity is needed.
- **SHA-256 certificate, SHA-1 handshake fallback.** Certificates are signed
  with SHA-256. The handshake additionally advertises `rsa_pkcs1_sha1` because
  some legacy DTLS stacks only offer SHA-1 for `ServerKeyExchange`.
- **Only AES-128/256-CBC-SHA.** These are the suites observed in both vendors'
  cipher lists. Neither firmware offers AES-GCM or ECDHE suites, so advertising
  more would not improve interoperability.
- **Self-signed, 20-year validity.** Neither tested WTP verifies the AC
  certificate or its chain, so a CA hierarchy adds no security value. The long
  validity avoids failures on APs whose clock is far from real time.
- **No client certificate request.** Both tested families authenticate the AC
  only by completing the DTLS handshake; requiring a client certificate would
  break the join flow.

## 5. Regeneration

Equivalent commands (run from the repository root):

```sh
# Shared default identity: RSA-2048, SHA-256, 7300 days.
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 7300 \
  -subj "/C=CN/O=MiniAC/CN=miniac-ac" \
  -keyout /tmp/default-key.pem -out /tmp/default-cert.pem
cat /tmp/default-cert.pem /tmp/default-key.pem > certs/default/server.pem
```

Verify with:

```sh
openssl x509 -in certs/default/server.pem -noout -subject -dates -text \
  | grep -E "subject=|Not |Public-Key|Signature Algorithm"
```

## 6. Limitations

- `7AP3602HI-PoE` has not been tested on hardware; its compatibility is inferred
  from the shared libcyassl 5.0.1 DTLS stack.
- Static RSA provides no forward secrecy. This is required by the tested WTP
  firmware and cannot be improved on the AC side alone.
- The Ed25519 fallback is not usable with WTPs that offer static-RSA suites
  only; it is a startup safety net, not a supported deployment identity.
