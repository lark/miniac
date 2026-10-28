# CAPWAP Private Message Types and Elements (TP-Link / H3C)

Copyright (c) 2026  Wang Jian

Known private message types and element definitions for TP-Link AC100 / TL-AP1300GI and
H3C AX60 / M60.

Terminology: *message type* is the CAPWAP header `Type` field of a message
(Discovery/Join/Config Status/…); *element tag* is the 16-bit TLV tag inside a message body.
Both are given as either decimal or `0x…` hex.

Source column:

- `wire` — confirmed from live captures (real AC100 sessions in
  `/home/lark/tmp/miniac-tplink/ac100-full2.pcap`, `ac100-station.pcap`; miniac side from the
  `-D` dump).
- `code` — derived from AC/WTP firmware disassembly or from the miniac implementation, not yet
  observed on the wire.

Fields whose semantics or layout are still uncertain are marked `?`.

## 1. Carriage and framing differences

| Item | TP-Link AC100/AP1300GI | H3C Mini M60/AX60 |
| --- | --- | --- |
| Private element carriage | nested inside RFC 5415 element 37 (Vendor Specific Payload) | private tags sit directly in the top-level element stream |
| VSP value layout | `[vendor u32 = 0x12345678][rsv u16][id u16][len u16][value]` | n/a |
| Control header | base 8B + Type 4B + Seq 1B + MsgElemLen 2B + Flags 1B | base 8B + Type 4B + Seq **4B** + MsgElemLen 2B + Flags 1B |
| First element offset | 16 | 19 |
| MsgElemLen | counts the bytes after Seq (= 3 + Flags + elements) | self-inclusive (= 3 + elements) |
| Message type (header `Type` field) | identical to RFC 5415 | mostly identical, plus private 139 / 145 / 146 |

### 1.1 The VSP `rsv` field

`rsv` is not a reserved word but a group/sub-table selector: the same `id` means different things
under different `rsv` values. Observed values (`wire`):

| rsv | ids seen |
| --- | --- |
| `0x0000` | 0, 5, 30, 32, 33, 35, 37, 39, 44, 56, 57, 64, 65, 81, 91 |
| `0x0008` | 8 (rsv equals id; `code`) |
| `0x0026` | 38 (rsv equals id) |
| `0x003a` | 58 (rsv equals id) |
| `0x003b` | 60, 61 `?` (group semantics unknown) |

## 2. TP-Link (TL-AC100 / TL-AP1300GI)

### 2.1 Private TLVs inside element 37

| id | Name | Value layout | Direction / message type | Source |
| --- | --- | --- | --- | --- |
| 0 | `?` | 4B; `00010001` at Join | AP→AC message type 3 | wire |
| 5 | AP base parameters | 2 × u32; instance `(300, 5)`, field semantics `?` | AC→WTP message type 6 (rsv 0) / message type 7 | wire |
| 6 | Channel state | `?` | — | code |
| 7 | Add MAC ACL entry | AC100 appends a fixed 2B `00 30` to every WLAN push `?` | AC→WTP, message type 0x33DD01 | code |
| 8 | MAC Operation (private) | 20B; `:00 :01` prefix + per-radio variant byte (radio 1 `06`, radio 2 `09`) | AC→WTP message type 7 (rsv 0x0008) | code |
| 9 | WSRV_PARA (WLAN security parameter) | see 2.2 | AC→WTP, message type 0x33DD01 | code |
| 13 | Clear / statistics counter request | `?` | — | code |
| 20 | Transparent data request | `?` | — | code |
| 27 | AC information | `?` | — | code |
| 30 | WLAN list the WTP holds | `[u32 ?][u32 count]` then `count` records of `[u8 radio][32B SSID]`; observed `00000001 00000002` + radio 1 `"miniac"` + radio 2 `"miniac"`, and `…00000000` for a WTP holding nothing; rides the Configuration Status Request (message type 5) and is the AC's basis for skipping a redundant push | wire |
| 31 | Station list | `?` (the station list actually rides top-level tag 51, see 2.3) | — | code |
| 32 | `?` | 4B; `00000014` (20) in both Join and Echo `?` | AP→AC message type 3 / message type 13 | wire |
| 33 | `?` | 32B = 8 × u16 pair `(1,0) … (8,0)`, likely a WLAN slot table `?` | AP→AC message type 13 | wire |
| 35 | Reset mask | u32; plain restart `00000001` | AC→WTP message type 17 | wire |
| 37 | AP resource info | 5B `[radio u8][band type u8][channel u8][power u16]`; band type `06` = 2.4G, `09` = 5G (same selector as private 8 / the radio record); instances radio 1 `01 06 06 000d` (2.4G, ch 6, 13) and radio 2 `02 09 95 000f` (5G, ch 149, 15) | AP→AC message type 9 | wire |
| 38 | SPEC_MSG_SW (supported special messages bitmap) | 2 × u32; instance `(0x6e, 0x6e)` | AC→WTP message type 6 (rsv 0x0026) | wire |
| 39 | Config type | 4B; instance `00000001` | AC→WTP message type 4 | wire |
| 44 | `?` | 4B; `00000001` at Join | AP→AC message type 3 | wire |
| 48 | Wired VLAN (primary form) | `?` | AC→WTP message type 7 | code |
| 56 | AP LED status | 4B; measured `00000001` / `00000000` | AP→AC message type 13 | wire |
| 57 | AP LED operation | 4B; measured `00000000` | AC→WTP message type 7 | wire |
| 58 | `?` (rsv 0x003a) | 4B `01 28 08 0a` | AC→WTP message type 6 | wire |
| 60 | AP offline behaviour / report period | 24B: `[radio u32][period u32]` + 16B zeros; instance `(1, 120)`; trailing 16B semantics `?` | AC→WTP message type 6 (rsv 0x003b) | wire |
| 61 | AP_USER | 128B: two 21B runs of `"92C37C67D7AD3FC"` + zeros `?` | AC→WTP message type 6 (rsv 0x003b) | wire |
| 64 | `?` | 4B; measured `00000001` | AP→AC message type 9 | wire |
| 65 | AP configuration checksum | 16B; measured all-zero `?` | AP→AC message type 9 | wire |
| 67 | Wired VLAN (alternate form) | `?` | AC→WTP message type 7 | code |
| 68 | AP trunk | u32 `?` | AC→WTP message type 7 | code |
| 81 | AP capability / board blob | 128B; contains `"TL-AP1300GI-PoE"`, a version, `5EDB2E…` and per-radio records `?` | AP→AC message type 3 | wire |
| 91 | AP firmware id | 17B; measured `6f3427d6 ab86fb68 f525813c 4759edee 00` `?` | AP→AC message type 3 | wire |

### 2.2 Private 9 (WSRV_PARA) security parameter layout (`code`)

```
 0  radio id
 1  WLAN id
 2  VLAN id            (u16)
 4  max users          (u16)
 6  network type        (AC100 sends 1)
 7  client isolation
 8  security option     (1 = PSK; any other value is rejected by the WTP, so an
                         open WLAN must omit the element instead)
 9  auth type           ┐
10  cipher              │ security option PSK
11  rekey period  (u32) │
15  key length    (u16) │
17  PSK                 ┘
```

### 2.3 TP-Link top-level tags outside element 37

| Element tag | Name | Value layout | Source |
| --- | --- | --- | --- |
| 51 (0x0033) | Station report | `[radio u8][count u32]` followed by `count` records of `[6B MAC][1B ?]`; with no station the value is only 5B (`0100000000`); rides the WTP Event Request (message type 9) | wire |
| 52 (0x0034) | `?` | never seen in any capture | code |
| 77 (0x004d) | `?` | never seen in any capture | code |
| 1024 (0x0400) | Add WLAN (RFC 5416) | see 2.4 | code |
| 1027 (0x0403) | Delete WLAN (RFC 5416) | 2B `[radio][wlan]`; **destructive**: sending it for two unused slots left the next Configuration Status Request reporting zero saved WLANs, so on this WTP it clears the saved WLAN table rather than the named slot, and AC100 never sends it | wire (effect) |
| 1028 (0x0404) | Radio channel record | 19B; byte 0 = radio, byte 2 = channel (0 = ACS) | code |
| 1030 (0x0406) | Radio TX record | 16B | code |
| 1041 (0x0411) | MAC Operation | 4B `[radio][0][0][variant]` (variant `06`/`09` as above) | code |
| 1046 (0x0416) | Station Event Type | 16B; tail `64 43 4e 20` | code |
| 1048 (0x0418) | WTP Radio Info | 5B `[radio][u32 state]`, one per radio at Join | wire |

`0x0404`/`0x0406` are TP-Link's own tags with a different purpose from the RFC 5416 numbers
`0x0411`/`0x0416`. The `0x0033DD01` family is described in 2.5.

### 2.4 Add WLAN (1024) value layout (`code`)

```
 0  radio id
 1  WLAN id
 2  capability word   (u16; AC100 sends 0x8000)
 4  key index/status + key length + group TSC + QoS/auth/MAC  (13B, all zero from AC100)
17  tunnel flag       (AC100 sends 0x01)
18  broadcast flag    (AC100 sends 0x01)
19  SSID              (to the end of the value)
```

The trailing `01 01` pair is what actually brings the WLAN up: with capability 0x0001 and both
trailing bytes zero the WTP answers 0x0033DD02 with success but never puts the SSID on the air.

### 2.5 TP-Link private message types

| Message type | Name | Notes |
| --- | --- | --- |
| 0x0033DD01 | WLAN Configuration Update Request | pushes WLANs while the WTP runs; the RFC message type 7 path cannot carry WLANs (the WTP parser accepts private elements only and drops 1024/1027) |
| 0x0033DD02 | WLAN Configuration Update Response | element 33 = Result Code |

## 3. H3C (AX60 / M60)

### 3.1 Private top-level tags

| Element tag | Name | Value layout | Direction / message type | Source |
| --- | --- | --- | --- | --- |
| 0x0418 (1048) | Join contract element `?` | 5B; miniac fills zeros per the real AC template; anything other than exactly 5B makes the WTP drop the whole request | AC→WTP Discovery Response | code |
| 54 (0x0036) | WTP MAC | bare 6B; H3C does not use the RFC WTP Board Data (38) for the MAC | AP→AC | code |
| 65 (0x0041) | Release Client MAC | bare 6B; the station MAC the AC wants evicted | AC→WTP message type 139 | code |
| 0xFDE8 | WLAN configuration element | see 3.3 | AC→WTP message type 6 | code |
| 0xFDF0 | Keep-alive interval | u32 | AC→WTP message type 7 | code |
| 0xFDF1 | WLAN batch (runtime WLAN push) | opaque blob `?` | AC→WTP message type 7 | code |
| 0xFDF2 | AP name | NUL-terminated string | AC→WTP message type 7 | code |
| 0xFDF4 | LED switch: `0` = all LEDs off (`led_control stop`), non-zero = normal indication (`led_control restart`) | u32, exactly 4B | AC→WTP message type 7; also in the message type 6 snapshot | code |
| 0xFDF5 | Telnet | u32 | AC→WTP message type 7 | code |
| 0xFDF7 | Roaming | u32 | AC→WTP message type 7 | code |
| 0xFDF9 | Channel | 2B `[radio][channel]` | AC→WTP message type 7 | code |
| 0xFDFA | Power | 5B `[radio][power u32]` | AC→WTP message type 7 | code |
| 0xFE06 | AC address change (private twin) | 4B IPv4; the RFC-side tag is 0x003E | AC→WTP message type 7 | code |
| 0xFE0B | AP password | 96B = 3 × 32B slots `[type][password][prompt]`; type `1` = follow the AC login password | AC→WTP message type 6 | code |
| 0xFE0C | `?` | 16B; miniac template encoding `00000000 ffffffb5 00000000 ffffffb0` `?` | AC→WTP message type 6 | code |
| 0xFE0D | `?` | 4B zeros `?` | AC→WTP message type 6 | code |
| 0xFE1A | `?` | 4B `000004b0` (1200, miniac template value) `?` | AC→WTP message type 6 | code |
| 0xFE1B | `?` | 4B zeros `?` | AC→WTP message type 6 | code |
| 0xFE20 | Channel utilization report | 2B `[2.4G util%][5G util%]`; the AP retransmits with a fixed seq every 10s until the AC answers Result Code 0 to clear the pending entry | AP→AC message type 145 (reply 146) | code |
| 0xFE28 | OFDMA / MU-MIMO switches | 12B; word 1 = OFDMA, word 2 = MU-MIMO; not sent when both are zero | AC→WTP message type 6 | code |
| 0xFE31 | Band navigation (LBD) switch | 4B u32; not sent when zero | AC→WTP message type 6 | code |

### 3.2 Elements reusing RFC tag numbers with private value layouts (M60 template)

| Element tag | RFC name | H3C value layout |
| --- | --- | --- |
| 2 | AC IPv4 List | 2 × u32 (own control address + peer address) |
| 3 | AC IPv6 List | 2 × 16B |
| 12 | CAPWAP Timers | `[0x14, 0x0a]` `?` (20 / 10 s) |
| 16 | Decrypt Error Report Period | 2B; miniac template `01 0078` |
| 23 | Idle Timeout | u32; miniac template `0000000a` |
| 32 | Radio Operational State | 3B per record `[radio][state][?]` `?` |
| 40 | WTP Fallback | 1B `0x00` |
| 55 | `?` (not an RFC number) | 6B interface MAC |

### 3.3 0xFDE8 WLAN element value layout (`code`)

A single element must cover both bands, in this order:

```
[7 × u32 BE]  2.4G radio header (enable / wlan id / power / mode / radio id / channel …)
[records]     "SSID-" anchored 2.4G WLAN records
[7 × u32 BE]  5G radio header (also the element's trailing field; its enable word gates 5G)
[records]     "5G-SSID-" anchored 5G WLAN records
```

Each record:

```
[33B anchor][u32 enable][33B SSID name][4 × u32][u32 encrypt][if enc != 0: 65B PSK][u32 cipher][u32 wpa-period]
```

### 3.4 H3C private message types

| Message type | Name | Notes |
| --- | --- | --- |
| 139 | Release Client by AC Request | a single element (tag 65) carries the station MAC; any value other than 6 bytes is rejected |
| 145 / 146 | WTP channel utilization report / ack | element 0xFE20 |
