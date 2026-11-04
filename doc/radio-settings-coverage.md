# Per-radio wireless settings coverage analysis

> Inputs: TP-Link AC100 "Radio 5GHz" page screenshots, the existing implementation in `src/`, and H3C AX60 WTP / M60 AC disassembly and strings.
> Scope: current state and capability analysis only; no code changes.

## 1. AC100 page settings vs. miniac today

| # | AC100 setting | Meaning / range | miniac today | Status |
| --- | --- | --- | --- | --- |
| 1 | Radio mode | 802.11 mode (11n / 11ac only, etc.) | Stores a normalized 802.11 mode (`vendor::mode`: auto/11a/11b/11g/11b-g/11n/…, validated per band); translated by the vendor on the wire: H3C header byte 3 (2.4G 1–6 / 5G 7/8/10/11), TP-Link private record 8 byte 1 (AC100 codes 0–13) | Implemented |
| 2 | Channel bandwidth | 20/40/80/160 MHz or auto | `bandwidth` is stored and pushed with "upper bound" semantics: H3C band selector, TP-Link private record 8 byte 2 (20/40/80→0/1/2, auto/160→2); a device with a lower capability applies its own maximum | Implemented |
| 3 | Channel | Auto (ACS) or fixed channel | Global/override channel is modeled and pushed: TP-Link `0x0404` byte 2; H3C `0xfde8` header channel selector (5G converted from the IEEE number) | Implemented |
| 4 | Dynamic channel switching (DCS) | Automatic channel selection and its policy | Only "channel = auto"; no DCS policy parameters | Partially implemented |
| 5 | Online client steering | Periodically steer/switch clients to a better AP | Not implemented | Not implemented |
| 6 | Check period | 3–180 minutes, default 8 | Not modeled | Not implemented |
| 7 | Channel utilization threshold | 1–100, default 50 | Not modeled | Not implemented |
| 8 | Tolerance factor | 1–45, default 20 | Not modeled | Not implemented |
| 9 | Tx power | 0–100 % | UI/DB percentage; H3C `0xfde8` header byte 2; TP-Link RFC 5416 element 1041 (percentage × band maximum converted to dBm, AP1300GI 2.4G 17 / 5G 15, rounded) | Implemented |
| 10 | Airtime scheduling | Air-time fair scheduling switch | Not implemented | Not implemented |
| 11 | WMM | Wi-Fi multimedia QoS switch | Not implemented (the QoS bit in Add WLAN is fixed at 0) | Not implemented |
| 12 | Client limit | **Per radio** maximum associated clients, 1–100 | What exists is the **per SSID** `client_count` (H3C ≤32, TP-Link u16) | Different semantics; per-radio not implemented |
| 13 | Wireless client admission | Signal-based admission control | Not implemented | Not implemented |
| 14 | RSSI threshold | -95 to -40 dBm, default -60 | Not implemented; `roaming.rs` only has an 802.11k/v/r policy model, no RSSI threshold | Not implemented |
| 15 | Difference threshold | 3–24 dB, default 6 | Not implemented | Not implemented |
| 16 | Weak signal restriction | Reject new clients below the threshold | Not implemented | Not implemented |
| 17 | Weak signal kick-out | Disconnect already-associated weak-signal clients | Not implemented (H3C has `kickmac`, but it is not wired in) | Not implemented |

AC100's `0x0404` record (19B) carries, besides radio/channel, four u16 values: `8 / 50 / 100 / 20`, which match the page defaults "check period / utilization threshold / client limit / tolerance factor" exactly. The order still needs per-field verification, but this is the entry point for implementing that parameter group later. `0x0406` (16B) is TP-Link's MAC Operation record (u16@2 = RTS, u16@6 = Frag, always `0x092a` = 2346) and has nothing to do with tx power; power goes through RFC 5416 element 1041.

## 2. H3C AX60 / M60 support

Evidence from:
- `WTP.hexrays.c`: the 7×u32 header of `WTPEditSsidInit` maps to `CFG_SetWifiEnable / Mode / Band / Channel / Power`; `sub_3FF20` is the bandwidth enum; the SSID record includes `CFG_SetWifiSsidClientNum` (`-1 → 0`, `>32 → 32`).
- Symbols in the same binary: `CFG_SetWifiForbidden`, `CFG_SetWifiForbiddenRssi`, `CFG_SetWifiRoaming`, `CFG_SetWifiRoamingRssi`, `CFG_SetWifiRoamingPeriod`, `CFG_SetWifiLbd`, `CFG_SetWifi11R`, `CFG_SetWifiOfdma`, `CFG_SetWifiMumimo`, `iwpriv … kickmac`, `CAPWAP_setOptimizeChannel / CWWTP_DOOptimize`.
- `AC.hexrays.c`: M60 configuration fields `stRadioType / stBandwidth / stFixRate / pRtkChannel / pRtkPowerScale / iBasicTxpower / uiRoamingEnable / uiRoamingKickEn / uiRoamingThd / uiBandAuth / wlanRoaming / rssi`; `CWOptimizeApNetWork`.

| AC100 setting | H3C AX60/M60 | Notes |
| --- | --- | --- |
| Radio mode | Supported | `CFG_SetWifiMode` + enum mapping; M60 `stRadioType` |
| Channel bandwidth | Supported | `CFG_SetWifiBand` (`sub_3FF20`); the WTP has a 160M capability check; M60 `stBandwidth` |
| Channel / auto channel | Supported | `CFG_SetWifiChannel`, private element `0xfdf9`; 0 = auto |
| DCS | Partial equivalent | AP side `optimize/ACS` (`CAPWAP_setOptimizeChannel`, `CWWTP_DOOptimize`, `/var/optimize`), AC side triggered by `CWOptimizeApNetWork`; **no** AC100-style period/utilization/tolerance parameters |
| Online client steering | Partial equivalent | The closest is band navigation (`0xfe31`, `CFG_SetWifiLbd`, `uiBandAuth`) and roaming, not load-based steering |
| Check period | Not found | No corresponding configuration item in the binaries |
| Channel utilization threshold | Not found | Only reports utilization (`0xfe20`, `chutil`); no threshold parameter |
| Tolerance factor | Not found | — |
| Tx power | Supported | `CFG_SetWifiPower`, `0xfdfa`; M60 `pRtkPowerScale` / `iBasicTxpower` |
| Airtime scheduling | Not found | No WMM/airtime-like symbols |
| WMM | Not found | No switch entry point; presumably always on |
| Client limit | **Per SSID only** | `CFG_SetWifiSsidClientNum` / record +116 / `WLAN_SSID_CLIENTNUM`, max 32; no per-radio limit |
| Wireless client admission | Equivalent | `CFG_SetWifiForbidden`, `ForbiddenRssi`, `join_rssi` |
| RSSI threshold | Supported | `CFG_SetWifiForbiddenRssi`, `CFG_SetWifiRoamingRssi`, `uiRoamingThd` |
| Difference threshold | Not found | No corresponding "difference" concept |
| Weak signal restriction | Supported | forbidden join (the admission side of `uiRoamingKickEn`) |
| Weak signal kick-out | Supported | `iwpriv … kickmac`, `uiRoamingKickEn` |
| (Extra capabilities) | OFDMA / MU-MIMO / 802.11r / fixed rate / 5G compatibility | `0xfe28`, `CFG_SetWifi11R`, `stFixRate`, `CFG_SetWifi5ComptEnable` |

"Not found" only means no configuration path was found in these binaries; it does not mean the hardware cannot support it. The M60 web UI was not part of this evidence gathering.

## 3. The subset that is common to both vendors

- Radio enable, channel (auto/fixed), tx power, radio mode, channel bandwidth.
- Maximum clients per SSID (H3C ≤32, TP-Link via WLAN parameters/u16; same semantics, different range).
- SSID broadcast/isolation/VLAN/security (already implemented).
- Weak-signal admission/kick-out, roaming RSSI threshold (explicitly supported by H3C; TP-Link's page has corresponding items too).
- Band steering (H3C `0xfe31`; whether TP-Link's "online client steering" is the same mechanism is unconfirmed).

Only TP-Link explicitly exposes: WMM, Airtime, DCS period/utilization/tolerance parameters, per-radio client limit, difference threshold.

Only H3C explicitly exposes: OFDMA, MU-MIMO, 802.11r, fixed rate, 160MHz.

## 4. Remaining gaps

The common subset from section 3 is now wired end to end for both vendors: `H3cRadioHeader` drives enable/power/mode/bandwidth/channel in the H3C `0xfde8` sections, and TP-Link carries power in RFC 5416 element 1041, plus mode/bandwidth in private record 8, next to the `0x0404` channel record. What is still missing:

1. **Per-radio client limit**: only the per-SSID `client_count` exists (H3C ≤32, TP-Link u16); the page's per-radio 1–100 limit has no model field, API or UI. Reusing the per-SSID field would cause semantic confusion.
2. **WMM / Airtime / DCS parameters**: no DB, API or UI fields; DCS is still limited to "channel = auto", without period/utilization/tolerance settings.
3. **Signal and roaming thresholds**: `roaming.rs` only holds an 802.11k/v/r policy model, has no RSSI or difference threshold, and no call sites. H3C's forbidden/roaming RSSI + `kickmac` are not wired in, and TP-Link's admission/weak-signal items are not modeled either.
4. **Capability gating outside the mode list**: radio modes are already greyed out per device capability (`mode_mask_24/5` in the device DTO), but WMM, Airtime, DCS parameters and the per-radio client limit have no capability bits to gate on.

## 5. Follow-up proposals (not coded)

- Keep the per-SSID client count as is; model the per-radio "client limit" separately and only expose it where the capability table allows (TP-Link).
- Model signal/roaming as a per-band parameter group (admission threshold, kick-out threshold, difference); H3C maps to forbidden/roaming RSSI + kickmac, TP-Link maps to admission/weak-signal items.
- Treat WMM, Airtime and DCS parameters as TP-Link-only extensions, attached to the existing `product_caps` limits/capability bits, and show them in the frontend according to device capability.
