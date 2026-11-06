//! Normalized 802.11 radio mode shared by every vendor profile.
//!
//! Copyright (c) 2026  Wang Jian
//!
//! The DB, the REST API and the web UI keep one normalized mode per band; a
//! vendor's own selector code is never stored. The same small integer means
//! different things on different AC/AP generations: H3C sends `11` for
//! 11b/g/n and `8` for 11a/n, while TP-Link sends `6` for 11b/g/n and `8` for
//! 11ac. Each vendor module maps these values to its wire code and falls back
//! to the band default when a mode is not expressible.
//!
//! Values are stable and band-scoped: the UI offers only the modes the
//! selected band supports, and [`for_band`] rejects a mode from the other band.

/// Product default (the vendor chooses: AC100 sends 11b/g/n on 2.4 GHz and
/// 11a/n/ac on 5 GHz; H3C defaults to 11b/g/n and 11a/n).
pub const AUTO: u32 = 0;
/// 802.11a only (5 GHz).
pub const A: u32 = 1;
/// 802.11b only (2.4 GHz).
pub const B: u32 = 2;
/// 802.11g only (2.4 GHz).
pub const G: u32 = 3;
/// 802.11b/g (2.4 GHz).
pub const BG: u32 = 4;
/// 802.11n only (the band the radio is on).
pub const N: u32 = 5;
/// 802.11b/g/n (2.4 GHz).
pub const BGN: u32 = 6;
/// 802.11a/n (5 GHz).
pub const AN: u32 = 7;
/// 802.11ac only (5 GHz).
pub const AC: u32 = 8;
/// 802.11a/n/ac (5 GHz).
pub const ANAC: u32 = 9;
/// 802.11b/g/n/ax (2.4 GHz).
pub const BGNAX: u32 = 10;
/// 802.11a/n/ac/ax (5 GHz).
pub const ANACAX: u32 = 11;
/// 802.11b/g/n/ax/be (2.4 GHz).
pub const BGNAXBE: u32 = 12;
/// 802.11a/n/ac/ax/be (5 GHz).
pub const ANACAXBE: u32 = 13;

/// Whether `mode` can run on a 2.4 GHz radio.
pub fn supports_24(mode: u32) -> bool {
    matches!(mode, AUTO | B | G | BG | N | BGN | BGNAX | BGNAXBE)
}

/// Whether `mode` can run on a 5 GHz radio.
pub fn supports_5(mode: u32) -> bool {
    matches!(mode, AUTO | A | N | AN | AC | ANAC | ANACAX | ANACAXBE)
}

/// Whether `mode` exists on `band` (1 = 2.4 GHz, 2 = 5 GHz).
pub fn supports_band(band: u8, mode: u32) -> bool {
    if band == 2 {
        supports_5(mode)
    } else {
        supports_24(mode)
    }
}

/// Normalized mode checked against the band: an unknown value, or a mode that
/// only exists on the other band, becomes [`AUTO`]. This keeps a stale
/// cross-band value from being encoded as the wrong vendor selector.
pub fn for_band(band: u8, mode: u32) -> u32 {
    if supports_band(band, mode) {
        mode
    } else {
        AUTO
    }
}

/// Radio standards a catalogued product supports, as `(11ac, 11ax)`.
/// Uncatalogued products answer `(true, true)`, so the UI only greys a value
/// when the catalogue positively knows the radio cannot express it.
fn product_std(vendor: &str, model: &str) -> (bool, bool) {
    let vendor = vendor.trim().to_ascii_lowercase();
    let model = model.trim().to_ascii_uppercase();
    match vendor.as_str() {
        // Wi-Fi 5 (11ac) access point used as the TP-Link reference.
        "tp-link" | "tplink" if model.starts_with("TL-AP1300") => (true, false),
        // Wi-Fi 6 (11ax) AP; the reported model code is SWBA1B0.
        "h3c" if model.starts_with("SWBA1B0") || model.contains("AX60") => (true, true),
        _ => (true, true),
    }
}

/// Per-band capabilities of one product, as a bitmask where bit `N` set means
/// mode `N` is offered. Modes above the product's standard (11ax on a Wi-Fi 5
/// AP, 11ac on a 2.4 GHz-only part) stay clear so the web UI can grey them out.
pub fn device_mask(vendor: &str, model: &str, band: u8) -> u16 {
    let (ac, ax) = product_std(vendor, model);
    let mut mask = 0u16;
    for m in AUTO..=ANACAXBE {
        if !supports_band(band, m) {
            continue;
        }
        let ok = match m {
            BGNAX | BGNAXBE | ANACAX | ANACAXBE => ax,
            AC | ANAC => ac,
            _ => true,
        };
        if ok {
            mask |= 1 << m;
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_accept_only_their_own_modes() {
        assert!(supports_24(AUTO) && supports_5(AUTO));
        assert!(supports_24(BGNAXBE) && !supports_5(BGNAXBE));
        assert!(supports_5(ANACAXBE) && !supports_24(ANACAXBE));
        assert!(supports_24(N) && supports_5(N));
        assert!(!supports_24(A) && supports_5(A));
        assert!(!supports_5(B) && supports_24(B));
    }

    #[test]
    fn for_band_maps_cross_band_and_unknown_values_to_auto() {
        assert_eq!(for_band(1, BG), BG);
        assert_eq!(for_band(2, BG), AUTO);
        assert_eq!(for_band(1, AC), AUTO);
        assert_eq!(for_band(2, A), A);
        assert_eq!(for_band(1, 99), AUTO);
    }

    fn has(mask: u16, mode: u32) -> bool {
        mask & (1 << mode) != 0
    }

    #[test]
    fn device_mask_greys_out_standards_the_product_lacks() {
        // Wi-Fi 5 AP: 11ax modes are not offered on either band.
        let m24 = device_mask("tp-link", "TL-AP1300GI-PoE", 1);
        let m5 = device_mask("TP-Link", "tl-ap1300gi-poe", 2);
        assert!(has(m24, N) && has(m24, BGN));
        assert!(!has(m24, BGNAX) && !has(m24, BGNAXBE));
        assert!(has(m5, AC) && has(m5, ANAC));
        assert!(!has(m5, ANACAX) && !has(m5, ANACAXBE));
        // Wi-Fi 6 AP keeps the 11ax modes.
        let ax5 = device_mask("h3c", "SWBA1B0", 2);
        assert!(has(ax5, ANACAX) && has(ax5, ANACAXBE));
        // Uncatalogued products are not greyed beyond their band's limits.
        assert_eq!(device_mask("rfc", "unknown", 1), 0b1_0100_0111_1101);
        assert_eq!(device_mask("rfc", "unknown", 2), 0b10_1011_1010_0011);
    }
}
