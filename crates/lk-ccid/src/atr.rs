//! The interface bytes of an Answer-to-Reset (ISO/IEC 7816-3 §8.2.2–§8.2.3).
//!
//! Only what the T=1 parameter block needs is extracted. Parsing is lenient: a short
//! or malformed ATR simply yields fewer bytes, and the caller falls back to the
//! ISO/IEC 7816-3 defaults.

/// Interface bytes that determine the T=1 transmission parameters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InterfaceBytes {
    /// `TS` = `3F`: inverse convention (§8.1).
    pub inverse: bool,
    /// `TA1`: Fi (high nibble) and Di (low nibble) indices (§8.3).
    pub ta1: Option<u8>,
    /// `TC1`: extra guard time N (§8.3).
    pub tc1: Option<u8>,
    /// First `TAi` (i > 2) after a `TD(i-1)` announcing T=1: IFSC (§11.4.2).
    pub t1_ta: Option<u8>,
    /// First `TBi` (i > 2) for T=1: BWI and CWI (§11.4.3).
    pub t1_tb: Option<u8>,
    /// First `TCi` (i > 2) for T=1: error detection code, bit 0 set for CRC (§11.4.4).
    pub t1_tc: Option<u8>,
    /// First `TAi` (i > 2) for T=15: clock stop indicator in bits 8–7 (§8.3).
    pub t15_ta: Option<u8>,
}

/// Walk `TS`, `T0` and the `TAi`/`TBi`/`TCi`/`TDi` groups of `atr`.
pub(crate) fn interface_bytes(atr: &[u8]) -> InterfaceBytes {
    let mut out = InterfaceBytes {
        inverse: atr.first() == Some(&0x3F),
        ..Default::default()
    };
    let Some(&t0) = atr.get(1) else {
        return out;
    };
    let mut bytes = atr.iter().skip(2).copied();
    // Presence indicator of the current group, its index i, and the protocol T
    // announced by TD(i-1).
    let mut presence = t0 >> 4;
    let mut index = 1u32;
    let mut protocol: Option<u8> = None;
    loop {
        let mut next = |bit: u8| {
            if presence & bit != 0 {
                bytes.next()
            } else {
                None
            }
        };
        let (ta, tb, tc, td) = (next(0x1), next(0x2), next(0x4), next(0x8));
        match (index, protocol) {
            (1, _) => {
                out.ta1 = ta;
                out.tc1 = tc;
            }
            (2, _) => {}
            (_, Some(1)) => {
                out.t1_ta = out.t1_ta.or(ta);
                out.t1_tb = out.t1_tb.or(tb);
                out.t1_tc = out.t1_tc.or(tc);
            }
            (_, Some(15)) => out.t15_ta = out.t15_ta.or(ta),
            _ => {}
        }
        let Some(td) = td else {
            return out;
        };
        presence = td >> 4;
        protocol = Some(td & 0x0F);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compatibility-profile ATR given in the lk-ccid task; structure per ISO/IEC 7816-3 §8.2:
    /// TS 3B, T0 FD, TA1 13, TB1 00, TC1 00, TD1 81, TD2 31, TA3 FE, TB3 15,
    /// 13 historical bytes, TCK 40.
    const ATR: [u8; 23] = [
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57,
        0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
    ];

    #[test]
    fn compatibility_atr_interface_bytes() {
        let ib = interface_bytes(&ATR);
        assert_eq!(
            ib,
            InterfaceBytes {
                inverse: false,
                ta1: Some(0x13),
                tc1: Some(0x00),
                t1_ta: Some(0xFE),
                t1_tb: Some(0x15),
                t1_tc: None,
                t15_ta: None,
            }
        );
    }

    #[test]
    fn t15_global_bytes_and_inverse_convention() {
        // ISO/IEC 7816-3 §8.2.3: TS 3F (inverse); T0 80 (TD1 only, no historical bytes);
        // TD1 81 -> TD2 for T=1; TD2 B1 -> TA3, TB3, TD3 for T=1;
        // TD3 1F -> TA4 for T=15 with clock stop indicator 01 (state L).
        let atr = [0x3F, 0x80, 0x81, 0xB1, 0x20, 0x45, 0x1F, 0x43];
        let ib = interface_bytes(&atr);
        assert!(ib.inverse);
        assert_eq!(ib.ta1, None);
        assert_eq!(ib.t1_ta, Some(0x20));
        assert_eq!(ib.t1_tb, Some(0x45));
        assert_eq!(ib.t15_ta, Some(0x43));
    }

    #[test]
    fn truncated_atr_is_lenient() {
        assert_eq!(interface_bytes(&[]), InterfaceBytes::default());
        let ib = interface_bytes(&[0x3B, 0xF0, 0x11]);
        assert_eq!(ib.ta1, Some(0x11));
        assert_eq!(ib.tc1, None);
    }
}
