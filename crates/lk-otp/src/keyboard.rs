//! Keyboard output: scan codes, the 45-entry scan map and boot-keyboard reports.
//!
//! - Reports are USB HID 1.11 Appendix B.1 boot-keyboard input reports:
//!   `[modifiers, reserved, key1..key6]`. Each character is a press report followed by
//!   an all-zero release report, so repeated characters are always distinct.
//! - Scan codes are HID Usage Tables 1.12 §10 (Keyboard/Keypad page) usage IDs; bit 7
//!   set means "with left shift" (modifier bit `0x02`), the convention of Yubico's
//!   published keyboard layouts (yubikit `ykman/scancodes`).
//! - The scan map is the 45-character table of ykpers `ykp_write_scan_map` /
//!   yubikit `set_scan_map`: modhex `cbdefghijklnrtuv`, the same in upper case,
//!   digits `0123456789`, then `!`, TAB and CR. Every generated character (modhex,
//!   digits, TAB, ENTER) is looked up there, so a host can remap the output layout.
//! - Pacing (`CFGFLAG_PACING_10MS/20MS`) and the 0.5 s delays (`TKTFLAG_APPEND_DELAYx`)
//!   are encoded as extra all-zero reports. The program sends one report per keyboard
//!   poll interval of [`REPORT_PERIOD_MS`]; it must deliver every report in order and
//!   may pause (backpressure) without the engine dropping anything.
//! - The reports of a static password (or a static ticket) are the secret itself, so
//!   the report buffer is allocated for the longest emission up front and never grows
//!   by `Vec` reallocation, which would free a copy unwiped (`docs/DESIGN.md` §8). The
//!   finished reports leave through lk-device's outputs and are the caller's.

use crate::config::FIXED_SIZE;

/// Number of entries in a scan map.
pub const SCAN_MAP_SIZE: usize = 45;
/// Bit 7 of a scan code: type the key with left shift.
pub const SHIFT: u8 = 0x80;
/// Nominal interval between two keyboard reports, used to encode pacing and delays.
pub const REPORT_PERIOD_MS: u64 = 10;
/// Index of the first upper-case modhex entry in the scan map.
pub const MAP_UPPER: usize = 16;
/// Index of digit `0` in the scan map.
pub const MAP_DIGITS: usize = 32;
/// Index of `!` in the scan map.
pub const MAP_BANG: usize = 42;
/// Index of TAB in the scan map.
pub const MAP_TAB: usize = 43;
/// Index of CR (ENTER) in the scan map.
pub const MAP_CR: usize = 44;

/// The `TKTFLAG_APPEND_DELAY1` / `TKTFLAG_APPEND_DELAY2` delay (`ykdef.h`: "add 0.5s
/// delay").
pub(crate) const APPEND_DELAY_MS: u64 = 500;

/// The most keys one emission types (layout of `Otp::emit`, `ykdef.h` ticket flags):
/// `TAB_FIRST`, `APPEND_TAB1`, `APPEND_TAB2` and `APPEND_CR` (4), the 16-character
/// reference string (`CFGFLAG_SEND_REF`), part 1 of at most two characters per byte of
/// the fixed part, and part 2 of at most 32 characters (a 16-byte ticket in modhex).
/// The other layouts type fewer: a static password 4 + 38 scan codes (no reference, no
/// part 2), OATH-HOTP 4 + 32 + 8 digits.
const MAX_KEYS: usize = 4 + 16 + 2 * FIXED_SIZE + 2 * 16;

/// The most idle time one emission adds: both append delays.
const MAX_DELAY_MS: u64 = 2 * APPEND_DELAY_MS;

/// Idle reports after each key for `pacing_ms` of `CFGFLAG_PACING_*`.
fn idle_reports(pacing_ms: u64) -> usize {
    usize::try_from(pacing_ms / REPORT_PERIOD_MS).unwrap_or(0)
}

/// The number of reports the longest emission with `pacing_ms` produces: per key a
/// press, a release and the pacing idles, plus the idle reports of both delays. A
/// [`Typist`] allocates this many up front.
pub(crate) fn emission_capacity(pacing_ms: u64) -> usize {
    let per_key = idle_reports(pacing_ms).saturating_add(2);
    let delays = usize::try_from(MAX_DELAY_MS / REPORT_PERIOD_MS).unwrap_or(0);
    MAX_KEYS.saturating_mul(per_key).saturating_add(delays)
}

/// The US-layout scan map for `cbdefghijklnrtuvCBDEFGHIJKLNRTUV0123456789!\t\r`
/// (HID usage IDs: a=0x04 .. z=0x1D, 1=0x1E .. 9=0x26, 0=0x27, ENTER=0x28, TAB=0x2B).
pub const DEFAULT_SCAN_MAP: [u8; SCAN_MAP_SIZE] = [
    0x06, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x15, 0x17, 0x18,
    0x19, // modhex
    0x86, 0x85, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x91, 0x95, 0x97, 0x98,
    0x99, // MODHEX
    0x27, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, // 0-9
    0x9E, // '!' (shift + 1)
    0x2B, // TAB
    0x28, // ENTER
];

/// Keypad usage IDs for digits 0..9 (HID Usage Tables §10: Keypad 1..9 = 0x59..0x61,
/// Keypad 0 = 0x62).
const KEYPAD_DIGITS: [u8; 10] = [0x62, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61];

/// The all-zero report: no key pressed.
pub const RELEASE: [u8; 8] = [0; 8];

/// The press report for one scan code.
pub fn press_report(scan_code: u8) -> [u8; 8] {
    let modifiers = if scan_code & SHIFT != 0 { 0x02 } else { 0x00 };
    [modifiers, 0, scan_code & !SHIFT, 0, 0, 0, 0, 0]
}

/// Accumulates the reports for one OTP emission, in a buffer allocated for the longest
/// emission ([`emission_capacity`]; module documentation).
pub(crate) struct Typist<'a> {
    map: &'a [u8; SCAN_MAP_SIZE],
    idle_after_key: usize,
    keypad_digits: bool,
    reports: Vec<[u8; 8]>,
}

impl<'a> Typist<'a> {
    pub(crate) fn new(map: &'a [u8; SCAN_MAP_SIZE], pacing_ms: u64, keypad_digits: bool) -> Self {
        Self::with_capacity(map, pacing_ms, keypad_digits, emission_capacity(pacing_ms))
    }

    fn with_capacity(
        map: &'a [u8; SCAN_MAP_SIZE],
        pacing_ms: u64,
        keypad_digits: bool,
        capacity: usize,
    ) -> Self {
        Self {
            map,
            idle_after_key: idle_reports(pacing_ms),
            keypad_digits,
            reports: Vec::with_capacity(capacity),
        }
    }

    /// Append one report. Should the buffer ever be full (the capacity is an upper
    /// bound, so only if the layout outgrows it), the reports move to a buffer twice
    /// the size and the old one is wiped before it is freed, instead of letting `Vec`
    /// free it unwiped.
    fn push(&mut self, report: [u8; 8]) {
        if self.reports.len() == self.reports.capacity() {
            let mut grown = Vec::with_capacity(self.reports.capacity().saturating_mul(2).max(16));
            grown.extend_from_slice(&self.reports);
            lk_crypto::wipe(self.reports.as_flattened_mut());
            self.reports = grown;
        }
        self.reports.push(report);
    }

    /// Type one scan code (zero means "nothing").
    pub(crate) fn scan(&mut self, code: u8) {
        if code == 0 {
            return;
        }
        self.push(press_report(code));
        self.push(RELEASE);
        for _ in 0..self.idle_after_key {
            self.push(RELEASE);
        }
    }

    /// Type the scan map entry `index`.
    pub(crate) fn mapped(&mut self, index: usize) {
        let code = self.map.get(index).copied().unwrap_or(0);
        self.scan(code);
    }

    /// Type one modhex character.
    pub(crate) fn modhex_nibble(&mut self, nibble: u8) {
        self.mapped(usize::from(nibble & 0x0F));
    }

    /// Type bytes as modhex, high nibble first.
    pub(crate) fn modhex(&mut self, data: &[u8]) {
        for &byte in data {
            self.modhex_nibble(byte >> 4);
            self.modhex_nibble(byte & 0x0F);
        }
    }

    /// Type a decimal digit (0..9) from the scan map or the numeric keypad.
    pub(crate) fn digit(&mut self, digit: u8) {
        let d = usize::from(digit % 10);
        if self.keypad_digits {
            self.scan(KEYPAD_DIGITS.get(d).copied().unwrap_or(0));
        } else {
            self.mapped(MAP_DIGITS + d);
        }
    }

    /// Type a byte as two "numeric" nibbles: digits for 0..9, modhex for 10..15.
    pub(crate) fn numeric_byte(&mut self, byte: u8) {
        for nibble in [byte >> 4, byte & 0x0F] {
            if nibble < 10 {
                self.digit(nibble);
            } else {
                self.modhex_nibble(nibble);
            }
        }
    }

    pub(crate) fn tab(&mut self) {
        self.mapped(MAP_TAB);
    }

    pub(crate) fn enter(&mut self) {
        self.mapped(MAP_CR);
    }

    /// Idle for `ms` (rounded down to whole report periods).
    pub(crate) fn delay(&mut self, ms: u64) {
        for _ in 0..ms / REPORT_PERIOD_MS {
            self.push(RELEASE);
        }
    }

    pub(crate) fn finish(self) -> Vec<[u8; 8]> {
        self.reports
    }
}

/// Decode reports produced with [`DEFAULT_SCAN_MAP`] back to text (test and tooling
/// helper). Characters outside the map's alphabet decode as `?`; idle reports are
/// skipped.
pub fn decode_reports(reports: &[[u8; 8]]) -> String {
    let mut out = String::new();
    for report in reports {
        if report == &RELEASE {
            continue;
        }
        let code = report[2] | if report[0] & 0x22 != 0 { SHIFT } else { 0 };
        out.push(char_for_scan(code));
    }
    out
}

fn char_for_scan(code: u8) -> char {
    const ALPHABET: &[u8; SCAN_MAP_SIZE] = b"cbdefghijklnrtuvCBDEFGHIJKLNRTUV0123456789!\t\n";
    if let Some(pos) = DEFAULT_SCAN_MAP.iter().position(|&c| c == code) {
        return ALPHABET.get(pos).map_or('?', |&b| char::from(b));
    }
    if let Some(pos) = KEYPAD_DIGITS.iter().position(|&c| c == code) {
        return char::from(b'0' + u8::try_from(pos).unwrap_or(0));
    }
    '?'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn press_and_release_for_shifted_and_plain_codes() {
        assert_eq!(press_report(0x06), [0, 0, 0x06, 0, 0, 0, 0, 0]);
        assert_eq!(press_report(0x86), [0x02, 0, 0x06, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn typist_encodes_modhex_digits_and_pacing() {
        let mut t = Typist::new(&DEFAULT_SCAN_MAP, 20, false);
        t.modhex(&[0x0f]);
        t.digit(7);
        let reports = t.finish();
        // Each key: press, release, two pacing idles.
        assert_eq!(reports.len(), 3 * 4);
        assert_eq!(reports[0], press_report(0x06));
        assert_eq!(reports[4], press_report(0x19));
        assert_eq!(reports[8], press_report(0x24));
        assert_eq!(decode_reports(&reports), "cv7");
    }

    #[test]
    fn a_typist_that_outgrows_its_buffer_keeps_every_report_in_order() {
        let mut t = Typist::with_capacity(&DEFAULT_SCAN_MAP, 10, false, 3);
        t.modhex(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        t.delay(APPEND_DELAY_MS);
        t.enter();
        let reports = t.finish();
        // 17 keys of press, release and one pacing idle, plus 50 idles of the delay.
        assert_eq!(reports.len(), 17 * 3 + 50);
        assert!(reports.capacity() >= reports.len());
        assert_eq!(decode_reports(&reports), "cbdefghijklnrtuv\n");
    }

    /// The bound is MAX_KEYS keys of press, release and pacing idles plus both 0.5 s
    /// delays; `otp::tests` checks that the longest real emission fills it exactly.
    #[test]
    fn emission_capacity_counts_keys_pacing_and_both_delays() {
        assert_eq!(MAX_KEYS, 84);
        assert_eq!(emission_capacity(0), 84 * 2 + 100);
        assert_eq!(emission_capacity(30), 84 * 5 + 100);
        assert_eq!(
            Typist::new(&DEFAULT_SCAN_MAP, 20, false).reports.capacity(),
            84 * 4 + 100
        );
    }

    #[test]
    fn keypad_digits_use_keypad_usages() {
        let mut t = Typist::new(&DEFAULT_SCAN_MAP, 0, true);
        t.digit(0);
        t.digit(1);
        let reports = t.finish();
        assert_eq!(reports[0][2], 0x62);
        assert_eq!(reports[2][2], 0x59);
        assert_eq!(decode_reports(&reports), "01");
    }
}
