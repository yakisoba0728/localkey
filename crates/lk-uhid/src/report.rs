//! The report-number rule: how report data from `/dev/uhid` maps to the engine's 64-byte
//! FIDO reports and 8-byte OTP feature reports, and back (`docs/PROGRAM.md` "lk-uhid",
//! Report ID prefix; the crate docs record the sources).
//!
//! The engine's report descriptors declare no Report ID item, so every report is report
//! number 0 and `UHID_START` carries no `UHID_DEV_NUMBERED_*` flag. The kernel's own report
//! paths then add no prefix (`Documentation/hid/uhid.rst`), but hidraw passes the caller's
//! buffer through verbatim, report number byte included (`drivers/hid/hidraw.c`,
//! `drivers/hid/uhid.c`). Until a real kernel confirms which form arrives, both are
//! accepted: the bare report, or the report behind a leading report number 0.

/// Size of a CTAPHID report (`lk_device::Input::FidoReport`).
pub const FIDO_REPORT_SIZE: usize = 64;
/// Size of the OTP feature report (`lk_device::Input::OtpSetFeature`).
pub const OTP_FEATURE_SIZE: usize = 8;
/// Size of the OTP boot-keyboard input report (`lk_device::Output::OtpKeyboard`).
pub const OTP_KEYBOARD_SIZE: usize = 8;
/// The report number of every report of the engine's descriptors: they declare no Report
/// ID, and hidraw's convention for such a device is 0 (`Documentation/hid/hidraw.rst`;
/// `hidraw_get_report`'s comment in `drivers/hid/hidraw.c`).
pub const UNNUMBERED: u8 = 0;

/// The report of `N` bytes in `data`: exactly `N` bytes, or `N + 1` bytes behind a leading
/// report number 0. The reason names what was wrong.
fn unprefixed<const N: usize>(data: &[u8]) -> Result<[u8; N], &'static str> {
    let report = match data {
        [UNNUMBERED, rest @ ..] if rest.len() == N => rest,
        [_, rest @ ..] if rest.len() == N => return Err("the byte before the report is not report number 0"),
        _ if data.len() == N => data,
        _ => return Err("wrong report size"),
    };
    let mut out = [0; N];
    out.copy_from_slice(report);
    Ok(out)
}

/// The CTAPHID report in the data of a `UHID_OUTPUT` (64 bytes, or 65 with a leading 0).
pub fn fido_output(data: &[u8]) -> Result<[u8; FIDO_REPORT_SIZE], &'static str> {
    unprefixed(data)
}

/// The CTAPHID report in a `UHID_SET_REPORT` of an output report (report number 0; 64
/// bytes, or 65 with a leading 0). hidraw only takes this path when the device has no
/// interrupt OUT path (`hidraw_send_report`), which a UHID device always has; accepted for
/// the gadget's equivalent (`docs/PROGRAM.md` "lk-gadget": FIDO SET_REPORT(output)).
pub fn fido_set_output(rnum: u8, data: &[u8]) -> Result<[u8; FIDO_REPORT_SIZE], &'static str> {
    if rnum != UNNUMBERED {
        return Err("report number is not 0");
    }
    unprefixed(data)
}

/// The OTP feature report in a `UHID_SET_REPORT` of a feature report (report number 0; 8
/// bytes, or 9 with a leading 0 as `HIDIOCSFEATURE` passes it).
pub fn otp_feature_set(rnum: u8, data: &[u8]) -> Result<[u8; OTP_FEATURE_SIZE], &'static str> {
    if rnum != UNNUMBERED {
        return Err("report number is not 0");
    }
    unprefixed(data)
}

/// The data of the `UHID_GET_REPORT_REPLY` for a feature report: the report number, then
/// the 8 bytes. `hidraw_get_report` copies the reply verbatim from offset 0 to the caller,
/// who expects the report number in byte 0 and the report from byte 1, as usbhid returns it
/// (`usbhid_get_raw_report` in `drivers/hid/usbhid/hid-core.c`).
pub fn otp_feature_reply(report: &[u8; OTP_FEATURE_SIZE]) -> [u8; OTP_FEATURE_SIZE + 1] {
    let mut out = [UNNUMBERED; OTP_FEATURE_SIZE + 1];
    out[1..].copy_from_slice(report);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(len: usize) -> Vec<u8> {
        (1..=len).map(|byte| byte as u8).collect()
    }

    #[test]
    fn a_64_byte_output_is_the_fido_report() {
        let data = report(64);
        assert_eq!(fido_output(&data).map(|r| r.to_vec()), Ok(data));
        let zeros = vec![0; 64];
        assert_eq!(fido_output(&zeros), Ok([0; 64]), "a 64-byte report may start with 0");
    }

    #[test]
    fn a_65_byte_output_with_a_leading_zero_loses_the_report_number() {
        let mut data = vec![0];
        data.extend(report(64));
        assert_eq!(fido_output(&data).map(|r| r.to_vec()), Ok(report(64)));
    }

    #[test]
    fn a_65_byte_output_with_a_non_zero_first_byte_is_refused() {
        for first in [1, 0x86, 0xFF] {
            let mut data = vec![first];
            data.extend(report(64));
            assert!(fido_output(&data).is_err(), "{first:#x}");
        }
    }

    #[test]
    fn other_output_sizes_are_refused() {
        for len in [0, 1, 8, 63, 66, 128, 4096] {
            assert_eq!(fido_output(&vec![0; len]), Err("wrong report size"), "{len}");
        }
    }

    #[test]
    fn feature_set_takes_8_bytes_or_9_with_a_leading_zero() {
        assert_eq!(otp_feature_set(0, &report(8)).map(|r| r.to_vec()), Ok(report(8)));
        let mut data = vec![0];
        data.extend(report(8));
        assert_eq!(otp_feature_set(0, &data).map(|r| r.to_vec()), Ok(report(8)));
    }

    #[test]
    fn feature_set_refuses_other_sizes_prefixes_and_report_numbers() {
        let mut prefixed = vec![2];
        prefixed.extend(report(8));
        assert!(otp_feature_set(0, &prefixed).is_err());
        for len in [0, 7, 10, 64] {
            assert!(otp_feature_set(0, &vec![0; len]).is_err(), "{len}");
        }
        assert_eq!(otp_feature_set(1, &report(8)), Err("report number is not 0"));
    }

    #[test]
    fn fido_set_output_follows_the_output_rule_for_report_number_zero() {
        assert_eq!(fido_set_output(0, &report(64)).map(|r| r.to_vec()), Ok(report(64)));
        let mut data = vec![0];
        data.extend(report(64));
        assert_eq!(fido_set_output(0, &data).map(|r| r.to_vec()), Ok(report(64)));
        assert!(fido_set_output(3, &report(64)).is_err());
        assert!(fido_set_output(0, &report(10)).is_err());
    }

    #[test]
    fn the_feature_reply_is_the_report_number_then_the_report() {
        let reply = otp_feature_reply(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(reply, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
