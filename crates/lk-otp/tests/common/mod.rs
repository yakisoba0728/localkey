//! Host-side helpers written from the public host libraries' documented behaviour:
//! - configuration bytes as yubikit `_build_config` / ykpers `struct config_st` build
//!   them (`fixed.ljust(16) || uid || key || acc || len(fixed), ext, tkt, cfg || rfu ||
//!   ~crc16 LE`);
//! - HID frames as yubikit `OtpProtocol.send_and_receive` / `_send_frame` /
//!   `_read_frame` and ykpers `yk_write_to_key` handle them.

#![allow(dead_code, clippy::unwrap_used)]

use lk_core::{Host, Outcome};
use lk_otp::{MgmtBridge, Otp, OtpHid, crc16};
use lk_testkit::TestHost;

pub const ENTER: u8 = 0x20; // TKTFLAG_APPEND_CR
pub const ALLOW_UPDATE: u8 = 0x20;
pub const SERIAL_API_VISIBLE: u8 = 0x04;

/// Configuration bytes (yubikit `_build_config`).
pub fn config_bytes(
    fixed: &[u8],
    uid: &[u8; 6],
    key: &[u8; 16],
    acc: &[u8; 6],
    ext: u8,
    tkt: u8,
    cfg: u8,
) -> Vec<u8> {
    assert!(fixed.len() <= 16);
    let mut buf = fixed.to_vec();
    buf.resize(16, 0);
    buf.extend_from_slice(uid);
    buf.extend_from_slice(key);
    buf.extend_from_slice(acc);
    buf.extend_from_slice(&[fixed.len() as u8, ext, tkt, cfg, 0, 0]);
    let crc = !crc16(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    assert_eq!(buf.len(), 52);
    buf
}

/// `config || current access code` (yubikit `_write_config`).
pub fn write_payload(config: &[u8], current_acc: Option<&[u8; 6]>) -> Vec<u8> {
    let mut out = config.to_vec();
    out.extend_from_slice(current_acc.unwrap_or(&[0; 6]));
    out
}

/// A Yubico OTP slot like yubikit `YubiOtpSlotConfiguration(fixed, uid, key)`
/// (keyboard defaults: SERIAL_API_VISIBLE | ALLOW_UPDATE, APPEND_CR, FAST_TRIG).
pub fn yubico_otp_config(fixed: &[u8], uid: &[u8; 6], key: &[u8; 16], acc: &[u8; 6]) -> Vec<u8> {
    config_bytes(
        fixed,
        uid,
        key,
        acc,
        SERIAL_API_VISIBLE | ALLOW_UPDATE | 0x10,
        ENTER,
        0,
    )
}

/// An HMAC-SHA1 challenge-response slot like yubikit `HmacSha1SlotConfiguration`:
/// key[..16] in `key`, key[16..20] in `uid`; TKTFLAG_CHAL_RESP, CFGFLAG_CHAL_HMAC |
/// CFGFLAG_HMAC_LT64 (and CHAL_BTN_TRIG when `touch`).
pub fn hmac_config(secret: &[u8], touch: bool, lt64: bool) -> Vec<u8> {
    let mut padded = secret.to_vec();
    padded.resize(20, 0);
    let key: [u8; 16] = padded[..16].try_into().unwrap();
    let mut uid = [0u8; 6];
    uid[..4].copy_from_slice(&padded[16..20]);
    let cfg = 0x22 | if lt64 { 0x04 } else { 0 } | if touch { 0x08 } else { 0 };
    config_bytes(
        &[],
        &uid,
        &key,
        &[0; 6],
        SERIAL_API_VISIBLE | ALLOW_UPDATE,
        0x40,
        cfg,
    )
}

/// An OATH-HOTP slot like yubikit `HotpSlotConfiguration(key)` with `imf` and an
/// optional token id.
pub fn hotp_config(
    secret: &[u8; 20],
    digits8: bool,
    imf: u32,
    token_id: &[u8],
    id_flags: u8,
) -> Vec<u8> {
    let key: [u8; 16] = secret[..16].try_into().unwrap();
    let mut uid = [0u8; 6];
    uid[..4].copy_from_slice(&secret[16..20]);
    uid[4..].copy_from_slice(&((imf / 16) as u16).to_be_bytes());
    let cfg = if digits8 { 0x02 } else { 0 } | id_flags;
    config_bytes(
        token_id,
        &uid,
        &key,
        &[0; 6],
        SERIAL_API_VISIBLE | ALLOW_UPDATE | 0x10,
        0x40 | ENTER,
        cfg,
    )
}

/// The reference HMAC-SHA1 challenge padding: pad with a byte different from the
/// last challenge byte (yubikit `calculate_hmac_sha1`).
pub fn pad_challenge(challenge: &[u8]) -> Vec<u8> {
    let pad = if challenge.last() == Some(&0) { 1 } else { 0 };
    let mut out = challenge.to_vec();
    out.resize(64, pad);
    out
}

/// A device under test: the shared slots, the HID framer and a host.
pub struct Device {
    pub otp: Otp,
    pub hid: OtpHid,
    pub host: TestHost,
    pub mgmt: Option<FakeMgmt>,
}

impl Device {
    pub fn new() -> Self {
        let mut host = TestHost::new();
        let otp = Otp::new(None, &mut host);
        Self {
            otp,
            hid: OtpHid::new(),
            host,
            mgmt: None,
        }
    }

    /// Rebuild the applet from what it last persisted (a restart).
    pub fn restart(&mut self) {
        let stored = self.host.persisted(lk_core::Record::Otp);
        self.otp = Otp::new(stored.as_deref(), &mut self.host);
        self.hid = OtpHid::new();
    }

    pub fn set(&mut self, report: [u8; 8]) -> Outcome<()> {
        let mgmt = self.mgmt.as_mut().map(|m| m as &mut dyn MgmtBridge);
        self.hid
            .set_feature(&report, &mut self.otp, mgmt, &mut self.host)
    }

    pub fn get(&mut self) -> [u8; 8] {
        let now = self.host.now();
        self.hid.get_feature_at(&self.otp, now)
    }

    /// yubikit `read_status`: bytes 1..7 of a feature report.
    pub fn read_status(&mut self) -> [u8; 6] {
        let r = self.get();
        r[1..7].try_into().unwrap()
    }

    /// yubikit `_send_frame` (all-zero middle chunks skipped, ready check before each).
    /// Returns the outcome of the last report written.
    pub fn send_frame(&mut self, slot: u8, data: &[u8]) -> Outcome<()> {
        let frame = build_frame(slot, data);
        let mut outcome = Outcome::Done(());
        for (seq, chunk) in frame.chunks(7).enumerate() {
            if seq == 0 || seq == 9 || chunk.iter().any(|&b| b != 0) {
                // _await_ready_to_write: the write flag must be clear.
                assert_eq!(self.get()[7] & 0x80, 0, "device busy");
                let mut report = [0u8; 8];
                report[..7].copy_from_slice(chunk);
                report[7] = 0x80 | seq as u8;
                outcome = self.set(report);
            }
        }
        outcome
    }

    /// yubikit `_read_frame` without sleeping. `Err` carries the reason a real host
    /// would raise.
    pub fn read_frame(&mut self, programming_seq: u8) -> Result<Vec<u8>, &'static str> {
        let mut response = Vec::new();
        let mut seq = 0u8;
        for _ in 0..100 {
            let report = self.get();
            let status = report[7];
            if status & 0x40 != 0 {
                if seq == status & 0x1F {
                    response.extend_from_slice(&report[..7]);
                    seq += 1;
                } else if status & 0x1F == 0 {
                    self.reset_state();
                    return Ok(response);
                }
            } else if status == 0 {
                let next = report[4];
                if !response.is_empty() {
                    return Err("incomplete transfer");
                } else if next == programming_seq.wrapping_add(1)
                    || (programming_seq > 0 && next == 0 && report[5] & 0x03 == 0)
                {
                    return Ok(report[1..7].to_vec());
                } else {
                    return Err("no data");
                }
            } else {
                return Err("waiting for touch");
            }
        }
        Err("never completed")
    }

    /// yubikit `_reset_state`.
    pub fn reset_state(&mut self) {
        self.set([0, 0, 0, 0, 0, 0, 0, 0xFF]);
    }

    /// yubikit `send_and_receive`.
    pub fn send_and_receive(&mut self, slot: u8, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let programming_seq = self.read_status()[3];
        match self.send_frame(slot, data) {
            Outcome::Done(()) => self.read_frame(programming_seq),
            Outcome::NeedTouch { .. } => Err("waiting for touch"),
        }
    }

    /// A slot read with CRC check (yubikit `_YubiOtpOtpBackend.send_and_receive`).
    pub fn read_checked(
        &mut self,
        slot: u8,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let response = self.send_and_receive(slot, data)?;
        let framed = response.get(..expected_len + 2).ok_or("short response")?;
        if crc16(framed) != 0xF0B8 {
            return Err("invalid crc");
        }
        Ok(response[..expected_len].to_vec())
    }

    /// A configuration write that a host checks with the programming sequence.
    pub fn write(&mut self, slot: u8, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.send_and_receive(slot, payload)
    }

    pub fn button(&mut self, press: lk_otp::Press) -> String {
        let reports = self.otp.button(press, &mut self.host);
        lk_otp::decode_reports(&reports)
    }
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

/// `payload(64) || slot || crc16(payload) LE || filler(3)` (ykdef.h `YKFRAME`).
pub fn build_frame(slot: u8, data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 64);
    let mut payload = data.to_vec();
    payload.resize(64, 0);
    let crc = crc16(&payload);
    let mut frame = payload;
    frame.push(slot);
    frame.extend_from_slice(&crc.to_le_bytes());
    frame.extend_from_slice(&[0, 0, 0]);
    assert_eq!(frame.len(), 70);
    frame
}

/// A Management stand-in.
#[derive(Debug, Default)]
pub struct FakeMgmt {
    pub serial: Option<u32>,
    pub info: Vec<u8>,
    pub written: Vec<Vec<u8>>,
    pub legacy: Vec<Vec<u8>>,
    pub reject: Option<u16>,
    pub timeout_s: u8,
}

impl MgmtBridge for FakeMgmt {
    fn serial(&mut self, _host: &mut dyn Host) -> Option<u32> {
        self.serial
    }

    fn device_info(&mut self, page: u8, _host: &mut dyn Host) -> Option<Vec<u8>> {
        (page == 0).then(|| self.info.clone())
    }

    fn write_device_info(&mut self, data: &[u8], _host: &mut dyn Host) -> Result<(), u16> {
        if let Some(sw) = self.reject {
            return Err(sw);
        }
        self.written.push(data.to_vec());
        Ok(())
    }

    fn write_device_config(&mut self, data: &[u8], _host: &mut dyn Host) -> Result<(), u16> {
        if let Some(sw) = self.reject {
            return Err(sw);
        }
        self.legacy.push(data.to_vec());
        Ok(())
    }

    fn challenge_response_timeout_s(&self) -> u8 {
        if self.timeout_s == 0 {
            15
        } else {
            self.timeout_s
        }
    }
}

/// HMAC-SHA1 test helper (independent computation via lk-crypto).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    lk_crypto::hmac_sha1(key, data)
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
