//! The persisted device configuration and the transport-independent READ CONFIG /
//! WRITE CONFIG logic (yubikit-python `yubikit/management.py`: `DeviceConfig`,
//! `DeviceInfo`, `ManagementSession.write_device_config` / `read_device_info`).

use std::fmt;

use lk_codec::apdu::sw;
use lk_codec::tlv;
use lk_core::{Capabilities, DeviceProfile, Host, Record};
use lk_crypto::ct_eq;

use crate::info::{self, InfoFields, PAGE_LIMIT, tag};

/// Length of the configuration lock code (YubiKey 5 Series Technical Manual,
/// "Configuration lock"; yubikit-python `write_device_config` rejects other lengths).
pub const LOCK_CODE_LEN: usize = 16;

/// The challenge-response touch timeout a host-visible value of `0` stands for.
///
/// Model policy: the YubiKey documentation gives 15 seconds as the default touch wait
/// for OTP challenge-response; DeviceInfo reports the configured byte, which is `0`
/// ("use the default") on a fresh device. See [`Management::challenge_response_timeout_secs`].
pub const DEFAULT_CHALRESP_TIMEOUT_SECS: u8 = 15;

/// Version byte of the persisted record (`docs/CONTRACTS.md`, "Persisted state").
const FORMAT_VERSION: u8 = 0x01;

/// Device flag bits (yubikit-python `yubikit/management.py`, `DEVICE_FLAG`).
pub mod device_flags {
    /// The device may wake the host from USB suspend.
    pub const REMOTE_WAKEUP: u8 = 0x40;
    /// Touch ejects/inserts the smart card (CCID "touch eject").
    pub const EJECT: u8 = 0x80;
    /// Every flag the engine accepts on write.
    pub const ALL: u8 = REMOTE_WAKEUP | EJECT;
}

/// Field tags of the private persisted format (not host-visible).
mod field {
    pub const USB_ENABLED: u32 = 0x01;
    pub const AUTO_EJECT_TIMEOUT: u32 = 0x02;
    pub const CHALRESP_TIMEOUT: u32 = 0x03;
    pub const DEVICE_FLAGS: u32 = 0x04;
    pub const LOCK_CODE: u32 = 0x05;
}

/// What the device must do after a successful WRITE CONFIG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigEffect {
    /// Nothing; new settings apply as described on [`Management::enabled_usb`].
    None,
    /// The command carried the `REBOOT` tag (`0x0C`): after sending the response the
    /// device reboots, which re-enumerates USB with the enabled interfaces.
    Reboot,
}

/// The persisted configuration.
#[derive(Clone, PartialEq, Eq)]
struct Config {
    usb_enabled: u16,
    auto_eject_timeout: u16,
    chalresp_timeout: u8,
    device_flags: u8,
    /// All zero when no lock code is set.
    lock_code: [u8; LOCK_CODE_LEN],
    /// Unknown fields of a newer record, kept and written back unchanged
    /// (`docs/DESIGN.md` §7).
    unknown: Vec<u8>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("usb_enabled", &format_args!("{:#06x}", self.usb_enabled))
            .field("auto_eject_timeout", &self.auto_eject_timeout)
            .field("chalresp_timeout", &self.chalresp_timeout)
            .field("device_flags", &format_args!("{:#04x}", self.device_flags))
            .field("locked", &self.is_locked())
            .field("unknown_len", &self.unknown.len())
            .finish()
    }
}

impl Config {
    /// Factory state: the profile's default applications, zero timeouts and flags, no
    /// lock code.
    fn factory(profile: &DeviceProfile) -> Self {
        Self {
            usb_enabled: default_enabled(profile),
            auto_eject_timeout: 0,
            chalresp_timeout: 0,
            device_flags: 0,
            lock_code: [0; LOCK_CODE_LEN],
            unknown: Vec::new(),
        }
    }

    fn is_locked(&self) -> bool {
        self.lock_code.iter().any(|&b| b != 0)
    }

    /// `0x01 || TLV fields`, unknown fields last.
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        tlv::encode_into(
            &mut out,
            field::USB_ENABLED,
            &self.usb_enabled.to_be_bytes(),
        );
        tlv::encode_into(
            &mut out,
            field::AUTO_EJECT_TIMEOUT,
            &self.auto_eject_timeout.to_be_bytes(),
        );
        tlv::encode_into(&mut out, field::CHALRESP_TIMEOUT, &[self.chalresp_timeout]);
        tlv::encode_into(&mut out, field::DEVICE_FLAGS, &[self.device_flags]);
        tlv::encode_into(&mut out, field::LOCK_CODE, &self.lock_code);
        out.extend_from_slice(&self.unknown);
        out
    }

    /// Parse a stored record; `None` if it is unreadable (wrong version, malformed
    /// TLV, a known field with the wrong length, or a known field twice).
    fn decode(bytes: &[u8], profile: &DeviceProfile) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let mut config = Self::factory(profile);
        let mut seen = [false; 6];
        for item in tlv::parse_all(body).ok()? {
            let slot = match item.tag {
                field::USB_ENABLED => {
                    config.usb_enabled = u16::from_be_bytes(item.value.try_into().ok()?);
                    1
                }
                field::AUTO_EJECT_TIMEOUT => {
                    config.auto_eject_timeout = u16::from_be_bytes(item.value.try_into().ok()?);
                    2
                }
                field::CHALRESP_TIMEOUT => {
                    let [v] = <[u8; 1]>::try_from(item.value).ok()?;
                    config.chalresp_timeout = v;
                    3
                }
                field::DEVICE_FLAGS => {
                    let [v] = <[u8; 1]>::try_from(item.value).ok()?;
                    config.device_flags = v;
                    4
                }
                field::LOCK_CODE => {
                    config.lock_code = item.value.try_into().ok()?;
                    5
                }
                _ => {
                    config.unknown.extend_from_slice(item.raw);
                    0
                }
            };
            if slot != 0 {
                let flag = seen.get_mut(slot)?;
                if *flag {
                    return None;
                }
                *flag = true;
            }
        }
        Some(config)
    }
}

/// Capabilities this engine can expose on this profile: the profile's supported set
/// limited to the applications that exist ([`Capabilities::ALL`]).
fn supported(profile: &DeviceProfile) -> u16 {
    profile.supported_usb.0 & Capabilities::ALL.0
}

/// The profile's default enabled set, limited to [`supported`]; the whole supported
/// set if that leaves nothing.
fn default_enabled(profile: &DeviceProfile) -> u16 {
    let supported = supported(profile);
    match profile.default_enabled_usb.0 & supported {
        0 => supported,
        bits => bits,
    }
}

/// A WRITE CONFIG request after structural parsing (tags known, none repeated).
#[derive(Default)]
struct Request<'a> {
    reboot: bool,
    unlock: Option<&'a [u8]>,
    usb_enabled: Option<&'a [u8]>,
    auto_eject_timeout: Option<&'a [u8]>,
    chalresp_timeout: Option<&'a [u8]>,
    device_flags: Option<&'a [u8]>,
    new_lock_code: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// Parse the TLV list of a WRITE CONFIG (yubikit-python `DeviceConfig.get_bytes`).
    ///
    /// Model policy: a malformed list, a tag that is not writable on this USB-only
    /// device (read-only DeviceInfo tags, the NFC tags `0E`/`17`, unknown tags) and a
    /// repeated tag are all `6A80`.
    fn parse(body: &'a [u8]) -> Result<Self, u16> {
        let items = tlv::parse_all(body).map_err(|_| sw::INCORRECT_DATA)?;
        let mut req = Request::default();
        let mut reboot_seen = false;
        for item in items {
            let slot = match item.tag {
                tag::REBOOT => {
                    if reboot_seen {
                        return Err(sw::INCORRECT_DATA);
                    }
                    reboot_seen = true;
                    req.reboot = true;
                    continue;
                }
                tag::UNLOCK => &mut req.unlock,
                tag::USB_ENABLED => &mut req.usb_enabled,
                tag::AUTO_EJECT_TIMEOUT => &mut req.auto_eject_timeout,
                tag::CHALRESP_TIMEOUT => &mut req.chalresp_timeout,
                tag::DEVICE_FLAGS => &mut req.device_flags,
                tag::CONFIG_LOCK => &mut req.new_lock_code,
                _ => return Err(sw::INCORRECT_DATA),
            };
            if slot.replace(item.value).is_some() {
                return Err(sw::INCORRECT_DATA);
            }
        }
        Ok(req)
    }
}

/// A big-endian unsigned field of exactly `N` bytes.
fn exact<const N: usize>(value: &[u8]) -> Result<[u8; N], u16> {
    value.try_into().map_err(|_| sw::INCORRECT_DATA)
}

/// The Management application state shared by its three transports.
#[derive(Debug, Clone)]
pub struct Management {
    config: Config,
}

impl Management {
    /// Restore from `stored`, the plaintext last passed to `host.persist(Record::Device, ..)`.
    ///
    /// The record is `0x01` followed by BER-TLV fields (`docs/CONTRACTS.md`, "Persisted
    /// state"): `01` USB enabled (2 bytes), `02` auto-eject timeout (2), `03`
    /// challenge-response timeout (1), `04` device flags (1), `05` lock code (16).
    /// Unknown fields are kept and written back. `None` or an unreadable record gives
    /// the factory state: the profile's default applications, zero timeouts and flags,
    /// no lock code.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let profile = host.profile();
        let config = stored
            .and_then(|bytes| Config::decode(bytes, profile))
            .unwrap_or_else(|| Config::factory(profile));
        Self { config }
    }

    /// The serialized state, as last persisted (or as it would be persisted).
    pub fn to_record(&self) -> Vec<u8> {
        self.config.encode()
    }

    /// The device serial number (DeviceInfo tag `02`; also the OTP HID serial slot).
    pub fn serial(&self, host: &dyn Host) -> u32 {
        host.profile().serial
    }

    /// Capabilities supported over USB (DeviceInfo tag `01`).
    pub fn supported_usb(&self, host: &dyn Host) -> Capabilities {
        Capabilities(supported(host.profile()))
    }

    /// Capabilities enabled over USB (DeviceInfo tag `03`), limited to the supported set.
    ///
    /// This is the configured value: a WRITE CONFIG changes it at once, and DeviceInfo
    /// reports it from then on. The USB interfaces follow it when the device next
    /// enumerates: after a [`ConfigEffect::Reboot`], a power cycle, or (`lk-device`'s
    /// choice, `settle_management`) right after a write that changes the interface
    /// set. yubikit-python writes such changes with `REBOOT` (ykman `config usb` sets
    /// `reboot` exactly when the interface set changes), except `set_mode`, which
    /// writes without it and has ykman tell the user to re-insert the key.
    pub fn enabled_usb(&self, host: &dyn Host) -> Capabilities {
        let profile = host.profile();
        Capabilities(match self.config.usb_enabled & supported(profile) {
            0 => default_enabled(profile),
            bits => bits,
        })
    }

    /// Auto-eject timeout in seconds (DeviceInfo tag `06`; `0` disables it).
    pub fn auto_eject_timeout(&self) -> u16 {
        self.config.auto_eject_timeout
    }

    /// Configured challenge-response touch timeout byte (DeviceInfo tag `07`).
    pub fn challenge_response_timeout(&self) -> u8 {
        self.config.chalresp_timeout
    }

    /// Effective challenge-response touch timeout in seconds: the configured value, or
    /// [`DEFAULT_CHALRESP_TIMEOUT_SECS`] when it is `0`.
    pub fn challenge_response_timeout_secs(&self) -> u8 {
        match self.config.chalresp_timeout {
            0 => DEFAULT_CHALRESP_TIMEOUT_SECS,
            secs => secs,
        }
    }

    /// Device flags (DeviceInfo tag `08`; see [`device_flags`]).
    pub fn device_flags(&self) -> u8 {
        self.config.device_flags
    }

    /// Whether a configuration lock code is set (DeviceInfo tag `0A`).
    pub fn is_locked(&self) -> bool {
        self.config.is_locked()
    }

    fn info_fields(&self, host: &dyn Host) -> InfoFields {
        let profile = host.profile();
        InfoFields {
            usb_supported: supported(profile),
            serial: profile.serial,
            usb_enabled: self.enabled_usb(host).0,
            form_factor: profile.form_factor,
            version: profile.firmware.bytes(),
            auto_eject_timeout: self.config.auto_eject_timeout,
            chalresp_timeout: self.config.chalresp_timeout,
            device_flags: self.config.device_flags,
            locked: self.config.is_locked(),
        }
    }

    /// The complete DeviceInfo as one BER-TLV list, without the length prefix or
    /// paging (tag order and values: [`crate::tag`]).
    pub fn device_info(&self, host: &dyn Host) -> Vec<u8> {
        info::encode_items(&self.info_fields(host)).concat()
    }

    /// The bare TLVs of DeviceInfo page `page` (no length byte, no CRC), or `None`
    /// past the last page.
    ///
    /// This is the form `lk_otp::MgmtBridge::device_info` expects: `lk-otp` adds the
    /// length byte itself and its HID layer appends the OTP CRC (yubikit-python
    /// `_ManagementOtpBackend.read_config` checks `check_crc` over `len || TLVs ||
    /// CRC`). Every page but the last ends with `MORE_DATA` (`10 01 01`); see
    /// [`crate::PAGE_LIMIT`].
    pub fn device_info_page(&self, page: u8, host: &dyn Host) -> Option<Vec<u8>> {
        self.page_with_limit(page, PAGE_LIMIT, host)
    }

    fn page_with_limit(&self, page: u8, limit: usize, host: &dyn Host) -> Option<Vec<u8>> {
        let items = info::encode_items(&self.info_fields(host));
        info::paginate(&items, usize::from(page), limit)
    }

    /// One READ CONFIG page: `len || TLVs` (yubikit-python `read_device_info`, which
    /// checks `len(encoded) - 1 == encoded[0]`), as CCID INS `1D` and CTAPHID `0x42`
    /// answer it.
    ///
    /// Every page but the last ends with `MORE_DATA` (`10 01 01`); see
    /// [`crate::PAGE_LIMIT`]. A page past the last is `6A86` (model policy: the host
    /// only asks for a further page after `MORE_DATA`).
    pub fn read_config(&self, page: u8, host: &dyn Host) -> Result<Vec<u8>, u16> {
        self.read_config_with_limit(page, PAGE_LIMIT, host)
    }

    /// [`Management::read_config`] with an explicit page size, so the paging of the
    /// real DeviceInfo can be tested although it fits one page at [`PAGE_LIMIT`].
    pub(crate) fn read_config_with_limit(
        &self,
        page: u8,
        limit: usize,
        host: &dyn Host,
    ) -> Result<Vec<u8>, u16> {
        let tlvs = self
            .page_with_limit(page, limit, host)
            .ok_or(sw::INCORRECT_P1P2)?;
        let len = u8::try_from(tlvs.len()).map_err(|_| sw::UNKNOWN)?;
        let mut out = Vec::with_capacity(1 + tlvs.len());
        out.push(len);
        out.extend_from_slice(&tlvs);
        Ok(out)
    }

    /// The YubiKey 4 SET MODE command (CCID INS `16` P1 `11`, CTAPHID `0x40`, OTP slot
    /// `0x11`; data `mode, chalresp timeout, auto-eject timeout (2 bytes, little
    /// endian)`, yubikit-python `ManagementSession.set_mode`): not implemented, always
    /// `6D00`.
    ///
    /// yubikit-python's `set_mode` on firmware 5.0.0 and later never sends this
    /// command; it builds a WRITE CONFIG instead (`write_device_config`). How 5.7.4
    /// firmware itself maps a legacy mode byte to capabilities is undocumented, so the
    /// engine does not guess (`docs/catalog/mgmt.md`, deferred). The method exists so
    /// that every transport answers SET MODE the same way: `lk-device` uses it for
    /// `lk_otp::MgmtBridge::write_device_config`, and the CCID view uses it for INS
    /// `16`. Nothing changes and nothing is persisted.
    pub fn legacy_set_mode(
        &mut self,
        _data: &[u8],
        _host: &mut dyn Host,
    ) -> Result<ConfigEffect, u16> {
        Err(sw::INS_NOT_SUPPORTED)
    }

    /// WRITE CONFIG with the data exactly as the host sends it on CCID and CTAPHID:
    /// `len || TLVs`, where `len` must equal the number of TLV bytes
    /// (yubikit-python `DeviceConfig.get_bytes` prepends the length byte).
    ///
    /// Errors are ISO 7816-4 status words: `6700` no data; `6A80` a wrong length byte or
    /// a request rejected by [`Management::write_config_tlvs`]; `6982` lock code
    /// missing or wrong; `6581` storage failure.
    pub fn write_config(&mut self, data: &[u8], host: &mut dyn Host) -> Result<ConfigEffect, u16> {
        let (&len, body) = data.split_first().ok_or(sw::WRONG_LENGTH)?;
        if usize::from(len) != body.len() {
            return Err(sw::INCORRECT_DATA);
        }
        self.write_config_tlvs(body, host)
    }

    /// WRITE CONFIG from a zero-padded buffer (the 64-byte OTP HID slot data): the
    /// length byte selects the TLVs and the bytes after them are ignored.
    pub fn write_config_padded(
        &mut self,
        data: &[u8],
        host: &mut dyn Host,
    ) -> Result<ConfigEffect, u16> {
        let (&len, rest) = data.split_first().ok_or(sw::WRONG_LENGTH)?;
        let body = rest.get(..usize::from(len)).ok_or(sw::INCORRECT_DATA)?;
        self.write_config_tlvs(body, host)
    }

    /// Apply a WRITE CONFIG TLV list (no length prefix).
    ///
    /// Order of checks:
    /// 1. Structure: a malformed TLV list, a tag that is not writable on this USB-only
    ///    device (read-only DeviceInfo tags, the NFC tags `0E`/`17`, unknown tags) or a
    ///    repeated tag is `6A80`.
    /// 2. Configuration lock (YubiKey 5 Series Technical Manual, "Configuration
    ///    lock"): while a lock code is set, every WRITE CONFIG must carry the current
    ///    code in tag `0B`, compared in constant time; a `0B` sent while unlocked must
    ///    be the all-zero code. Otherwise `6982`. Model policy: a request carrying only
    ///    `REBOOT` is no exception, and there is no retry counter (none is documented;
    ///    the code is 128 bits).
    /// 3. Values: `03` exactly 2 bytes, non-zero (at least one application stays
    ///    enabled) and within the supported set; `06` 2 bytes; `07` 1 byte; `08` 1 byte
    ///    with only [`device_flags::ALL`] bits; `0A` 16 bytes (all zero clears the
    ///    lock). Otherwise `6A80`. The value of `0C` is ignored.
    /// 4. If the configuration changes, it is persisted in [`Record::Device`] before
    ///    success; on failure the previous state stays and the answer is `6581`
    ///    (`docs/CONTRACTS.md`). A request that changes nothing (only `REBOOT`, or the
    ///    current values) is not persisted.
    ///
    /// Returns [`ConfigEffect::Reboot`] when `0C` is present, even if nothing changed.
    pub fn write_config_tlvs(
        &mut self,
        body: &[u8],
        host: &mut dyn Host,
    ) -> Result<ConfigEffect, u16> {
        let req = Request::parse(body)?;

        if self.config.is_locked() || req.unlock.is_some() {
            let supplied = req.unlock.unwrap_or(&[]);
            if !ct_eq(supplied, &self.config.lock_code) {
                return Err(sw::SECURITY_STATUS);
            }
        }

        let mut next = self.config.clone();
        if let Some(value) = req.usb_enabled {
            let bits = u16::from_be_bytes(exact::<2>(value)?);
            if bits == 0 || bits & !supported(host.profile()) != 0 {
                return Err(sw::INCORRECT_DATA);
            }
            next.usb_enabled = bits;
        }
        if let Some(value) = req.auto_eject_timeout {
            next.auto_eject_timeout = u16::from_be_bytes(exact::<2>(value)?);
        }
        if let Some(value) = req.chalresp_timeout {
            let [secs] = exact::<1>(value)?;
            next.chalresp_timeout = secs;
        }
        if let Some(value) = req.device_flags {
            let [flags] = exact::<1>(value)?;
            if flags & !device_flags::ALL != 0 {
                return Err(sw::INCORRECT_DATA);
            }
            next.device_flags = flags;
        }
        if let Some(value) = req.new_lock_code {
            next.lock_code = exact::<LOCK_CODE_LEN>(value)?;
        }

        if next != self.config {
            host.persist(Record::Device, &next.encode())
                .map_err(|_| sw::MEMORY_FAILURE)?;
            self.config = next;
        }
        Ok(if req.reboot {
            ConfigEffect::Reboot
        } else {
            ConfigEffect::None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_testkit::TestHost;

    #[test]
    fn record_round_trips_and_keeps_unknown_fields() {
        let mut host = TestHost::new();
        // docs/CONTRACTS.md "Persisted state": version 0x01 + BER-TLV; unknown fields
        // are skipped (and, per docs/DESIGN.md §7, preserved).
        let mut stored = vec![0x01, 0x01, 0x02, 0x02, 0x00, 0x7E, 0x01, 0xAA];
        stored.extend_from_slice(&[0x03, 0x01, 0x1E]);
        let m = Management::new(Some(&stored), &mut host);
        assert_eq!(m.enabled_usb(&host).0, 0x0200);
        assert_eq!(m.challenge_response_timeout(), 30);
        let record = m.to_record();
        assert!(record.ends_with(&[0x7E, 0x01, 0xAA]));
        let again = Management::new(Some(&record), &mut host);
        assert_eq!(again.to_record(), record);
    }

    #[test]
    fn unreadable_records_give_factory_state() {
        let mut host = TestHost::new();
        let factory = Management::new(None, &mut host).to_record();
        let bad: [&[u8]; 7] = [
            &[],
            &[0x02],
            &[0x01, 0x01],
            &[0x01, 0x01, 0x01, 0x02],
            &[0x01, 0x05, 0x01, 0x01],
            &[0x01, 0x03, 0x01, 0x01, 0x03, 0x01, 0x02],
            &[0x01, 0x01, 0x80],
        ];
        for b in bad {
            assert_eq!(
                Management::new(Some(b), &mut host).to_record(),
                factory,
                "{b:02x?}"
            );
        }
    }

    /// The TLVs of every page from 0 until `read_config_with_limit` refuses, each
    /// checked against yubikit-python `read_device_info`: `len || TLVs` with
    /// `len(encoded) - 1 == encoded[0]`, `MORE_DATA` (`10 01 01`) last on every page
    /// but the last and nowhere else.
    fn pages(m: &Management, limit: usize, host: &TestHost) -> Vec<Vec<u8>> {
        let mut pages = Vec::new();
        for page in 0..=u8::MAX {
            let Ok(encoded) = m.read_config_with_limit(page, limit, host) else {
                assert_eq!(
                    m.read_config_with_limit(page, limit, host),
                    Err(sw::INCORRECT_P1P2)
                );
                break;
            };
            let (&len, tlvs) = encoded.split_first().expect("length byte");
            assert_eq!(usize::from(len), tlvs.len(), "page {page}");
            assert_eq!(m.page_with_limit(page, limit, host).as_deref(), Some(tlvs));
            pages.push(tlvs.to_vec());
        }
        let last = pages.len().saturating_sub(1);
        for (i, page) in pages.iter().enumerate() {
            let items = tlv::parse_all(page).expect("page parses");
            let more: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, t)| t.tag == tag::MORE_DATA)
                .map(|(j, _)| j)
                .collect();
            if i == last {
                assert!(more.is_empty(), "last page {i} has MORE_DATA");
            } else {
                assert_eq!(more, vec![items.len() - 1], "page {i}");
                assert!(page.ends_with(&[0x10, 0x01, 0x01]));
            }
        }
        pages
    }

    fn merged(pages: &[Vec<u8>]) -> Vec<u8> {
        pages
            .iter()
            .flat_map(|p| {
                tlv::parse_all(p)
                    .expect("page parses")
                    .into_iter()
                    .filter(|t| t.tag != tag::MORE_DATA)
                    .flat_map(|t| t.raw.to_vec())
                    .collect::<Vec<u8>>()
            })
            .collect()
    }

    // Source: yubikit-python `ManagementSession.read_device_info` asks for the next
    // page (P1 / payload byte) while a page carries MORE_DATA = 01 and merges the TLVs
    // of all pages. The real DeviceInfo (50 bytes) fits one page at PAGE_LIMIT, so
    // the split is exercised with smaller page sizes.
    #[test]
    fn real_device_info_pages_at_small_limits() {
        let mut host = TestHost::new();
        let m = Management::new(None, &mut host);
        let info = m.device_info(&host);
        assert_eq!(info.len(), 50);

        // At the engine's limit: one page, the whole info, page 1 refused.
        assert_eq!(pages(&m, PAGE_LIMIT, &host), vec![info.clone()]);
        assert_eq!(m.device_info_page(0, &host), Some(info.clone()));
        assert_eq!(m.device_info_page(1, &host), None);

        // A 20-byte page (17 bytes of objects before MORE_DATA): page 0 holds
        // 01 02 03 04 (17 bytes) + 10 01 01, page 1 holds 05 06 07 08 (15 bytes) +
        // 10 01 01, and page 2 holds the remaining 0A 14 15 16 18 (18 bytes, no
        // marker).
        let p = pages(&m, 20, &host);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].len(), 20);
        assert_eq!(p[0].get(..17), info.get(..17));
        assert_eq!(p[1].len(), 18);
        assert_eq!(p[1].get(..15), info.get(17..32));
        assert_eq!(p[2], info.get(32..).expect("tail").to_vec());
        assert_eq!(
            m.read_config_with_limit(3, 20, &host),
            Err(sw::INCORRECT_P1P2)
        );
        // A 30-byte page: 26 bytes (01..06) + marker, then the last 24 bytes fit.
        let p = pages(&m, 30, &host);
        assert_eq!(p.len(), 2);
        assert_eq!(p[1], info.get(26..).expect("tail").to_vec());

        // Every limit that holds the largest object (6 bytes) plus MORE_DATA: no page
        // exceeds the limit and the merged pages give the DeviceInfo back.
        for limit in 9..=60 {
            let p = pages(&m, limit, &host);
            assert!(p.iter().all(|page| page.len() <= limit), "limit {limit}");
            assert_eq!(merged(&p), info, "limit {limit}");
        }
    }

    #[test]
    fn legacy_set_mode_is_refused_without_change() {
        // yubikit-python `set_mode` data for YubiKey 4: struct.pack("<BBH", mode,
        // chalresp_timeout, auto_eject_timeout); mode 0x06 = OTP+FIDO+CCID, 0x81 =
        // CCID with touch eject.
        let mut host = TestHost::new();
        let mut m = Management::new(None, &mut host);
        let before = m.to_record();
        for data in [
            &[0x06, 0x00, 0x00, 0x00][..],
            &[0x81, 0x0F, 0x2C, 0x01],
            &[],
        ] {
            assert_eq!(
                m.legacy_set_mode(data, &mut host),
                Err(sw::INS_NOT_SUPPORTED)
            );
        }
        assert_eq!(m.to_record(), before);
        assert_eq!(host.persist_attempts(), 0);
    }

    #[test]
    fn debug_does_not_print_lock_code() {
        let mut host = TestHost::new();
        let mut m = Management::new(None, &mut host);
        let mut body = vec![0x0A, 0x10];
        body.extend_from_slice(&[0xC7; 16]);
        assert_eq!(
            m.write_config_tlvs(&body, &mut host),
            Ok(ConfigEffect::None)
        );
        let text = format!("{m:?}");
        assert!(text.contains("locked: true"));
        assert!(!text.to_lowercase().contains("c7"));
        assert!(!text.contains("199"));
    }
}
