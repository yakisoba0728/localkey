//! The applications the device owns, their identifiers on the card interface, and the
//! `lk_otp::MgmtBridge` implementation over `lk-mgmt`.

use lk_core::{CardApplet, Capabilities, Host, Record};
use lk_fido::Authenticator;
use lk_hsmauth::HsmAuth;
use lk_mgmt::{ConfigEffect, Management, MgmtApplet};
use lk_oath::Oath;
use lk_openpgp::OpenPgp;
use lk_otp::{MgmtBridge, OtpApplet};
use lk_piv::Piv;
use lk_sd::SecurityDomain;

use crate::host::{DeviceHost, Loaded, RECORDS};

/// Every application, each built from its own record (`docs/DESIGN.md` §7: one record
/// per application, so a failed write in one never rolls back another).
pub(crate) struct Apps {
    pub(crate) fido: Authenticator,
    pub(crate) mgmt: MgmtApplet,
    pub(crate) otp: OtpApplet,
    pub(crate) oath: Oath,
    pub(crate) piv: Piv,
    pub(crate) openpgp: OpenPgp,
    pub(crate) hsmauth: HsmAuth,
    pub(crate) sd: SecurityDomain,
}

impl Apps {
    /// Load every record and construct each application with `new(stored, host)`
    /// (`docs/CONTRACTS.md` "Application crates"). Returns the applications and the
    /// records that existed but could not be read; each of those applications starts
    /// from its factory state, the others from their stored state.
    pub(crate) fn open(host: &mut DeviceHost) -> (Self, Vec<Record>) {
        let mut unreadable = Vec::new();
        let mut stored = RECORDS.map(|record| match host.load(record) {
            Loaded::Opened(plaintext) => Some(plaintext),
            Loaded::Absent => None,
            Loaded::Unreadable => {
                unreadable.push(record);
                None
            }
        });
        let mut take = |record: Record| {
            RECORDS
                .iter()
                .position(|&r| r == record)
                .and_then(|i| stored.get_mut(i))
                .and_then(Option::take)
        };
        // Construction order follows `RECORDS`, which fixes the entropy each
        // constructor draws (SD and PIV/OpenPGP create their own keys on first start).
        // Constructors never overwrite an unreadable record, and a constructor save the
        // store rejects is retried later (`DeviceHost::begin_construction`).
        host.begin_construction(&unreadable);
        let mgmt = MgmtApplet::new(take(Record::Device).as_deref(), host);
        let fido = Authenticator::new(take(Record::Fido).as_deref(), host);
        let oath = Oath::new(take(Record::Oath).as_deref(), host);
        let otp = OtpApplet::new(take(Record::Otp).as_deref(), host);
        let piv = Piv::new(take(Record::Piv).as_deref(), host);
        let openpgp = OpenPgp::new(take(Record::OpenPgp).as_deref(), host);
        let hsmauth = HsmAuth::new(take(Record::HsmAuth).as_deref(), host);
        let sd = SecurityDomain::new(take(Record::SecurityDomain).as_deref(), host);
        host.end_construction();
        let apps = Self {
            fido,
            mgmt,
            otp,
            oath,
            piv,
            openpgp,
            hsmauth,
            sd,
        };
        (apps, unreadable)
    }

    /// The card applet behind `id`, through the common `CardApplet` contract.
    pub(crate) fn card(&mut self, id: AppId) -> &mut dyn CardApplet {
        match id {
            AppId::Management => &mut self.mgmt,
            AppId::Otp => &mut self.otp,
            AppId::Oath => &mut self.oath,
            AppId::Piv => &mut self.piv,
            AppId::OpenPgp => &mut self.openpgp,
            AppId::HsmAuth => &mut self.hsmauth,
            AppId::SecurityDomain => &mut self.sd,
        }
    }
}

/// The applications reachable on the CCID interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppId {
    Management,
    Otp,
    Oath,
    Piv,
    OpenPgp,
    HsmAuth,
    SecurityDomain,
}

impl AppId {
    pub(crate) const ALL: [AppId; 7] = [
        AppId::Management,
        AppId::Otp,
        AppId::Oath,
        AppId::Piv,
        AppId::OpenPgp,
        AppId::HsmAuth,
        AppId::SecurityDomain,
    ];

    /// The AID each applet answers to (`docs/CONTRACTS.md` "Application crates" table;
    /// the constants are the crates' own, and a unit test checks them against
    /// `CardApplet::aid`). PIV and OpenPGP are right-truncated AIDs (SP 800-73-4 Part 1
    /// §2.2; OpenPGP card 3.4.1 §4.2.1), so a SELECT naming the full AID still matches.
    pub(crate) fn aid(self) -> &'static [u8] {
        match self {
            AppId::Management => lk_mgmt::AID,
            AppId::Otp => &lk_otp::OTP_AID,
            AppId::Oath => lk_oath::AID,
            AppId::Piv => lk_piv::AID,
            AppId::OpenPgp => &lk_openpgp::AID_PREFIX,
            AppId::HsmAuth => lk_hsmauth::AID,
            AppId::SecurityDomain => lk_sd::AID,
        }
    }

    /// The Management capability bit that enables the application
    /// (`lk_core::Capabilities`). Management and the Security Domain have none and are
    /// always reachable while the CCID interface is enabled (they carry no capability
    /// in the YubiKey DeviceInfo).
    pub(crate) fn capability(self) -> Option<u16> {
        match self {
            AppId::Management | AppId::SecurityDomain => None,
            AppId::Otp => Some(Capabilities::OTP),
            AppId::Oath => Some(Capabilities::OATH),
            AppId::Piv => Some(Capabilities::PIV),
            AppId::OpenPgp => Some(Capabilities::OPENPGP),
            AppId::HsmAuth => Some(Capabilities::HSMAUTH),
        }
    }

    /// The command that fetches the rest of a `61xx` response: YKOATH SEND REMAINING
    /// (`A5`, YKOATH §SEND REMAINING) for OATH, ISO/IEC 7816-4 §7.6.1 GET RESPONSE
    /// (`C0`) for the others.
    pub(crate) fn continuation_ins(self) -> u8 {
        match self {
            AppId::Oath => lk_oath::ins::SEND_REMAINING,
            _ => 0xC0,
        }
    }
}

/// `lk_otp::MgmtBridge` over `lk-mgmt`, with the mapping `docs/CONTRACTS.md`
/// ("Applications A as implemented", `MgmtBridge` mapping) and the `lk-mgmt` transport
/// module fix:
///
/// | `MgmtBridge` | `lk-mgmt` |
/// | --- | --- |
/// | `serial` | `Some(Management::serial)` |
/// | `device_info(page)` | `Management::device_info_page` (bare TLVs) |
/// | `write_device_info(len \|\| TLVs)` | `Management::write_config`, keeping the `ConfigEffect` |
/// | `write_device_config` | `Management::legacy_set_mode` (always `6D00`) |
/// | `challenge_response_timeout_s` | `Management::challenge_response_timeout_secs` |
///
/// A returned [`ConfigEffect::Reboot`] is recorded so that the device reboots after the
/// slot command finishes ("lk-device must apply the returned `ConfigEffect` itself").
pub(crate) struct Bridge<'a> {
    mgmt: &'a mut Management,
    reboot: bool,
}

impl<'a> Bridge<'a> {
    pub(crate) fn new(mgmt: &'a mut Management) -> Self {
        Self { mgmt, reboot: false }
    }

    /// Whether a write through the bridge asked for a reboot.
    pub(crate) fn reboot_requested(&self) -> bool {
        self.reboot
    }

    fn record(&mut self, effect: ConfigEffect) {
        if effect == ConfigEffect::Reboot {
            self.reboot = true;
        }
    }
}

impl MgmtBridge for Bridge<'_> {
    fn serial(&mut self, host: &mut dyn Host) -> Option<u32> {
        Some(self.mgmt.serial(&*host))
    }

    fn device_info(&mut self, page: u8, host: &mut dyn Host) -> Option<Vec<u8>> {
        self.mgmt.device_info_page(page, &*host)
    }

    fn write_device_info(&mut self, data: &[u8], host: &mut dyn Host) -> Result<(), u16> {
        let effect = self.mgmt.write_config(data, host)?;
        self.record(effect);
        Ok(())
    }

    fn write_device_config(&mut self, data: &[u8], host: &mut dyn Host) -> Result<(), u16> {
        let effect = self.mgmt.legacy_set_mode(data, host)?;
        self.record(effect);
        Ok(())
    }

    fn challenge_response_timeout_s(&self) -> u8 {
        self.mgmt.challenge_response_timeout_secs()
    }
}
