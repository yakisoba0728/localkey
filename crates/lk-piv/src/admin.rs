//! Card management key authentication (SP 800-73-4 Part 2 §3.2.4 and Appendix A) and
//! the Yubico PIV extension commands of firmware 5.7: SET MANAGEMENT KEY (`FF`), SET PIN
//! RETRIES (`FA`), RESET (`FB`), GET VERSION (`FD`), GET SERIAL (`F8`) and GET METADATA
//! (`F7`) ("Yubico PIV extensions" in the YubiKey 5 technical manual and the Yubico PIV
//! command reference).

use lk_codec::apdu::{Command, sw};
use lk_codec::tlv;
use lk_core::Host;
use lk_crypto::{SecretBytes, aes_ecb_encrypt_block, ct_eq, tdes_ecb_encrypt_block};

use crate::asym::slot_metadata;
use crate::keys::Operation;
use crate::pin::{KEY_PIN, KEY_PUK};
use crate::state::{
    Credential, DEFAULT_MGMT_KEY, DEFAULT_PIN, DEFAULT_PUK, MgmtAlg, MgmtKey, PivState, is_key_slot,
};
use crate::{Piv, Reply, Step, explicit_le};

/// Key reference of the card management key (SP 800-73-4 Part 1 Table 4).
pub(crate) const KEY_MGMT: u8 = 0x9B;
/// Key references of the primary and secondary finger on-card biometric comparison
/// (SP 800-73-4 Part 1 Table 4); not held by this card.
const KEY_OCC_PRIMARY: u8 = 0x96;
const KEY_OCC_SECONDARY: u8 = 0x97;

/// Dynamic Authentication Template and its elements (SP 800-73-4 Part 2 Table 7).
const TAG_DYN_AUTH: u32 = 0x7C;
const TAG_WITNESS: u32 = 0x80;
const TAG_CHALLENGE: u32 = 0x81;
const TAG_RESPONSE: u32 = 0x82;

/// GET METADATA tags (Yubico PIV command reference, "GET METADATA").
const MD_ALGORITHM: u32 = 0x01;
const MD_POLICY: u32 = 0x02;
const MD_DEFAULT: u32 = 0x05;
const MD_RETRIES: u32 = 0x06;
/// Algorithm value reported for the PIN and PUK.
const MD_ALG_PIN: u8 = 0xFF;
/// Policy byte values (Yubico PIV documentation, "PIN and touch policies").
const PIN_POLICY_DEFAULT: u8 = 0x00;
const TOUCH_POLICY_NEVER: u8 = 0x01;
const TOUCH_POLICY_ALWAYS: u8 = 0x02;

/// SET MANAGEMENT KEY P2: touch not required / required.
const P2_NO_TOUCH: u8 = 0xFF;
const P2_TOUCH: u8 = 0xFE;

/// The open step of a management key authentication, consumed by the next command.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Challenge {
    /// Mutual authentication: the card sent `E(K, witness)` and expects `witness` back.
    /// The witness proves knowledge of the key, so it is wiped when dropped.
    Mutual { witness: SecretBytes },
    /// External authentication: the card sent `challenge` and expects `E(K, challenge)`.
    External { challenge: Vec<u8> },
}

/// A command finished cryptographically but waiting for a touch.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PendingTouch {
    /// Management key authentication succeeded; on touch the card becomes
    /// authenticated and answers `response` (served in pieces of `max` bytes).
    MgmtAuth { response: Vec<u8>, max: usize },
    /// A checked slot key operation; on touch it runs and answers (`asym`).
    SlotOperation { slot: u8, op: Operation, input: Vec<u8>, max: usize },
}

/// Encrypt one block with the management key (3DES per SP 800-67, AES per FIPS 197).
fn encrypt_block(mgmt: &MgmtKey, block: &[u8]) -> Result<Vec<u8>, u16> {
    match mgmt.alg {
        MgmtAlg::Tdes => tdes_ecb_encrypt_block(&mgmt.key, block).map(|b| b.to_vec()),
        _ => aes_ecb_encrypt_block(&mgmt.key, block).map(|b| b.to_vec()),
    }
    .map_err(|_| sw::UNKNOWN)
}

impl Piv {
    /// GENERAL AUTHENTICATE (`INS 87`, SP 800-73-4 Part 2 §3.2.4): the card management
    /// key (P2 `9B`) here, slot keys in `asym::slot_authenticate`.
    ///
    /// Le may be present or absent (Part 2 §3.2.4 "Le: Absent or '00'"; the Appendix A.2
    /// and A.4.2 examples send `00`, and hosts such as OpenSC send other values).
    ///
    /// `armed` is the PIN-always authorization from before this command; a management key
    /// authentication drops it, a slot operation may use or keep it (`asym`).
    pub(crate) fn general_authenticate(
        &mut self,
        cmd: &Command,
        pending: Option<Challenge>,
        armed: bool,
        host: &mut dyn Host,
        max: usize,
    ) -> Step {
        let result = if cmd.p2 == KEY_MGMT {
            self.authenticate_management(cmd, pending, host, max)
        } else {
            self.slot_authenticate(cmd, armed, host, max)
        };
        match result {
            Ok(step) => step,
            Err(sw) => Step::Reply(Err(sw)),
        }
    }

    /// Management key authentication, SP 800-73-4 Part 2 Appendix A (A.1 external
    /// authentication by challenge-response, A.2 mutual authentication); block length
    /// 8 for 3DES, 16 for AES.
    ///
    /// | Request (inside `7C`) | Answer |
    /// | --- | --- |
    /// | `80 00` | `7C { 80 E(K, W) }`, W random (mutual, step 1) |
    /// | `80 W' 81 C [82 00]` | W' = W: `7C { 82 E(K, C) }` (mutual, step 2) |
    /// | `81 00` | `7C { 81 C }`, C random (external, step 1) |
    /// | `82 R` | R = E(K, C): `9000` (external, step 2) |
    ///
    /// The empty `82` in mutual step 2 requests the response (Table 7: empty tags "can be
    /// seen as requests"); SP 800-73-4 Part 2 Table 19 sends it (`7C 16 80 08 .. 81 08 ..
    /// 82 00`), Yubico's tools leave it out, and both forms are accepted.
    ///
    /// P1 must be the stored key's algorithm (`6A86`; model policy, the physical status
    /// is unmeasured). Malformed templates and a second step without its first are
    /// `6A80`; a wrong witness or response is `6982`. Either failure leaves the card
    /// unauthenticated. With the touch flag set (SET MANAGEMENT KEY P2 `FE`), the
    /// completing step waits for a touch and finishes in `touch_resolved`.
    fn authenticate_management(
        &mut self,
        cmd: &Command,
        pending: Option<Challenge>,
        host: &mut dyn Host,
        max: usize,
    ) -> Result<Step, u16> {
        let alg = MgmtAlg::from_byte(cmd.p1).ok_or(sw::INCORRECT_P1P2)?;
        if alg != self.state.mgmt.alg {
            return Err(sw::INCORRECT_P1P2);
        }
        let (template, rest) = tlv::parse_one(&cmd.data).map_err(|_| sw::INCORRECT_DATA)?;
        if template.tag != TAG_DYN_AUTH || !rest.is_empty() {
            return Err(sw::INCORRECT_DATA);
        }
        let items = template.children().map_err(|_| sw::INCORRECT_DATA)?;
        let block = alg.block_len();
        let shape: Vec<(u32, usize)> = items.iter().map(|t| (t.tag, t.value.len())).collect();
        match shape.as_slice() {
            [(TAG_WITNESS, 0)] => {
                let mut witness = SecretBytes::zeroed(block);
                host.fill(&mut witness);
                let encrypted = encrypt_block(&self.state.mgmt, &witness)?;
                self.session.challenge = Some(Challenge::Mutual { witness });
                Ok(Step::Reply(Ok(tlv::encode(TAG_DYN_AUTH, &tlv::encode(TAG_WITNESS, &encrypted)))))
            }
            [(TAG_CHALLENGE, 0)] => {
                let mut challenge = vec![0; block];
                host.fill(&mut challenge);
                let answer = tlv::encode(TAG_DYN_AUTH, &tlv::encode(TAG_CHALLENGE, &challenge));
                self.session.challenge = Some(Challenge::External { challenge });
                Ok(Step::Reply(Ok(answer)))
            }
            [(TAG_WITNESS, w), (TAG_CHALLENGE, c)] | [(TAG_WITNESS, w), (TAG_CHALLENGE, c), (TAG_RESPONSE, 0)]
                if *w == block && *c == block =>
            {
                let (witness, host_challenge) = match items.as_slice() {
                    [w, c, ..] => (w.value, c.value),
                    _ => return Err(sw::INCORRECT_DATA),
                };
                let Some(Challenge::Mutual { witness: expected }) = pending else {
                    return self.fail_management(sw::INCORRECT_DATA);
                };
                if !ct_eq(witness, &expected) {
                    return self.fail_management(sw::SECURITY_STATUS);
                }
                let encrypted = encrypt_block(&self.state.mgmt, host_challenge)?;
                let answer = tlv::encode(TAG_DYN_AUTH, &tlv::encode(TAG_RESPONSE, &encrypted));
                Ok(self.complete_management(answer, max))
            }
            [(TAG_RESPONSE, r)] if *r == block => {
                let response = items.first().map(|t| t.value).unwrap_or_default();
                let Some(Challenge::External { challenge }) = pending else {
                    return self.fail_management(sw::INCORRECT_DATA);
                };
                let expected = encrypt_block(&self.state.mgmt, &challenge)?;
                if !ct_eq(response, &expected) {
                    return self.fail_management(sw::SECURITY_STATUS);
                }
                Ok(self.complete_management(Vec::new(), max))
            }
            _ => Err(sw::INCORRECT_DATA),
        }
    }

    fn fail_management(&mut self, sw: u16) -> Result<Step, u16> {
        self.session.mgmt_authenticated = false;
        Err(sw)
    }

    /// Authentication verified: become authenticated now, or after a touch when the key
    /// requires one.
    fn complete_management(&mut self, answer: Vec<u8>, max: usize) -> Step {
        if self.state.mgmt.touch {
            self.session.touch = Some(PendingTouch::MgmtAuth { response: answer, max });
            Step::Touch
        } else {
            self.session.mgmt_authenticated = true;
            Step::Reply(Ok(answer))
        }
    }

    /// SET MANAGEMENT KEY (`INS FF`, Yubico extension): P1 `FF`, P2 `FF` (no touch) or
    /// `FE` (touch required), data `alg || 9B || len || key` with `alg` one of `03`,
    /// `08`, `0A`, `0C` and the matching key length (24, 16, 24, 32). Requires management
    /// key authentication. Header and Le are checked first (catalog "SET MANAGEMENT KEY
    /// P1/P2/Le are rejected before changing ... management key state"). Weak 3DES keys
    /// are not rejected (not documented for the device).
    pub(crate) fn set_management_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p1 != 0xFF {
            return Err(sw::INCORRECT_P1P2);
        }
        let touch = match cmd.p2 {
            P2_NO_TOUCH => false,
            P2_TOUCH => true,
            _ => return Err(sw::INCORRECT_P1P2),
        };
        if !self.session.mgmt_authenticated {
            return Err(sw::SECURITY_STATUS);
        }
        let (&alg, rest) = cmd.data.split_first().ok_or(sw::INCORRECT_DATA)?;
        let alg = MgmtAlg::from_byte(alg).ok_or(sw::INCORRECT_DATA)?;
        let key = match tlv::parse_all(rest).map_err(|_| sw::INCORRECT_DATA)?.as_slice() {
            [key] if key.tag == u32::from(KEY_MGMT) && key.value.len() == alg.key_len() => {
                SecretBytes::from_slice(key.value)
            }
            _ => return Err(sw::INCORRECT_DATA),
        };
        self.modify(host, |s| s.mgmt = MgmtKey { alg, key, touch })?;
        Ok(Vec::new())
    }

    /// SET PIN RETRIES (`INS FA`, Yubico extension): P1 = PIN retry limit, P2 = PUK
    /// retry limit, each 1..=255 (profile `retry_limits`). Requires management key
    /// authentication and a verified PIN. Per the Yubico documentation it also resets the
    /// PIN and PUK to their defaults; the PIN is no longer verified afterwards. Command
    /// data or an explicit Le (`crate::explicit_le`) is `6700` (catalog "Malformed SET PIN
    /// RETRIES Le ... rejected").
    pub(crate) fn set_pin_retries(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if explicit_le(cmd) || !cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p1 == 0 || cmd.p2 == 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        if !self.session.mgmt_authenticated || !self.session.pin_verified {
            return Err(sw::SECURITY_STATUS);
        }
        let (pin_max, puk_max) = (cmd.p1, cmd.p2);
        self.modify(host, |s| {
            s.pin = Credential::new(DEFAULT_PIN, pin_max);
            s.puk = Credential::new(DEFAULT_PUK, puk_max);
        })?;
        self.session.pin_verified = false;
        Ok(Vec::new())
    }

    /// RESET (`INS FB`, Yubico extension): only when both the PIN and the PUK are
    /// blocked (`6985` otherwise). P1-P2 must be `0000` (`6A86`), and command data or an
    /// explicit Le (`crate::explicit_le`; `00 FB 00 00 00` and `00 FB 00 00 00 00 00` are case 1) is
    /// `6700`; every check happens before anything is erased (catalog
    /// "Malformed PIV RESET P1/P2, command data, or explicit Le are rejected before
    /// erasing keys or retries"). Restores factory PIN, PUK, retry limits and management
    /// key and erases data objects and keys, except the attestation key and certificate.
    pub(crate) fn reset_applet(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        if !cmd.data.is_empty() || explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if !self.state.pin.blocked() || !self.state.puk.blocked() {
            return Err(sw::CONDITIONS);
        }
        let next = self.state.after_reset();
        self.commit(host, next)?;
        self.session.pin_verified = false;
        self.session.mgmt_authenticated = false;
        Ok(Vec::new())
    }

    /// GET VERSION (`INS FD`, Yubico extension): the firmware version, three bytes.
    pub(crate) fn get_version(&self, host: &dyn Host) -> Reply {
        Ok(host.profile().firmware.bytes().to_vec())
    }

    /// GET SERIAL (`INS F8`, Yubico extension): the serial number, four bytes big-endian.
    pub(crate) fn get_serial(&self, host: &dyn Host) -> Reply {
        Ok(host.profile().serial.to_be_bytes().to_vec())
    }

    /// GET METADATA (`INS F7`, Yubico extension, firmware 5.3 and later): P2 the
    /// reference; P1 is ignored, as GET VERSION and GET SERIAL ignore P1-P2. Measured on a
    /// YubiKey 5C Nano 5.7.4: `00 F7 01 9A` with slot `9A` empty answers `6A88`, the same
    /// as `00 F7 00 9A` (docs/MEASUREMENT.md, probe `bad-p1p2-piv`, which also shows GET
    /// VERSION with P1 `01` and GET SERIAL with P2 `01` answering `9000`). The empty slot
    /// cannot tell "P1 ignored" from "P1 other than `00` is `6A88`"; ignoring P1 for the
    /// other references (P1 `01` P2 `80` returns the PIN metadata) is that reading's
    /// extrapolation, unmeasured.
    ///
    /// - PIN `80` / PUK `81`: `01 FF` (algorithm), `05` default value flag, `06` retry
    ///   limit and retries remaining as full bytes (catalog "complete eight-bit metadata").
    /// - Management key `9B`: `01` algorithm, `02` PIN policy / touch policy, `05`
    ///   default value flag. The PIN policy byte is reported as `00`; the device's value
    ///   is not documented (model policy).
    /// - Key slots: `01` algorithm, `02` PIN and touch policy, `03` origin, `04` public key
    ///   (`asym::slot_metadata`); `6A88` while empty.
    /// - The on-card biometric comparison references `96` and `97` (SP 800-73-4 Part 1
    ///   Table 4), which only a YubiKey Bio holds: `6A88`. python yubikit's
    ///   `get_bio_metadata()` (called by `ykman piv info` and by `PivSession.reset()`)
    ///   treats only `6A88` and `6D00` as "no biometrics" and fails on anything else.
    /// - Anything else: `6A86`.
    pub(crate) fn get_metadata(&self, cmd: &Command) -> Reply {
        match cmd.p2 {
            KEY_PIN => Ok(credential_metadata(&self.state.pin, &DEFAULT_PIN)),
            KEY_PUK => Ok(credential_metadata(&self.state.puk, &DEFAULT_PUK)),
            KEY_MGMT => Ok(management_metadata(&self.state)),
            KEY_OCC_PRIMARY | KEY_OCC_SECONDARY => Err(sw::REF_NOT_FOUND),
            slot if is_key_slot(slot) => self.state.slots.get(&slot).map(slot_metadata).ok_or(sw::REF_NOT_FOUND),
            _ => Err(sw::INCORRECT_P1P2),
        }
    }
}

fn credential_metadata(cred: &Credential, default: &[u8; 8]) -> Vec<u8> {
    let mut out = tlv::encode(MD_ALGORITHM, &[MD_ALG_PIN]);
    tlv::encode_into(&mut out, MD_DEFAULT, &[u8::from(ct_eq(&cred.value, default))]);
    tlv::encode_into(&mut out, MD_RETRIES, &[cred.max, cred.remaining]);
    out
}

fn management_metadata(state: &PivState) -> Vec<u8> {
    let mgmt = &state.mgmt;
    let touch = if mgmt.touch { TOUCH_POLICY_ALWAYS } else { TOUCH_POLICY_NEVER };
    let mut out = tlv::encode(MD_ALGORITHM, &[mgmt.alg.byte()]);
    tlv::encode_into(&mut out, MD_POLICY, &[PIN_POLICY_DEFAULT, touch]);
    tlv::encode_into(&mut out, MD_DEFAULT, &[u8::from(ct_eq(&mgmt.key, &DEFAULT_MGMT_KEY))]);
    out
}
