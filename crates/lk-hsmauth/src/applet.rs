//! The YubiHSM Auth card application (`CardApplet`).
//!
//! Status words (see the crate docs for sources):
//!
//! | SW | Meaning |
//! | --- | --- |
//! | `9000` | success |
//! | `63Cx` | wrong management key or credential password, `x` tries left |
//! | `6581` | the state could not be stored; nothing changed |
//! | `6700` | malformed APDU; RESET with data or an explicit Le |
//! | `6982` | a touch-required CALCULATE was not touched (ykman "not touched"; ykhsmauth touch error; YESDK `RetryWithTouch`) |
//! | `6983` | PUT with an existing label; GET PUBLIC KEY of a symmetric credential (ykman; YESDK "label conflict" / "invalid entry") |
//! | `6984` | card cryptogram or receipt does not verify, or the context does not carry the outstanding ephemeral key (YESDK maps `ReferenceDataUnusable` `6984` to "invalid authentication data"; ykhsmauth `SW_DATA_INVALID`; the exact triggers are a model decision) |
//! | `6985` | model decision: GET RESPONSE with nothing pending; a touch with nothing waiting; touch confirmed after the credential vanished |
//! | `6A80` | malformed command data (ykhsmauth "invalid parameters") |
//! | `6A82` | no credential with that label |
//! | `6A84` | all 32 credential slots are in use |
//! | `6A86` | RESET without `P1 P2 = DE AD` |
//! | `6D00` | unknown instruction (including 5.8's CHANGE CREDENTIAL PASSWORD) |
//! | `6E00` | unsupported class |

use core::fmt;

use lk_codec::apdu::{Command, CommandChain, ResponseQueue, response, status, sw};
use lk_codec::tlv;
use lk_core::{CardApplet, Host, Outcome, Record, ResetKind};
use lk_crypto::{Curve, EcPrivateKey, ct_eq, ec_public_is_valid};

use crate::kdf::{SessionKeys, asymmetric_session_keys, card_cryptogram, symmetric_session_keys};
use crate::request::{Fields, fixed};
use crate::state::{Credential, Key, State, wipe};
use crate::{
    AID, CREDENTIAL_PASSWORD_LEN, MANAGEMENT_KEY_LEN, MAX_COMMAND_LEN, MAX_CREDENTIALS, RESET_P1P2, RETRIES,
    TOUCH_TIMEOUT_MS, alg, ins, tag,
};

/// CLA bits this application accepts: the chaining bit (ISO/IEC 7816-4 §5.1.1.1) and
/// the secure messaging indication (§5.1.1), which the device's secure channel has
/// already processed. Logical channels and other classes are `6E00`.
const CLA_ALLOWED_BITS: u8 = 0x10 | 0x0C;
/// Response data per APDU for short commands (ISO/IEC 7816-4 §5.1: Ne at most 256).
const SHORT_MAX_NE: usize = 256;
/// Response data per APDU for extended commands without a smaller Le.
const EXTENDED_MAX_NE: usize = 65_536;
/// Uncompressed P-256 point length.
const POINT_LEN: usize = 65;
/// Symmetric context: host challenge (8) || card challenge (8).
const SYMMETRIC_CONTEXT_LEN: usize = 16;
/// Asymmetric context: EPK.OCE (65) || EPK.SD (65).
const ASYMMETRIC_CONTEXT_LEN: usize = 2 * POINT_LEN;
/// Symmetric card cryptogram length (Amendment D §6.2.2.2, 64 bits).
const CARD_CRYPTOGRAM_LEN: usize = 8;
/// Asymmetric receipt length (one AES-CMAC block).
const RECEIPT_LEN: usize = 16;
/// Symmetric host challenge length returned by GET CHALLENGE (yubikit
/// `test_get_challenge_symmetric`: 8 bytes).
const HOST_CHALLENGE_LEN: usize = 8;

/// What a command handler produced.
enum Reply {
    /// Send this data with `9000`.
    Data(Vec<u8>),
    /// Send the session keys once the user touches the device.
    AfterTouch(PendingTouch),
}

/// A touch-required CALCULATE that passed every check and waits for the user.
///
/// YESDK `GetAes128SessionKeysResponse` / `GetEccP256SessionKeysResponse`: when the
/// proof of user presence fails, "the credential password retry count is not
/// changed". So a correct password's return to eight tries is only committed once the
/// touch arrives, together with the release of the keys.
struct PendingTouch {
    /// S-ENC || S-MAC || S-RMAC.
    keys: Vec<u8>,
    /// Label of the credential whose password tries go back to eight on touch.
    restore: Option<Vec<u8>>,
}

impl Drop for PendingTouch {
    fn drop(&mut self) {
        wipe(&mut self.keys);
    }
}

/// The outstanding ephemeral key of an asymmetric credential (eSK.OCE). Volatile and
/// single-use: consumed by the next CALCULATE on an asymmetric credential.
struct Challenge {
    label: Vec<u8>,
    key: EcPrivateKey,
}

/// The YubiHSM Auth application (AID `A0 00 00 05 27 21 07 01`).
pub struct HsmAuth {
    state: State,
    chain: CommandChain,
    queue: ResponseQueue,
    challenge: Option<Challenge>,
    /// A touch-required CALCULATE waiting for the user.
    pending: Option<PendingTouch>,
}

impl fmt::Debug for HsmAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmAuth")
            .field("credentials", &self.state.credentials.len())
            .field("management_retries", &self.state.management_retries)
            .field("challenge_outstanding", &self.challenge.is_some())
            .field("touch_pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl HsmAuth {
    /// Restore from the plaintext last persisted under [`Record::HsmAuth`]; missing or
    /// unreadable state is factory state (`docs/CONTRACTS.md` "Persisted state").
    pub fn new(stored: Option<&[u8]>, _host: &mut dyn Host) -> Self {
        let state = stored.and_then(State::deserialize).unwrap_or_else(State::factory);
        Self {
            state,
            chain: CommandChain::new(MAX_COMMAND_LEN),
            queue: ResponseQueue::new(),
            challenge: None,
            pending: None,
        }
    }

    /// Drop everything that does not survive deselection or a reset.
    fn clear_volatile(&mut self) {
        self.chain.clear();
        self.queue.clear();
        self.challenge = None;
        self.drop_pending();
    }

    /// Abandon a CALCULATE waiting for touch; its keys are wiped (`PendingTouch::drop`)
    /// and nothing is persisted, so the password tries stay as they were.
    fn drop_pending(&mut self) {
        self.pending = None;
    }

    /// Persist `next` and make it current; on failure keep the current state (`6581`).
    fn commit(&mut self, next: State, host: &mut dyn Host) -> Result<(), u16> {
        let mut bytes = next.serialize();
        let stored = host.persist(Record::HsmAuth, &bytes);
        wipe(&mut bytes);
        match stored {
            Ok(()) => {
                self.state = next;
                Ok(())
            }
            Err(_) => Err(sw::MEMORY_FAILURE),
        }
    }

    fn credential(&self, index: usize) -> Result<&Credential, u16> {
        self.state.credentials.get(index).ok_or(sw::FILE_NOT_FOUND)
    }

    /// Forget the outstanding ephemeral key if it belongs to `label`.
    fn forget_challenge(&mut self, label: &[u8]) {
        if self.challenge.as_ref().is_some_and(|c| c.label == label) {
            self.challenge = None;
        }
    }

    /// Check the management key. A wrong key costs a try, persisted before the `63Cx`
    /// that reveals it; a correct key restores all tries, persisted before the command
    /// goes on. With no tries left every attempt answers `63C0` until RESET (yubikit
    /// `InvalidPinError` handling; YESDK `AddCredentialCommand`: "a limit of 8 attempts
    /// ... Once the management key is blocked, the application must be reset ...
    /// Supplying the correct management key before the management key is blocked will
    /// reset the retry counter to 8").
    fn verify_management_key(&mut self, presented: &[u8; MANAGEMENT_KEY_LEN], host: &mut dyn Host) -> Result<(), u16> {
        if self.state.management_retries == 0 {
            return Err(sw::retries(0));
        }
        let mut next = self.state.clone();
        if ct_eq(presented, &self.state.management_key) {
            if next.management_retries != RETRIES {
                next.management_retries = RETRIES;
                self.commit(next, host)?;
            }
            return Ok(());
        }
        next.management_retries = next.management_retries.saturating_sub(1);
        let left = next.management_retries;
        self.commit(next, host)?;
        Err(sw::retries(left))
    }

    /// Check a credential password.
    ///
    /// A wrong password costs a try, persisted before the `63Cx` that reveals it; the
    /// eighth wrong password deletes the credential and its outstanding ephemeral key
    /// (YESDK YubiHSM Auth overview: "a limit of 8 retries, after which the credential
    /// will be permanently deleted"; `reference/BEHAVIOR_CATALOG.md` YubiHSMAuth).
    ///
    /// A correct password answers `Ok(true)` when the tries must go back to eight
    /// (YESDK `GetAes128SessionKeysCommand`: "Supplying the correct password before the
    /// credential is deleted will reset the retry counter to 8"). Nothing is persisted
    /// for it here: the caller commits it with [`Self::restore_tries`] before it
    /// reveals anything, or after the touch for a touch-required CALCULATE.
    fn check_password(
        &mut self,
        index: usize,
        presented: &[u8; CREDENTIAL_PASSWORD_LEN],
        host: &mut dyn Host,
    ) -> Result<bool, u16> {
        let cred = self.credential(index)?;
        let correct = ct_eq(presented, &cred.password);
        let tries = cred.retries;
        if correct {
            return Ok(tries != RETRIES);
        }
        let label = cred.label.clone();
        let left = tries.saturating_sub(1);
        let mut next = self.state.clone();
        if left == 0 {
            next.credentials.retain(|c| c.label != label);
        } else if let Some(c) = next.credentials.get_mut(index) {
            c.retries = left;
        }
        self.commit(next, host)?;
        if left == 0 {
            self.forget_challenge(&label);
        }
        Err(sw::retries(left))
    }

    /// Give the credential named `label` its eight password tries back, persisted
    /// (`6581` on storage failure). `6985` if the credential no longer exists.
    fn restore_tries(&mut self, label: &[u8], host: &mut dyn Host) -> Result<(), u16> {
        let index = self.state.find(label).ok_or(sw::CONDITIONS)?;
        if self.credential(index)?.retries == RETRIES {
            return Ok(());
        }
        let mut next = self.state.clone();
        if let Some(c) = next.credentials.get_mut(index) {
            c.retries = RETRIES;
        }
        self.commit(next, host)
    }

    fn dispatch(&mut self, cmd: &Command, host: &mut dyn Host) -> Result<Reply, u16> {
        let data = cmd.data.as_slice();
        match cmd.ins {
            ins::PUT => self.put(data, host),
            ins::DELETE => self.delete(data, host),
            ins::CALCULATE => self.calculate(data, host),
            ins::GET_CHALLENGE => self.get_challenge(data, host),
            ins::LIST => Ok(Reply::Data(self.list())),
            ins::RESET => self.reset_application(cmd, host),
            // ykhsmauth `ykhsmauth_get_version`: three raw bytes, no TLV.
            ins::GET_VERSION => Ok(Reply::Data(host.profile().firmware.bytes().to_vec())),
            ins::PUT_MANAGEMENT_KEY => self.put_management_key(data, host),
            // yubikit `get_management_key_retries`: `bytes2int` of the raw response.
            ins::GET_MANAGEMENT_KEY_RETRIES => Ok(Reply::Data(vec![self.state.management_retries])),
            ins::GET_PUBLIC_KEY => self.get_public_key(data),
            _ => Err(sw::INS_NOT_SUPPORTED),
        }
    }

    /// PUT (`01`): store a symmetric credential (alg 38: `75` K-ENC, `76` K-MAC), import
    /// an asymmetric one (alg 39 with a 32-byte `7D` scalar) or generate one on the
    /// device (alg 39 with an empty `7D`, as yubikit `generate_credential_asymmetric`
    /// sends it, or without `7D`), as built by yubikit `_put_credential`, ykhsmauth
    /// `ykhsmauth_put` and YESDK `AddCredentialCommand`.
    ///
    /// Order: syntax (`6A80`, no try consumed), management key (`63Cx`), duplicate label
    /// (`6983`), capacity (`6A84`), then persist. Touch `7A` must be one byte `00` or
    /// `01` (catalog `yubihsm_auth_touch_policy_syntax`); model decision: an absent `7A`
    /// means no touch.
    fn put(&mut self, data: &[u8], host: &mut dyn Host) -> Result<Reply, u16> {
        let fields = Fields::parse(
            data,
            &[
                tag::MANAGEMENT_KEY,
                tag::LABEL,
                tag::ALGORITHM,
                tag::KEY_ENC,
                tag::KEY_MAC,
                tag::PRIVATE_KEY,
                tag::CREDENTIAL_PASSWORD,
                tag::TOUCH,
            ],
        )?;
        let management_key = fields.fixed::<MANAGEMENT_KEY_LEN>(tag::MANAGEMENT_KEY)?;
        let label = fields.label()?;
        let [algorithm] = fields.fixed::<1>(tag::ALGORITHM)?;
        let password = fields.fixed::<CREDENTIAL_PASSWORD_LEN>(tag::CREDENTIAL_PASSWORD)?;
        let touch = match fields.get(tag::TOUCH) {
            None | Some([0x00]) => false,
            Some([0x01]) => true,
            Some(_) => return Err(sw::INCORRECT_DATA),
        };
        // `None` for an asymmetric credential means "generate on the device".
        let key = match algorithm {
            alg::AES128_YUBICO_AUTHENTICATION => {
                if fields.get(tag::PRIVATE_KEY).is_some() {
                    return Err(sw::INCORRECT_DATA);
                }
                Some(Key::Symmetric { enc: fields.fixed(tag::KEY_ENC)?, mac: fields.fixed(tag::KEY_MAC)? })
            }
            alg::EC_P256_YUBICO_AUTHENTICATION => {
                if fields.get(tag::KEY_ENC).is_some() || fields.get(tag::KEY_MAC).is_some() {
                    return Err(sw::INCORRECT_DATA);
                }
                match fields.get(tag::PRIVATE_KEY) {
                    // yubikit `generate_credential_asymmetric` sends an empty `7D`
                    // ("Empty byte will generate key"); an absent `7D` is read the same
                    // way (model decision).
                    None | Some([]) => None,
                    Some(value) => {
                        let scalar = fixed::<32>(value)?;
                        EcPrivateKey::from_scalar(Curve::P256, &scalar).map_err(|_| sw::INCORRECT_DATA)?;
                        Some(Key::EcP256 { scalar })
                    }
                }
            }
            _ => return Err(sw::INCORRECT_DATA),
        };
        self.verify_management_key(&management_key, host)?;
        if self.state.find(label).is_some() {
            return Err(sw::AUTH_BLOCKED);
        }
        if self.state.credentials.len() >= MAX_CREDENTIALS {
            return Err(sw::NO_SPACE);
        }
        let key = match key {
            Some(key) => key,
            None => {
                let generated = EcPrivateKey::generate(Curve::P256, host);
                Key::EcP256 { scalar: generated.scalar().try_into().map_err(|_| sw::UNKNOWN)? }
            }
        };
        let mut next = self.state.clone();
        next.credentials.push(Credential { label: label.to_vec(), key, touch, password, retries: RETRIES });
        self.commit(next, host)?;
        Ok(Reply::Data(Vec::new()))
    }

    /// DELETE (`02`): `7B` management key and `71` label (yubikit `delete_credential`).
    /// The management key is checked before the label is looked up.
    fn delete(&mut self, data: &[u8], host: &mut dyn Host) -> Result<Reply, u16> {
        let fields = Fields::parse(data, &[tag::MANAGEMENT_KEY, tag::LABEL])?;
        let management_key = fields.fixed::<MANAGEMENT_KEY_LEN>(tag::MANAGEMENT_KEY)?;
        let label = fields.label()?;
        self.verify_management_key(&management_key, host)?;
        if self.state.find(label).is_none() {
            return Err(sw::FILE_NOT_FOUND);
        }
        let mut next = self.state.clone();
        next.credentials.retain(|c| c.label != label);
        self.commit(next, host)?;
        self.forget_challenge(label);
        Ok(Reply::Data(Vec::new()))
    }

    /// CALCULATE (`03`): `71` label, `77` context, `7C` PK.SD (asymmetric), `78` card
    /// cryptogram / receipt, `73` password (yubikit `_calculate_session_keys`). Answers
    /// S-ENC || S-MAC || S-RMAC (48 bytes).
    ///
    /// - Symmetric: 16-byte context; an optional 8-byte card cryptogram is verified
    ///   (model decision; ykhsmauth sends none for symmetric credentials).
    /// - Asymmetric: 130-byte context `EPK.OCE || EPK.SD` whose first half must be the
    ///   ephemeral key GET CHALLENGE issued for this credential; PK.SD and a 16-byte
    ///   receipt are required and the receipt must verify. Once the command is well
    ///   formed and names an existing asymmetric credential, it consumes the outstanding
    ///   ephemeral key whatever the outcome (wrong password, wrong receipt, stale
    ///   challenge, declined touch, storage failure): catalog "single-use ephemeral
    ///   challenges". Syntax errors and unknown labels leave it in place (no ECDH was
    ///   done with it).
    /// - Order: TLV syntax, label syntax and password length (`6A80`); label lookup
    ///   (`6A82`); context, PK.SD and `78` shape for the credential's type (`6A80`);
    ///   password (`63Cx`, persisted); then challenge / receipt / cryptogram (`6984`). A
    ///   mismatch there still restores the tries of a correct password (persisted
    ///   before the `6984`). No `6A80` consumes a try or the challenge.
    /// - Touch-required credentials answer [`Outcome::NeedTouch`] only after all of the
    ///   above succeed; GET CHALLENGE never waits for touch (catalog
    ///   `hsmauth_symmetric_challenge_touch`). The return to eight tries is committed
    ///   only when the touch arrives (see [`PendingTouch`]).
    fn calculate(&mut self, data: &[u8], host: &mut dyn Host) -> Result<Reply, u16> {
        let fields = Fields::parse(
            data,
            &[tag::LABEL, tag::CONTEXT, tag::PUBLIC_KEY, tag::RESPONSE, tag::CREDENTIAL_PASSWORD],
        )?;
        let label = fields.label()?;
        let context = fields.required(tag::CONTEXT)?;
        let password = fields.fixed::<CREDENTIAL_PASSWORD_LEN>(tag::CREDENTIAL_PASSWORD)?;
        let card_public = fields.get(tag::PUBLIC_KEY);
        let card_response = fields.get(tag::RESPONSE);
        let index = self.state.find(label).ok_or(sw::FILE_NOT_FOUND)?;
        let asymmetric = matches!(self.credential(index)?.key, Key::EcP256 { .. });
        let well_formed = if asymmetric {
            let (epk_oce, epk_sd) = context.split_at(context.len().min(POINT_LEN));
            context.len() == ASYMMETRIC_CONTEXT_LEN
                && ec_public_is_valid(Curve::P256, epk_oce)
                && ec_public_is_valid(Curve::P256, epk_sd)
                && card_public.is_some_and(|p| ec_public_is_valid(Curve::P256, p))
                && card_response.is_some_and(|r| r.len() == RECEIPT_LEN)
        } else {
            context.len() == SYMMETRIC_CONTEXT_LEN
                && card_public.is_none()
                && card_response.is_none_or(|r| r.len() == CARD_CRYPTOGRAM_LEN)
        };
        if !well_formed {
            return Err(sw::INCORRECT_DATA);
        }
        let challenge = if asymmetric { self.challenge.take() } else { None };
        let restore = self.check_password(index, &password, host)?;
        let touch = self.credential(index)?.touch;
        let derived = self.session_keys(index, label, context, card_public, card_response, challenge);
        let mut keys = match derived {
            Ok(keys) => keys,
            Err(code) => {
                if restore {
                    self.restore_tries(label, host)?;
                }
                return Err(code);
            }
        };
        let mut pending = PendingTouch { keys: keys.to_vec(), restore: restore.then(|| label.to_vec()) };
        wipe(&mut keys);
        if touch {
            return Ok(Reply::AfterTouch(pending));
        }
        if restore {
            // `pending` (and its copy of the keys) is wiped on drop if this fails.
            self.restore_tries(label, host)?;
        }
        Ok(Reply::Data(core::mem::take(&mut pending.keys)))
    }

    /// The session keys of credential `index` for a well-formed CALCULATE, after the
    /// card cryptogram (symmetric, when supplied) or the challenge and receipt
    /// (asymmetric) verify; `6984` when they do not.
    fn session_keys(
        &self,
        index: usize,
        label: &[u8],
        context: &[u8],
        card_public: Option<&[u8]>,
        card_response: Option<&[u8]>,
        challenge: Option<Challenge>,
    ) -> Result<SessionKeys, u16> {
        let cred = self.credential(index)?;
        match &cred.key {
            Key::Symmetric { enc, mac } => {
                let mut keys = symmetric_session_keys(enc, mac, context).map_err(|_| sw::UNKNOWN)?;
                if let Some(expected) = card_response {
                    let verified = keys
                        .get(16..32)
                        .and_then(|s_mac| card_cryptogram(s_mac, context).ok())
                        .is_some_and(|cryptogram| ct_eq(&cryptogram, expected));
                    if !verified {
                        wipe(&mut keys);
                        return Err(sw::DATA_INVALID);
                    }
                }
                Ok(keys)
            }
            Key::EcP256 { .. } => {
                let challenge = challenge.filter(|c| c.label == label).ok_or(sw::DATA_INVALID)?;
                let (epk_oce, epk_sd) = context.split_at_checked(POINT_LEN).ok_or(sw::INCORRECT_DATA)?;
                if !ct_eq(epk_oce, &challenge.key.public_uncompressed()) {
                    return Err(sw::DATA_INVALID);
                }
                let credential_key = cred.ec_key().ok_or(sw::UNKNOWN)?;
                let card_public = card_public.ok_or(sw::INCORRECT_DATA)?;
                let mut derived =
                    asymmetric_session_keys(&credential_key, &challenge.key, card_public, epk_oce, epk_sd)
                        .map_err(|_| sw::INCORRECT_DATA)?;
                if !card_response.is_some_and(|r| ct_eq(&derived.receipt, r)) {
                    wipe(&mut derived.session);
                    return Err(sw::DATA_INVALID);
                }
                Ok(derived.session)
            }
        }
    }

    /// GET CHALLENGE (`04`): `71` label and, from firmware 5.7.1, an optional `73`
    /// password, verified when present (yubikit `get_challenge`). A symmetric
    /// credential answers 8 random bytes to use as the host challenge; an asymmetric one
    /// answers a fresh ephemeral public key EPK.OCE (65 bytes) and keeps eSK.OCE for the
    /// next CALCULATE (YESDK `CreateHostChallengeCommand`). No touch is needed.
    ///
    /// Model decision: a well-formed GET CHALLENGE naming an existing credential
    /// discards the previously outstanding ephemeral key, before the password is
    /// checked; a syntax error or an unknown label (`6A82`) leaves it in place. A
    /// correct password restores the credential's tries at once (persisted before the
    /// challenge is returned).
    fn get_challenge(&mut self, data: &[u8], host: &mut dyn Host) -> Result<Reply, u16> {
        let fields = Fields::parse(data, &[tag::LABEL, tag::CREDENTIAL_PASSWORD])?;
        let label = fields.label()?;
        let password = fields.optional_fixed::<CREDENTIAL_PASSWORD_LEN>(tag::CREDENTIAL_PASSWORD)?;
        let index = self.state.find(label).ok_or(sw::FILE_NOT_FOUND)?;
        self.challenge = None;
        if let Some(password) = password
            && self.check_password(index, &password, host)?
        {
            self.restore_tries(label, host)?;
        }
        let asymmetric = matches!(self.credential(index)?.key, Key::EcP256 { .. });
        if asymmetric {
            let key = EcPrivateKey::generate(Curve::P256, host);
            let public = key.public_uncompressed();
            self.challenge = Some(Challenge { label: label.to_vec(), key });
            Ok(Reply::Data(public))
        } else {
            let mut challenge = vec![0u8; HOST_CHALLENGE_LEN];
            host.fill(&mut challenge);
            Ok(Reply::Data(challenge))
        }
    }

    /// LIST (`05`): one `72` object per credential holding algorithm, touch flag, label
    /// and password tries left (yubikit `list_credentials`, ykhsmauth
    /// `ykhsmauth_list_keys`), in the order the credentials were stored.
    fn list(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for cred in &self.state.credentials {
            let mut entry = Vec::with_capacity(cred.label.len() + 3);
            entry.push(cred.key.algorithm());
            entry.push(u8::from(cred.touch));
            entry.extend_from_slice(&cred.label);
            entry.push(cred.retries);
            tlv::encode_into(&mut out, tag::LABEL_LIST, &entry);
        }
        out
    }

    /// RESET (`06`, `P1 P2 = DE AD`, yubikit `reset`): delete every credential and
    /// restore the default management key with all tries.
    ///
    /// Catalog `hsmauth_reset_apdu_shape`: data or an explicit Le is rejected (`6700`)
    /// before anything is cleared, except the ambiguous five-byte form `00 06 DE AD 00`
    /// that formatters emitting an empty Lc produce (parsed as short Le `00`).
    fn reset_application(&mut self, cmd: &Command, host: &mut dyn Host) -> Result<Reply, u16> {
        if [cmd.p1, cmd.p2] != RESET_P1P2 {
            return Err(sw::INCORRECT_P1P2);
        }
        let le_acceptable = match cmd.le {
            None => true,
            Some(0) => !cmd.extended,
            Some(_) => false,
        };
        if !cmd.data.is_empty() || !le_acceptable {
            return Err(sw::WRONG_LENGTH);
        }
        self.commit(State::factory(), host)?;
        self.challenge = None;
        Ok(Reply::Data(Vec::new()))
    }

    /// PUT MANAGEMENT KEY (`08`): `7B` current key then `7B` new key, 16 bytes each
    /// (yubikit `put_management_key`). A successful change restores all tries.
    fn put_management_key(&mut self, data: &[u8], host: &mut dyn Host) -> Result<Reply, u16> {
        let items = tlv::parse_all(data).map_err(|_| sw::INCORRECT_DATA)?;
        let [current, new] = items.as_slice() else {
            return Err(sw::INCORRECT_DATA);
        };
        if current.tag != tag::MANAGEMENT_KEY || new.tag != tag::MANAGEMENT_KEY {
            return Err(sw::INCORRECT_DATA);
        }
        let current = fixed::<MANAGEMENT_KEY_LEN>(current.value)?;
        let new = fixed::<MANAGEMENT_KEY_LEN>(new.value)?;
        self.verify_management_key(&current, host)?;
        let mut next = self.state.clone();
        next.management_key = new;
        next.management_retries = RETRIES;
        self.commit(next, host)?;
        Ok(Reply::Data(Vec::new()))
    }

    /// GET PUBLIC KEY (`0A`): `71` label; answers PK.OCE as a 65-byte uncompressed point
    /// (yubikit `get_public_key`). A symmetric credential is `6983` (ykman `export`:
    /// "The entry is not an asymmetric credential").
    fn get_public_key(&self, data: &[u8]) -> Result<Reply, u16> {
        let fields = Fields::parse(data, &[tag::LABEL])?;
        let label = fields.label()?;
        let index = self.state.find(label).ok_or(sw::FILE_NOT_FOUND)?;
        let cred = self.credential(index)?;
        match cred.key {
            Key::EcP256 { .. } => {
                let key = cred.ec_key().ok_or(sw::UNKNOWN)?;
                Ok(Reply::Data(key.public_uncompressed()))
            }
            Key::Symmetric { .. } => Err(sw::AUTH_BLOCKED),
        }
    }
}

/// Response bytes per APDU before `61xx` continuation (ISO/IEC 7816-4 §5.1.3). Short
/// commands get up to 256 bytes whatever their Le, which also covers formatters that
/// send an empty Lc (`00`) that parses as Le; extended ones up to Ne.
fn max_response(cmd: &Command) -> usize {
    if cmd.extended { cmd.expected_len().filter(|&n| n > 0).unwrap_or(EXTENDED_MAX_NE) } else { SHORT_MAX_NE }
}

impl CardApplet for HsmAuth {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    /// SELECT answers exactly one TLV `79 03 major minor patch` (yubikit `_parse_select`
    /// unpacks the whole response as one `79` object).
    fn select(&mut self, _apdu: &[u8], host: &mut dyn Host) -> Vec<u8> {
        self.clear_volatile();
        response(&tlv::encode(tag::VERSION, &host.profile().firmware.bytes()), sw::OK)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        // Model decision: a command arriving while a CALCULATE waits for touch abandons
        // that CALCULATE.
        self.drop_pending();
        let cmd = match Command::parse(apdu) {
            Ok(cmd) => cmd,
            Err(err) => {
                self.chain.clear();
                self.queue.clear();
                return Outcome::Done(status(err.sw()));
            }
        };
        if cmd.cla & !CLA_ALLOWED_BITS != 0 {
            self.chain.clear();
            self.queue.clear();
            return Outcome::Done(status(sw::CLA_NOT_SUPPORTED));
        }
        if cmd.ins == ins::GET_RESPONSE && !self.chain.is_active() {
            let max = max_response(&cmd);
            return Outcome::Done(self.queue.next(max).unwrap_or_else(|| status(sw::CONDITIONS)));
        }
        self.queue.clear();
        let cmd = match self.chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => return Outcome::Done(status(sw::OK)),
            Err(err) => return Outcome::Done(status(err.sw())),
        };
        let max = max_response(&cmd);
        match self.dispatch(&cmd, host) {
            Ok(Reply::Data(data)) => Outcome::Done(self.queue.start(data, sw::OK, max)),
            Ok(Reply::AfterTouch(pending)) => {
                self.pending = Some(pending);
                Outcome::NeedTouch { timeout_ms: TOUCH_TIMEOUT_MS }
            }
            Err(code) => Outcome::Done(status(code)),
        }
    }

    /// Finish a touch-required CALCULATE.
    ///
    /// - Touched: a correct password's return to eight tries is persisted first
    ///   (`6581` and no keys if that fails), then the session keys go out.
    /// - Not touched: `6982` (ykman `handle_error` "The device was not touched";
    ///   ykhsmauth `translate_error` `SW_SECURITY_STATUS_NOT_SATISFIED` → touch error;
    ///   YESDK `RetryWithTouch`), nothing is persisted, so "the credential password
    ///   retry count is not changed" (YESDK `GetAes128SessionKeysResponse`).
    /// - `touched = false` answers `6982` even if a reset or deselect already dropped
    ///   the pending command, since `lk_core::Outcome::NeedTouch` allows the device to
    ///   report the session reset in either order; a touch with nothing waiting is
    ///   `6985` (model decision).
    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8> {
        let Some(pending) = self.pending.take() else {
            return status(if touched { sw::CONDITIONS } else { sw::SECURITY_STATUS });
        };
        if !touched {
            return status(sw::SECURITY_STATUS);
        }
        if let Some(label) = &pending.restore
            && let Err(code) = self.restore_tries(label, host)
        {
            return status(code);
        }
        response(&pending.keys, sw::OK)
    }

    fn deselect(&mut self) {
        self.clear_volatile();
    }

    fn reset(&mut self, _kind: ResetKind) {
        // Every reset kind ends the card session, so all volatile state goes.
        self.clear_volatile();
    }
}
