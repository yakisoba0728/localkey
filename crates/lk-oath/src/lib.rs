//! OATH application: HOTP (RFC 4226) and TOTP (RFC 6238) credentials over
//! YKOATH APDUs (PUT, DELETE, LIST, CALCULATE, CALCULATE ALL, SET CODE, VALIDATE,
//! RESET, RENAME, SEND REMAINING).
//!
//! Sources, in the order of `docs/DESIGN.md` §2:
//!
//! - Yubico's public "YKOATH Protocol Specification" (cited as *YKOATH §<instruction>*);
//!   RENAME (`05`) is the firmware 5.3+ addition documented with it.
//! - RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 2104 (HMAC), ISO/IEC 7816-4 (APDUs, BER-TLV,
//!   status words).
//! - The OATH section of `reference/BEHAVIOR_CATALOG.md` and `oath_profile` of
//!   `reference/legacy-v0.64-profiles.json` for boundary decisions the documents leave
//!   open (capacity 64, IMF exactly four bytes and HOTP only, the property byte rules,
//!   the 14-byte minimum wire secret, `6984` statuses, SEND REMAINING CLA, the HOTP
//!   terminal counter, authorization binding). These are marked *model policy* below.
//!
//! The applet is a pure state machine (`docs/DESIGN.md` §4): user presence is requested
//! with [`Outcome::NeedTouch`] and finished in [`CardApplet::touch_resolved`]; time-based
//! codes need no clock because the host sends the time step as the challenge
//! (RFC 6238 §4.2, YKOATH §CALCULATE).
//!
//! Persistence follows `docs/DESIGN.md` §7: every mutation, including each HOTP counter
//! step and each "only increasing" challenge, is persisted through [`Host::persist`]
//! before the response that reveals it. On a storage failure the previous state is
//! kept and the command answers `6581`. When nothing is stored yet, [`Oath::new`]
//! persists the factory state so that the device id (the SELECT salt) is stable
//! across restarts. The record layout is documented in the private `state` module
//! (version byte `01`, then BER-TLV).
//!
//! YKOATH has no retry counter: VALIDATE may be repeated without limit, as on the
//! device, and the proofs of VALIDATE and SET CODE are compared in constant time
//! ([`lk_crypto::ct_eq`]). The "spend and persist the try before comparing" rule of
//! `docs/CONTRACTS.md` therefore has nothing to apply to here.
//!
//! Secrets are wiped when they are dropped (`docs/DESIGN.md` §8): credential keys, the
//! access key, the serialized record and every HMAC output (full codes, which a host
//! may use as key-derived secrets, the device's VALIDATE proof and the expected
//! VALIDATE and SET CODE proofs) are held in [`lk_crypto::SecretBytes`]. The record and
//! the code answers are built at their final size, so no reallocation frees a copy.
//! Command data, chained data and pending response data are wiped by
//! `lk_codec::apdu`'s types.
//!
//! # Status words
//!
//! | Situation | SW | Source |
//! | --- | --- | --- |
//! | malformed data, bad lengths, unknown or repeated tags | `6A80` | YKOATH §PUT ("data is malformed") |
//! | wrong VALIDATE response (proof) | `6A80` | YKOATH §VALIDATE response codes (only "auth not enabled" `6984` and "wrong syntax" `6A80`; the catalog is silent) |
//! | wrong P1/P2 | `6A86` | ISO/IEC 7816-4 §5.1.3 |
//! | no such credential, no access key for VALIDATE, wrong SET CODE proof | `6984` | catalog / `oath_profile` |
//! | access key set and session not validated | `6982` | ISO/IEC 7816-4 §5.1.3 |
//! | 65th credential | `6A84` | YKOATH §PUT ("no space") |
//! | storage failure | `6581` | `docs/CONTRACTS.md` |
//! | touch refused or timed out | `6982` | model policy |
//! | exhausted HOTP counter, nothing pending for SEND REMAINING | `6985` | model policy |
//! | CLA with secure-messaging bits (the device unwraps secure messaging first) | `6882` | ISO/IEC 7816-4 §5.1.1, §5.6 |
//! | CLA with a logical channel number | `6881` | ISO/IEC 7816-4 §5.1.1, §5.6 |
//! | any other CLA but `00` (`10` while chaining, never for SEND REMAINING) | `6E00` | ISO/IEC 7816-4 §5.1.1 |
//! | unknown INS | `6D00` | ISO/IEC 7816-4 §5.1.3 |

#![forbid(unsafe_code)]

mod credential;
mod request;
mod state;

pub use credential::{PROP_ONLY_INCREASING, PROP_REQUIRE_TOUCH};

use std::cmp::Ordering;
use std::fmt;
use std::ops::RangeInclusive;

use lk_codec::apdu::{self, Command, CommandChain, ResponseQueue, sw};
use lk_codec::tlv;
use lk_core::{CardApplet, Host, Millis, Outcome, Record, ResetKind};
use lk_crypto::SecretBytes;

use credential::{Alg, Credential, HOTP_EXHAUSTED, Kind, PROP_ALL, compare_challenges, dynamic_truncate};
use state::{AccessKey, State, tlv_len};

/// The OATH application identifier `A0 00 00 05 27 21 01` (YKOATH §SELECT).
pub const AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// Credential capacity of firmware 5.7 (catalog: "published 64-credential capacity";
/// `oath_profile.credential_capacity`).
pub const MAX_CREDENTIALS: usize = 64;

/// Longest credential name (YKOATH §PUT: "Name length ... max 64 bytes").
pub const MAX_NAME_LEN: usize = 64;

/// Shortest secret accepted on the wire. Clients pad HMAC keys with zero bytes to 14
/// bytes, which leaves the MAC unchanged (RFC 2104 §2 pads the key to `B` with zeros);
/// a shorter secret is refused before anything is written (catalog: "PUT credential
/// secret minimum 14 wire bytes", model policy).
pub const MIN_SECRET_LEN: usize = 14;

/// Longest CALCULATE / CALCULATE ALL / VALIDATE challenge accepted (model policy: the
/// reference maximum is unmeasured, `oath_profile.validate_challenge`; 64 bytes covers
/// any time step and any SHA-1/SHA-256 block-sized challenge).
pub const MAX_CHALLENGE_LEN: usize = 64;

/// SET CODE challenge length (YKOATH §SET CODE: "an 8 byte challenge";
/// `oath_profile.set_code_challenge_length`).
pub const SET_CODE_CHALLENGE_LEN: usize = 8;

/// How long a touch credential waits for the user (model policy: 15 seconds, the
/// window the device also uses for its other touch-gated operations).
pub const TOUCH_TIMEOUT_MS: Millis = 15_000;

/// Accepted number of digits: RFC 4226 §5.3 requires at least 6 and allows 7 and 8.
pub(crate) const DIGITS_RANGE: RangeInclusive<u8> = 6..=8;

/// Most command data accepted through command chaining (ISO/IEC 7816-4 §5.1.1.1).
/// The largest well-formed PUT is far smaller; this only bounds buffering.
const CHAIN_LIMIT: usize = 4096;

/// Response piece size when the command carries no Le (ISO/IEC 7816-4 §5.1: the
/// short-form maximum Ne).
const DEFAULT_RESPONSE_MAX: usize = 256;

/// CLA bit b5: command chaining (ISO/IEC 7816-4 §5.1.1.1).
const CLA_CHAIN: u8 = 0x10;
/// CLA bits b4-b3: secure messaging indication (ISO/IEC 7816-4 §5.1.1). The device's
/// secure channel (lk-sd) verifies, decrypts and clears these bits before a command
/// reaches an applet, so a command that still carries them was never unwrapped.
const CLA_SM: u8 = 0x0C;
/// CLA bits b2-b1: logical channel number (ISO/IEC 7816-4 §5.1.1); only the basic
/// channel exists.
const CLA_CHANNEL: u8 = 0x03;
/// CLA bits b8-b6: anything but the first interindustry class `0x00..=0x1F`
/// (ISO/IEC 7816-4 §5.1.1).
const CLA_CLASS: u8 = 0xE0;

/// YKOATH instruction bytes.
pub mod ins {
    /// YKOATH §PUT.
    pub const PUT: u8 = 0x01;
    /// YKOATH §DELETE.
    pub const DELETE: u8 = 0x02;
    /// YKOATH §SET CODE.
    pub const SET_CODE: u8 = 0x03;
    /// YKOATH §RESET (P1 `DE`, P2 `AD`).
    pub const RESET: u8 = 0x04;
    /// YKOATH §RENAME (firmware 5.3+).
    pub const RENAME: u8 = 0x05;
    /// YKOATH §LIST.
    pub const LIST: u8 = 0xA1;
    /// YKOATH §CALCULATE.
    pub const CALCULATE: u8 = 0xA2;
    /// YKOATH §VALIDATE.
    pub const VALIDATE: u8 = 0xA3;
    /// YKOATH §CALCULATE ALL.
    pub const CALCULATE_ALL: u8 = 0xA4;
    /// YKOATH §SEND REMAINING.
    pub const SEND_REMAINING: u8 = 0xA5;
}

/// YKOATH data object tags.
pub mod tag {
    /// Credential name, or the device id/salt in the SELECT response.
    pub const NAME: u8 = 0x71;
    /// LIST entry: type/algorithm byte then name.
    pub const NAME_LIST: u8 = 0x72;
    /// Key: type/algorithm byte, digits (PUT only), key bytes.
    pub const KEY: u8 = 0x73;
    pub const CHALLENGE: u8 = 0x74;
    /// Full response: digits then the whole HMAC.
    pub const RESPONSE: u8 = 0x75;
    /// Truncated response: digits then four bytes.
    pub const TRUNCATED: u8 = 0x76;
    /// CALCULATE ALL placeholder for an HOTP credential: digits only.
    pub const HOTP: u8 = 0x77;
    /// PUT property: followed directly by one byte, without a length.
    pub const PROPERTY: u8 = 0x78;
    pub const VERSION: u8 = 0x79;
    /// PUT initial moving factor of an HOTP credential (four bytes).
    pub const IMF: u8 = 0x7A;
    /// SELECT: access key algorithm.
    pub const ALGORITHM: u8 = 0x7B;
    /// CALCULATE ALL placeholder for a touch credential: digits only.
    pub const TOUCH: u8 = 0x7C;
}

/// The OATH application.
pub struct Oath {
    state: State,
    /// Authorization revision: bumped whenever the access key or the salt changes
    /// (SET CODE, RESET), so an authorization or a pending continuation obtained
    /// before the change is stale (catalog: "authorization is bound to current salt,
    /// access key and rotation revision").
    revision: u64,
    session: Session,
}

/// Selection-scoped, never persisted state (`docs/DESIGN.md` §7, "volatile state").
#[derive(Debug)]
struct Session {
    /// The challenge sent in the SELECT response while an access key is set.
    challenge: Option<[u8; 8]>,
    /// The revision at which this session proved the access key (YKOATH §VALIDATE).
    authorized: Option<u64>,
    chain: CommandChain,
    queue: ResponseQueue,
    /// The revision the pending response was produced under.
    queue_revision: u64,
    /// Whether the pending response needs the session to stay authorized (everything
    /// but the SELECT response).
    queue_bound: bool,
    touch: Option<TouchRequest>,
}

impl Session {
    fn new() -> Self {
        Self {
            challenge: None,
            authorized: None,
            chain: CommandChain::new(CHAIN_LIMIT),
            queue: ResponseQueue::new(),
            queue_revision: 0,
            queue_bound: false,
            touch: None,
        }
    }
}

/// A CALCULATE waiting for the user's touch.
#[derive(Debug)]
struct TouchRequest {
    name: Vec<u8>,
    challenge: Vec<u8>,
    truncated: bool,
    max: usize,
    revision: u64,
}

/// What a command handler produced.
enum Reply {
    /// Success with response data (possibly empty).
    Data(Vec<u8>),
    /// Success without data.
    Ok,
    /// Wait for a touch.
    Touch,
}

type Handled = Result<Reply, u16>;

impl fmt::Debug for Oath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oath")
            .field("credentials", &self.state.creds.len())
            .field("access_key", &self.state.access_key.is_some())
            .field("revision", &self.revision)
            .field("authorized", &self.session.authorized.is_some())
            .finish_non_exhaustive()
    }
}

impl Oath {
    /// Restore the application from the plaintext it last persisted. Missing or
    /// unreadable state means factory state with a fresh salt from host entropy
    /// (`docs/CONTRACTS.md`, "Persisted state").
    ///
    /// The factory salt is the device id of YKOATH §SELECT (tag `71`). Hosts key
    /// remembered passwords and cached accounts by it (yubikit and yubikit-android:
    /// `device_id = base64(SHA-256(salt)[..16])`; ykman `oath access remember`, Yubico
    /// Authenticator), so it has to stay the same across restarts even before the first
    /// mutating command. When nothing is stored (`stored` is `None`), the new factory
    /// state is therefore persisted right here (`docs/CONTRACTS.md` "Constructors may
    /// persist"). A rejected save is not reported: the state stays in memory, the
    /// device saves a rejected constructor state again before its next input
    /// (lk-device `DeviceHost::retry_deferred`), and every later commit writes the
    /// whole state, salt included.
    ///
    /// A record that exists but does not decode (`Some` but unreadable, for example one
    /// written in a newer format) also gives factory state, but it is *not* overwritten
    /// here: opening never destroys a record, and only a mutating OATH command replaces
    /// it (`docs/DESIGN.md` §7). Until then the salt is drawn again at each start.
    /// lk-device passes `None` for a record it cannot open and shields that record from
    /// constructor saves, so the save above never overwrites one either.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let state = match stored {
            Some(bytes) => State::decode(bytes).unwrap_or_else(|| State::factory(host)),
            None => {
                let state = State::factory(host);
                // Not reported (see above): the in-memory state is still the factory
                // state, and the host or the next commit stores it.
                let _ = host.persist(Record::Oath, &state.encode());
                state
            }
        };
        Self {
            state,
            revision: 0,
            session: Session::new(),
        }
    }

    /// Whether commands that need the access key may run: no key is set, or this
    /// session validated it at the current revision (YKOATH §VALIDATE).
    fn is_authorized(&self) -> bool {
        self.state.access_key.is_none() || self.session.authorized == Some(self.revision)
    }

    /// LIST, PUT, DELETE, SET CODE, RENAME, CALCULATE and CALCULATE ALL require
    /// authentication while an access key is set (YKOATH §VALIDATE); otherwise `6982`.
    fn require_auth(&self) -> Result<(), u16> {
        if self.is_authorized() {
            Ok(())
        } else {
            Err(sw::SECURITY_STATUS)
        }
    }

    /// Persist `next` and adopt it, or keep the current state and answer `6581`
    /// (`docs/DESIGN.md` §7 commit rule).
    fn commit(&mut self, next: State, host: &mut dyn Host) -> Result<(), u16> {
        host.persist(Record::Oath, &next.encode())
            .map_err(|_| sw::MEMORY_FAILURE)?;
        self.state = next;
        Ok(())
    }

    /// Start serving `data` in pieces of at most `max` bytes (`61xx`, YKOATH §SEND
    /// REMAINING).
    fn respond(&mut self, data: Vec<u8>, max: usize, bound: bool) -> Vec<u8> {
        self.session.queue_revision = self.revision;
        self.session.queue_bound = bound;
        self.session.queue.start(data, sw::OK, max)
    }

    fn dispatch(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        match cmd.ins {
            ins::PUT => self.put(cmd, host),
            ins::DELETE => self.delete(cmd, host),
            ins::SET_CODE => self.set_code(cmd, host),
            ins::RESET => self.reset_application(cmd, host),
            ins::RENAME => self.rename(cmd, host),
            ins::LIST => self.list(cmd),
            ins::CALCULATE => self.calculate(cmd, host),
            ins::VALIDATE => self.validate(cmd),
            ins::CALCULATE_ALL => self.calculate_all(cmd, host),
            _ => Err(sw::INS_NOT_SUPPORTED),
        }
    }

    /// YKOATH §PUT: add a credential or overwrite the one with the same name.
    ///
    /// Data: `71` name (1..=64 bytes, any byte values), `73` type/algorithm, digits
    /// and key, optional `78` property byte, optional `7A` initial moving factor.
    /// Model policy (catalog "four-byte HOTP-only IMF, singleton property and
    /// required/allowed TLV syntax"): name and key are required; every field appears
    /// at most once; the property may only hold the only-increasing and touch bits;
    /// the IMF is exactly four bytes and only valid for HOTP; digits are 6..=8
    /// (RFC 4226 §5.3); the secret is at least [`MIN_SECRET_LEN`] bytes. Keys longer
    /// than the hash block are stored hashed (RFC 2104 §2). An overwrite keeps the
    /// credential's list position and does not need a free slot.
    fn put(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        expect_p1p2(cmd, 0x00, 0x00)?;
        self.require_auth()?;
        let [name, key, property, imf] = request::pick(&cmd.data, [tag::NAME, tag::KEY, tag::PROPERTY, tag::IMF])?;
        let name = name.ok_or(sw::INCORRECT_DATA)?;
        check_name(name)?;
        let key = key.ok_or(sw::INCORRECT_DATA)?;
        let (&type_alg, rest) = key.split_first().ok_or(sw::INCORRECT_DATA)?;
        let (&digits, secret) = rest.split_first().ok_or(sw::INCORRECT_DATA)?;
        let kind = Kind::from_code(type_alg & 0xF0).ok_or(sw::INCORRECT_DATA)?;
        let alg = Alg::from_code(type_alg & 0x0F).ok_or(sw::INCORRECT_DATA)?;
        if !DIGITS_RANGE.contains(&digits) || secret.len() < MIN_SECRET_LEN {
            return Err(sw::INCORRECT_DATA);
        }
        let props = match property {
            None => 0,
            Some([byte]) if byte & !PROP_ALL == 0 => *byte,
            Some(_) => return Err(sw::INCORRECT_DATA),
        };
        let counter = match (imf, kind) {
            (None, _) => 0,
            (Some(&[a, b, c, d]), Kind::Hotp) => u64::from(u32::from_be_bytes([a, b, c, d])),
            (Some(_), _) => return Err(sw::INCORRECT_DATA),
        };
        let cred = Credential {
            name: name.to_vec(),
            kind,
            alg,
            digits,
            key: alg.shorten(secret),
            props,
            counter,
            last_challenge: Vec::new(),
        };
        let mut next = self.state.clone();
        match next.find(name) {
            Some(index) => {
                if let Some(slot) = next.creds.get_mut(index) {
                    *slot = cred;
                }
            }
            None if next.creds.len() >= MAX_CREDENTIALS => return Err(sw::NO_SPACE),
            None => next.creds.push(cred),
        }
        self.commit(next, host)?;
        Ok(Reply::Ok)
    }

    /// YKOATH §DELETE: data `71` name; `6984` if there is no such credential
    /// (`oath_profile.missing_credential_status`).
    fn delete(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        expect_p1p2(cmd, 0x00, 0x00)?;
        self.require_auth()?;
        let [name] = request::pick(&cmd.data, [tag::NAME])?;
        let name = name.ok_or(sw::INCORRECT_DATA)?;
        let index = self.state.find(name).ok_or(sw::DATA_INVALID)?;
        let mut next = self.state.clone();
        next.creds.remove(index);
        self.commit(next, host)?;
        Ok(Reply::Ok)
    }

    /// YKOATH §SET CODE: set or remove the access key.
    ///
    /// Data `73` algorithm byte and key, `74` challenge, `75` response. The host
    /// proves the key with `HMAC(key, challenge)`; the challenge is exactly
    /// [`SET_CODE_CHALLENGE_LEN`] bytes and the response is one HMAC output long (20
    /// bytes for SHA-1, `oath_profile.authentication_proof_length`). A wrong proof is
    /// `6984` (`oath_profile.set_code_mismatch_status`). An empty key (`73 00`)
    /// removes authentication. Only the algorithm nibble of the first key byte is
    /// interpreted (clients send `21`, TOTP|SHA-1). The session that set the key stays
    /// authorized under the new revision, since it just proved the key. Hosts rely on
    /// this: yubikit `OathSession.set_key` re-selects and validates only for the NEO
    /// (firmware below 3.0, its "NEO unlock workaround"), and Yubico Authenticator keeps
    /// using the same session after setting a password.
    fn set_code(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        expect_p1p2(cmd, 0x00, 0x00)?;
        self.require_auth()?;
        let [key, challenge, response] = request::pick(&cmd.data, [tag::KEY, tag::CHALLENGE, tag::RESPONSE])?;
        let key = key.ok_or(sw::INCORRECT_DATA)?;
        let mut next = self.state.clone();
        if key.is_empty() {
            if challenge.is_some() || response.is_some() {
                return Err(sw::INCORRECT_DATA);
            }
            next.access_key = None;
        } else {
            let (&code, secret) = key.split_first().ok_or(sw::INCORRECT_DATA)?;
            let alg = Alg::from_code(code & 0x0F).ok_or(sw::INCORRECT_DATA)?;
            if secret.is_empty() {
                return Err(sw::INCORRECT_DATA);
            }
            let challenge = challenge
                .filter(|c| c.len() == SET_CODE_CHALLENGE_LEN)
                .ok_or(sw::INCORRECT_DATA)?;
            let response = response
                .filter(|r| r.len() == alg.output_len())
                .ok_or(sw::INCORRECT_DATA)?;
            let stored = alg.shorten(secret);
            let expected = alg.hmac(&stored, challenge);
            if !lk_crypto::ct_eq(&expected, response) {
                return Err(sw::DATA_INVALID);
            }
            next.access_key = Some(AccessKey { alg, key: stored });
        }
        let has_key = next.access_key.is_some();
        self.commit(next, host)?;
        self.revision = self.revision.wrapping_add(1);
        self.session.authorized = has_key.then_some(self.revision);
        self.session.challenge = None;
        Ok(Reply::Ok)
    }

    /// YKOATH §RESET (P1 `DE`, P2 `AD`): delete every credential and the access key and
    /// pick a new salt, so the device id changes. It needs no authentication; that is
    /// how a forgotten access key is recovered (catalog: "locked app reset rotates
    /// OATH salt"). Only the OATH record is written.
    fn reset_application(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        expect_p1p2(cmd, 0xDE, 0xAD)?;
        expect_no_data(cmd)?;
        let next = State::factory(host);
        self.commit(next, host)?;
        self.revision = self.revision.wrapping_add(1);
        self.session.authorized = None;
        self.session.challenge = None;
        Ok(Reply::Ok)
    }

    /// YKOATH §RENAME: data `71` current name, `71` new name. `6984` if the current
    /// name does not exist; `6A80` if the new name is invalid or belongs to another
    /// credential (model policy). Renaming needs no free slot, so it works at full
    /// capacity. Renaming a credential to its own name changes nothing.
    fn rename(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        expect_p1p2(cmd, 0x00, 0x00)?;
        self.require_auth()?;
        let fields = request::parse_fields(&cmd.data)?;
        let (old, new) = match fields.as_slice() {
            [a, b] if a.tag == tag::NAME && b.tag == tag::NAME => (a.value, b.value),
            _ => return Err(sw::INCORRECT_DATA),
        };
        check_name(new)?;
        let index = self.state.find(old).ok_or(sw::DATA_INVALID)?;
        if old == new {
            return Ok(Reply::Ok);
        }
        if self.state.find(new).is_some() {
            return Err(sw::INCORRECT_DATA);
        }
        let mut next = self.state.clone();
        if let Some(cred) = next.creds.get_mut(index) {
            cred.name = new.to_vec();
        }
        self.commit(next, host)?;
        Ok(Reply::Ok)
    }

    /// YKOATH §LIST: one `72` object per credential holding the type/algorithm byte and
    /// the name, in list order. Long lists continue with `61xx` and SEND REMAINING.
    fn list(&mut self, cmd: &Command) -> Handled {
        expect_p1p2(cmd, 0x00, 0x00)?;
        self.require_auth()?;
        expect_no_data(cmd)?;
        let mut out = Vec::new();
        for cred in &self.state.creds {
            let mut value = Vec::with_capacity(1 + cred.name.len());
            value.push(cred.type_alg());
            value.extend_from_slice(&cred.name);
            put_tlv(&mut out, tag::NAME_LIST, &value);
        }
        Ok(Reply::Data(out))
    }

    /// YKOATH §CALCULATE: data `71` name and `74` challenge; P2 `00` answers `75`
    /// (digits and the full HMAC), P2 `01` answers `76` (digits and the dynamic
    /// truncation of RFC 4226 §5.3).
    ///
    /// - TOTP: the HMAC is taken over the challenge, which the host sets to the time
    ///   step `T` (RFC 6238 §4.2). With "only increasing", a challenge lower than the
    ///   last one is `6982`; an equal one is allowed so a client can show the current
    ///   step again (model policy for YKOATH §PUT "always higher").
    /// - HOTP: the challenge is ignored (it may be empty or absent) and the HMAC is
    ///   taken over the 8-byte counter (RFC 4226 §5.2). The next counter is persisted
    ///   before the code is returned (`docs/DESIGN.md` §7).
    /// - A touch credential answers [`Outcome::NeedTouch`] after these checks; the code
    ///   is computed (and an HOTP counter consumed) only when the touch arrives.
    fn calculate(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        let truncated = truncation_flag(cmd)?;
        self.require_auth()?;
        let [name, challenge] = request::pick(&cmd.data, [tag::NAME, tag::CHALLENGE])?;
        let name = name.ok_or(sw::INCORRECT_DATA)?;
        if challenge.is_some_and(|c| c.len() > MAX_CHALLENGE_LEN) {
            return Err(sw::INCORRECT_DATA);
        }
        let index = self.state.find(name).ok_or(sw::DATA_INVALID)?;
        let cred = self.state.creds.get(index).ok_or(sw::DATA_INVALID)?;
        let challenge = match (cred.kind, challenge) {
            (Kind::Totp, None) => return Err(sw::INCORRECT_DATA),
            (_, c) => c.unwrap_or(&[]),
        };
        check_calculation(cred, challenge)?;
        if cred.requires_touch() {
            self.session.touch = Some(TouchRequest {
                name: name.to_vec(),
                challenge: challenge.to_vec(),
                truncated,
                max: response_max(cmd),
                revision: self.revision,
            });
            return Ok(Reply::Touch);
        }
        self.calculate_now(index, challenge, truncated, host).map(Reply::Data)
    }

    /// Compute the code of credential `index`, persisting a new HOTP counter or "only
    /// increasing" challenge first; returns the encoded `75`/`76` object.
    fn calculate_now(&mut self, index: usize, challenge: &[u8], truncated: bool, host: &mut dyn Host) -> Result<Vec<u8>, u16> {
        let cred = self.state.creds.get(index).ok_or(sw::DATA_INVALID)?;
        check_calculation(cred, challenge)?;
        let (message, next) = match cred.kind {
            Kind::Hotp => {
                let following = cred.counter.checked_add(1).ok_or(sw::CONDITIONS)?;
                let mut next = self.state.clone();
                if let Some(c) = next.creds.get_mut(index) {
                    c.counter = following;
                }
                (cred.counter.to_be_bytes().to_vec(), Some(next))
            }
            Kind::Totp => {
                let raises = cred.only_increasing()
                    && compare_challenges(challenge, &cred.last_challenge) == Ordering::Greater;
                let next = raises.then(|| {
                    let mut next = self.state.clone();
                    if let Some(c) = next.creds.get_mut(index) {
                        c.last_challenge = challenge.to_vec();
                    }
                    next
                });
                (challenge.to_vec(), next)
            }
        };
        let (response_tag, value) = code_response(cred.digits, &cred.hmac(&message), truncated)?;
        if let Some(next) = next {
            self.commit(next, host)?;
        }
        // At its final size, so no reallocation frees a copy of a full code.
        let mut out = Vec::with_capacity(tlv_len(value.len()));
        put_tlv(&mut out, response_tag, &value);
        Ok(out)
    }

    /// YKOATH §VALIDATE: mutual challenge-response with the access key.
    ///
    /// Data `75` the host's response to the SELECT challenge and `74` the host's own
    /// challenge (1..=[`MAX_CHALLENGE_LEN`] bytes, "variable VALIDATE challenge"). On a
    /// match the session is authorized and the answer is `75 HMAC(key, host
    /// challenge)`.
    ///
    /// - Without an access key the status is `6984` ("auth not enabled",
    ///   `oath_profile.validate_without_access_code_status`).
    /// - A wrong response is `6A80`. YKOATH §VALIDATE lists only "auth not enabled"
    ///   `6984` and "wrong syntax" `6A80` as failures, and the catalog fixes no status
    ///   for a wrong proof. Public YKOATH clients report "wrong password" only for
    ///   `6A80`. A failed attempt also drops an earlier authorization.
    ///
    /// The SELECT challenge stays valid for the whole selection, so a client may retry
    /// with another password.
    fn validate(&mut self, cmd: &Command) -> Handled {
        expect_p1p2(cmd, 0x00, 0x00)?;
        let Some(key) = self.state.access_key.as_ref() else {
            return Err(sw::DATA_INVALID);
        };
        let [response, challenge] = request::pick(&cmd.data, [tag::RESPONSE, tag::CHALLENGE])?;
        let response = response
            .filter(|r| r.len() == key.alg.output_len())
            .ok_or(sw::INCORRECT_DATA)?;
        let challenge = challenge
            .filter(|c| (1..=MAX_CHALLENGE_LEN).contains(&c.len()))
            .ok_or(sw::INCORRECT_DATA)?;
        let Some(device_challenge) = self.session.challenge else {
            return Err(sw::DATA_INVALID);
        };
        // The expected proof would authenticate this selection; it and the device's
        // own proof are wiped when dropped (`Alg::hmac`).
        let expected = key.alg.hmac(&key.key, &device_challenge);
        if !lk_crypto::ct_eq(&expected, response) {
            self.session.authorized = None;
            return Err(sw::INCORRECT_DATA);
        }
        let proof = key.alg.hmac(&key.key, challenge);
        let mut out = Vec::with_capacity(tlv_len(proof.len()));
        put_tlv(&mut out, tag::RESPONSE, &proof);
        self.session.authorized = Some(self.revision);
        Ok(Reply::Data(out))
    }

    /// YKOATH §CALCULATE ALL: data `74` challenge; P2 as for CALCULATE.
    ///
    /// For each credential in list order: `71` name, then `75`/`76` for a TOTP
    /// credential, `77 digits` for HOTP and `7C digits` for a touch credential. The
    /// placeholders consume nothing: no HOTP counter step and no touch (catalog
    /// "HOTP/touch placeholders without HOTP counter consumption"); HOTP takes
    /// precedence over touch because clients infer the type from `77`. An "only
    /// increasing" TOTP credential whose last challenge is higher fails the whole
    /// command with `6982`; raised challenges are persisted before the answer.
    fn calculate_all(&mut self, cmd: &Command, host: &mut dyn Host) -> Handled {
        let truncated = truncation_flag(cmd)?;
        self.require_auth()?;
        let [challenge] = request::pick(&cmd.data, [tag::CHALLENGE])?;
        let challenge = challenge
            .filter(|c| c.len() <= MAX_CHALLENGE_LEN)
            .ok_or(sw::INCORRECT_DATA)?;
        // Allocated for the longest answer, so no reallocation frees a copy of a full
        // code (`docs/DESIGN.md` §8).
        let mut out = Vec::with_capacity(calculate_all_capacity(&self.state.creds));
        let mut next: Option<State> = None;
        for (index, cred) in self.state.creds.iter().enumerate() {
            put_tlv(&mut out, tag::NAME, &cred.name);
            if cred.kind == Kind::Hotp {
                put_tlv(&mut out, tag::HOTP, &[cred.digits]);
                continue;
            }
            if cred.requires_touch() {
                put_tlv(&mut out, tag::TOUCH, &[cred.digits]);
                continue;
            }
            if cred.only_increasing() {
                match compare_challenges(challenge, &cred.last_challenge) {
                    Ordering::Less => return Err(sw::SECURITY_STATUS),
                    Ordering::Greater => {
                        let pending = next.get_or_insert_with(|| self.state.clone());
                        if let Some(c) = pending.creds.get_mut(index) {
                            c.last_challenge = challenge.to_vec();
                        }
                    }
                    Ordering::Equal => {}
                }
            }
            let (response_tag, value) = code_response(cred.digits, &cred.hmac(challenge), truncated)?;
            put_tlv(&mut out, response_tag, &value);
        }
        if let Some(next) = next {
            self.commit(next, host)?;
        }
        Ok(Reply::Data(out))
    }

    /// YKOATH §SEND REMAINING (`00 A5 00 00`): the next piece of a response that ended
    /// with `61xx`.
    ///
    /// Any CLA other than `00` (statuses as in [`check_cla`]; the chaining bit is not
    /// allowed either), wrong P1/P2 or command data is refused *without* consuming the
    /// pending response (catalog "SEND REMAINING rejects nonzero CLA before consuming a
    /// pending response"). A continuation produced under an older authorization
    /// revision, or one that needs an authorization the session no longer has, is
    /// dropped with `6982` (catalog "pending LIST continuation reject after another
    /// client changes the code"). With nothing pending the answer is `6985` (model
    /// policy).
    fn send_remaining(&mut self, cmd: &Command) -> Vec<u8> {
        if let Err(status) = check_cla(cmd.cla, false) {
            return apdu::status(status);
        }
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        if !cmd.data.is_empty() {
            return apdu::status(sw::WRONG_LENGTH);
        }
        let stale = self.session.queue_revision != self.revision || (self.session.queue_bound && !self.is_authorized());
        if self.session.queue.is_pending() && stale {
            self.session.queue.clear();
            return apdu::status(sw::SECURITY_STATUS);
        }
        self.session
            .queue
            .next(response_max(cmd))
            .unwrap_or_else(|| apdu::status(sw::CONDITIONS))
    }

    /// Drop everything scoped to the selection: authorization, challenge, chaining,
    /// pending responses and a pending touch.
    fn end_session(&mut self) {
        self.session = Session::new();
    }
}

impl CardApplet for Oath {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    /// YKOATH §SELECT: `79` version (the profile's firmware version), `71` the 8-byte
    /// device id / PBKDF2 salt, and while an access key is set `74` a fresh 8-byte
    /// challenge and `7B` the key's algorithm. Selecting starts a new session, so any
    /// earlier authorization is gone.
    fn select(&mut self, apdu: &[u8], host: &mut dyn Host) -> Vec<u8> {
        self.end_session();
        let max = Command::parse(apdu).map_or(DEFAULT_RESPONSE_MAX, |cmd| response_max(&cmd));
        let mut data = Vec::new();
        put_tlv(&mut data, tag::VERSION, &host.profile().firmware.bytes());
        put_tlv(&mut data, tag::NAME, &self.state.salt);
        if let Some(key) = &self.state.access_key {
            let mut challenge = [0u8; 8];
            host.fill(&mut challenge);
            put_tlv(&mut data, tag::CHALLENGE, &challenge);
            put_tlv(&mut data, tag::ALGORITHM, &[key.alg.code()]);
            self.session.challenge = Some(challenge);
        }
        self.respond(data, max, false)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        // The device never sends a command while a touch is pending; if one arrives
        // anyway, the waiting calculation is abandoned.
        self.session.touch = None;
        let cmd = match Command::parse(apdu) {
            Ok(cmd) => cmd,
            Err(err) => {
                self.session.chain.clear();
                self.session.queue.clear();
                return Outcome::Done(apdu::status(err.sw()));
            }
        };
        if cmd.ins == ins::SEND_REMAINING && !self.session.chain.is_active() {
            return Outcome::Done(self.send_remaining(&cmd));
        }
        // Any other command ends a pending response (ISO/IEC 7816-4 §5.1.3).
        self.session.queue.clear();
        if let Err(status) = check_cla(cmd.cla, true) {
            self.session.chain.clear();
            return Outcome::Done(apdu::status(status));
        }
        let cmd = match self.session.chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => return Outcome::Done(apdu::status(sw::OK)),
            Err(err) => return Outcome::Done(apdu::status(err.sw())),
        };
        let max = response_max(&cmd);
        match self.dispatch(&cmd, host) {
            Ok(Reply::Data(data)) => Outcome::Done(self.respond(data, max, true)),
            Ok(Reply::Ok) => Outcome::Done(apdu::status(sw::OK)),
            Ok(Reply::Touch) => Outcome::NeedTouch {
                timeout_ms: TOUCH_TIMEOUT_MS,
            },
            Err(status) => Outcome::Done(apdu::status(status)),
        }
    }

    /// Finish a CALCULATE of a touch credential. Without a touch (timeout, cancel,
    /// reset) the answer is `6982`, which clients report as a touch timeout; nothing
    /// is consumed.
    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8> {
        let Some(request) = self.session.touch.take() else {
            return apdu::status(sw::CONDITIONS);
        };
        if !touched || request.revision != self.revision || !self.is_authorized() {
            return apdu::status(sw::SECURITY_STATUS);
        }
        let Some(index) = self.state.find(&request.name) else {
            return apdu::status(sw::DATA_INVALID);
        };
        match self.calculate_now(index, &request.challenge, request.truncated, host) {
            Ok(data) => self.respond(data, request.max, true),
            Err(status) => apdu::status(status),
        }
    }

    fn deselect(&mut self) {
        self.end_session();
    }

    /// Every reset kind ends the card session; OATH keeps no other volatile state.
    fn reset(&mut self, _kind: ResetKind) {
        self.end_session();
    }
}

/// Append a YKOATH data object (one-byte tag, BER-TLV length).
fn put_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    tlv::encode_into(out, u32::from(tag), value);
}

/// Check the class byte (ISO/IEC 7816-4 §5.1.1). YKOATH commands use CLA `00`; with
/// `chaining` the command-chaining bit `10` (§5.1.1.1) is also accepted.
///
/// - A class outside the first interindustry range (`80`, `40`, ...) is `6E00`.
/// - Secure-messaging bits are `6882` ("secure messaging not supported", §5.6). The
///   device's secure channel clears them after unwrapping, so a command that still
///   has them was never verified.
/// - A logical channel number is `6881` ("logical channel not supported", §5.6).
/// - The chaining bit where chaining is not allowed (SEND REMAINING) is `6E00`.
///
/// These statuses follow ISO/IEC 7816-4 and the device's PIV applet (model policy:
/// the reference statuses are unmeasured).
fn check_cla(cla: u8, chaining: bool) -> Result<(), u16> {
    let base = if chaining { cla & !CLA_CHAIN } else { cla };
    if base == 0 {
        Ok(())
    } else if cla & CLA_CLASS != 0 {
        Err(sw::CLA_NOT_SUPPORTED)
    } else if cla & CLA_SM != 0 {
        Err(sw::SM_NOT_SUPPORTED)
    } else if cla & CLA_CHANNEL != 0 {
        Err(sw::LOGICAL_CHANNEL_NOT_SUPPORTED)
    } else {
        Err(sw::CLA_NOT_SUPPORTED)
    }
}

/// P1/P2 must be exactly the given values; otherwise `6A86` (catalog "command P1/P2
/// validation").
fn expect_p1p2(cmd: &Command, p1: u8, p2: u8) -> Result<(), u16> {
    if cmd.p1 == p1 && cmd.p2 == p2 {
        Ok(())
    } else {
        Err(sw::INCORRECT_P1P2)
    }
}

/// Commands without a data field refuse one with `6700` (ISO/IEC 7816-4 §5.1.3).
fn expect_no_data(cmd: &Command) -> Result<(), u16> {
    if cmd.data.is_empty() {
        Ok(())
    } else {
        Err(sw::WRONG_LENGTH)
    }
}

/// CALCULATE / CALCULATE ALL: P1 `00`, P2 `00` full or `01` truncated (YKOATH
/// §CALCULATE).
fn truncation_flag(cmd: &Command) -> Result<bool, u16> {
    match (cmd.p1, cmd.p2) {
        (0x00, 0x00) => Ok(false),
        (0x00, 0x01) => Ok(true),
        _ => Err(sw::INCORRECT_P1P2),
    }
}

/// A credential name is 1..=64 bytes (YKOATH §PUT).
fn check_name(name: &[u8]) -> Result<(), u16> {
    if (1..=MAX_NAME_LEN).contains(&name.len()) {
        Ok(())
    } else {
        Err(sw::INCORRECT_DATA)
    }
}

/// Whether `cred` may be calculated with `challenge` now: an HOTP counter must not be
/// exhausted (`6985`, catalog "64-bit HOTP terminal counter"), an "only increasing"
/// TOTP challenge must not go down (`6982`).
fn check_calculation(cred: &Credential, challenge: &[u8]) -> Result<(), u16> {
    match cred.kind {
        Kind::Hotp if cred.counter == HOTP_EXHAUSTED => Err(sw::CONDITIONS),
        Kind::Totp
            if cred.only_increasing() && compare_challenges(challenge, &cred.last_challenge) == Ordering::Less =>
        {
            Err(sw::SECURITY_STATUS)
        }
        _ => Ok(()),
    }
}

/// The response object for one code: tag `75` with digits and the full MAC, or tag
/// `76` with digits and the four truncated bytes (YKOATH §CALCULATE, RFC 4226 §5.3).
fn code_response(digits: u8, mac: &[u8], truncated: bool) -> Result<(u8, SecretBytes), u16> {
    let short;
    let (tag, code): (u8, &[u8]) = if truncated {
        short = dynamic_truncate(mac).ok_or(sw::UNKNOWN)?;
        (tag::TRUNCATED, &short)
    } else {
        (tag::RESPONSE, mac)
    };
    // The full response is the whole MAC: built at its final size and wiped when
    // dropped (`docs/DESIGN.md` §8).
    let mut value = SecretBytes::zeroed(1 + code.len());
    if let Some((first, rest)) = value.split_first_mut() {
        *first = digits;
        rest.copy_from_slice(code);
    }
    Ok((tag, value))
}

/// The most CALCULATE ALL can answer for `creds`: per credential the `71` name and a
/// full `75` response (digits and the whole MAC), which is longer than the `76`, `77`
/// and `7C` objects (5, 1 and 1 value bytes against at least 21).
fn calculate_all_capacity(creds: &[Credential]) -> usize {
    creds
        .iter()
        .map(|cred| tlv_len(cred.name.len()) + tlv_len(1 + cred.alg.output_len()))
        .sum()
}

/// Response piece size: Ne of the command, or 256 without Le (ISO/IEC 7816-4 §5.1).
fn response_max(cmd: &Command) -> usize {
    cmd.expected_len().unwrap_or(DEFAULT_RESPONSE_MAX).max(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Internal-state tests: states a client cannot reach through APDUs alone.

    use super::*;
    use lk_testkit::TestHost;

    fn ok(apdu: &[u8], oath: &mut Oath, host: &mut TestHost) -> Vec<u8> {
        match oath.process(apdu, host) {
            Outcome::Done(resp) => resp,
            Outcome::NeedTouch { .. } => panic!("unexpected touch"),
        }
    }

    fn put_hotp(name: &[u8]) -> Vec<u8> {
        let mut data = vec![0x71, name.len() as u8];
        data.extend_from_slice(name);
        data.extend_from_slice(&[0x73, 22, 0x11, 6]);
        data.extend_from_slice(b"12345678901234567890");
        let mut apdu = vec![0x00, 0x01, 0x00, 0x00, data.len() as u8];
        apdu.extend_from_slice(&data);
        apdu
    }

    fn calc(name: &[u8]) -> Vec<u8> {
        let mut data = vec![0x71, name.len() as u8];
        data.extend_from_slice(name);
        data.extend_from_slice(&[0x74, 0x00]);
        let mut apdu = vec![0x00, 0xA2, 0x00, 0x01, data.len() as u8];
        apdu.extend_from_slice(&data);
        apdu
    }

    /// Catalog: "64-bit HOTP terminal counter rejects the exhausted next-counter
    /// sentinel". RFC 4226 §5.1: C is an 8-byte counter. The last usable counter
    /// `u64::MAX - 1` still produces a code and leaves the sentinel `u64::MAX`, after
    /// which CALCULATE is refused with `6985` and nothing is written.
    #[test]
    fn hotp_terminal_counter_is_refused() {
        let mut host = TestHost::new();
        let mut oath = Oath::new(None, &mut host);
        assert_eq!(ok(&put_hotp(b"h"), &mut oath, &mut host), vec![0x90, 0x00]);
        let mut state = oath.state.clone();
        state.creds[0].counter = u64::MAX - 1;
        host.set_persisted(Record::Oath, &state.encode());
        let mut oath = Oath::new(host.persisted(Record::Oath).as_deref(), &mut host);

        let resp = ok(&calc(b"h"), &mut oath, &mut host);
        assert_eq!(resp.len(), 2 + 5 + 2);
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00]);
        let stored = State::decode(&host.persisted(Record::Oath).unwrap()).unwrap();
        assert_eq!(stored.creds[0].counter, u64::MAX);

        let attempts = host.persist_attempts();
        assert_eq!(ok(&calc(b"h"), &mut oath, &mut host), vec![0x69, 0x85]);
        assert_eq!(host.persist_attempts(), attempts);
        // Restarting does not revive the credential.
        let mut oath = Oath::new(host.persisted(Record::Oath).as_deref(), &mut host);
        assert_eq!(ok(&calc(b"h"), &mut oath, &mut host), vec![0x69, 0x85]);
        // CALCULATE ALL still lists it with the HOTP placeholder.
        let all = ok(&[0x00, 0xA4, 0x00, 0x01, 0x02, 0x74, 0x00], &mut oath, &mut host);
        assert_eq!(all, vec![0x71, 0x01, b'h', 0x77, 0x01, 0x06, 0x90, 0x00]);
    }

    /// Catalog: "Per-client OATH authorization is bound to current salt, access key and
    /// rotation revision; stale PUT and pending LIST continuation reject after another
    /// client changes the code". Within one card session another client cannot
    /// interleave, so the rotation another client would cause is simulated by bumping
    /// the revision directly.
    #[test]
    fn stale_authorization_and_continuation_are_refused() {
        let mut host = TestHost::new();
        let mut oath = Oath::new(None, &mut host);
        for i in 0..8u8 {
            let name = [b'n'; 60].iter().copied().chain([i]).collect::<Vec<_>>();
            assert_eq!(ok(&put_hotp(&name), &mut oath, &mut host), vec![0x90, 0x00]);
        }
        // Give the state an access key and authorize this session at revision 0.
        oath.state.access_key = Some(AccessKey {
            alg: Alg::Sha1,
            key: SecretBytes::new(vec![1; 16]),
        });
        oath.session.authorized = Some(oath.revision);

        let first = ok(&[0x00, 0xA1, 0x00, 0x00], &mut oath, &mut host);
        assert_eq!(first[first.len() - 2], 0x61);
        // Another client changes the code.
        oath.revision += 1;
        assert_eq!(ok(&[0x00, 0xA5, 0x00, 0x00], &mut oath, &mut host), vec![0x69, 0x82]);
        // The continuation is gone, and so is the authorization.
        assert_eq!(ok(&[0x00, 0xA5, 0x00, 0x00], &mut oath, &mut host), vec![0x69, 0x85]);
        assert_eq!(ok(&put_hotp(b"late"), &mut oath, &mut host), vec![0x69, 0x82]);
    }

    /// Same catalog bullet, for a calculation waiting for a touch: if the authorization
    /// it was requested under goes stale before the touch arrives (another client
    /// rotated the code, simulated by bumping the revision), the touch is refused with
    /// `6982` and the HOTP counter is neither consumed nor persisted.
    #[test]
    fn stale_authorization_refuses_a_pending_touch() {
        let mut host = TestHost::new();
        let mut oath = Oath::new(None, &mut host);
        let mut put = put_hotp(b"t");
        // Add the property `78 02` (require touch) and fix Lc.
        put.extend_from_slice(&[0x78, 0x02]);
        put[4] += 2;
        assert_eq!(ok(&put, &mut oath, &mut host), vec![0x90, 0x00]);
        oath.state.access_key = Some(AccessKey {
            alg: Alg::Sha1,
            key: SecretBytes::new(vec![1; 16]),
        });
        oath.session.authorized = Some(oath.revision);

        assert!(matches!(oath.process(&calc(b"t"), &mut host), Outcome::NeedTouch { .. }));
        oath.revision += 1;
        let attempts = host.persist_attempts();
        assert_eq!(oath.touch_resolved(true, &mut host), vec![0x69, 0x82]);
        assert_eq!(host.persist_attempts(), attempts);
        assert_eq!(oath.state.creds[0].counter, 0);

        // Losing the authorization itself (a failed VALIDATE in the real flow) has the
        // same effect.
        oath.session.authorized = Some(oath.revision);
        assert!(matches!(oath.process(&calc(b"t"), &mut host), Outcome::NeedTouch { .. }));
        oath.session.authorized = None;
        assert_eq!(oath.touch_resolved(true, &mut host), vec![0x69, 0x82]);
        assert_eq!(host.persist_attempts(), attempts);
        assert_eq!(oath.state.creds[0].counter, 0);
    }

    /// ISO/IEC 7816-4 §5.1.1 class byte rules of [`check_cla`].
    #[test]
    fn class_byte_rules() {
        assert_eq!(check_cla(0x00, false), Ok(()));
        assert_eq!(check_cla(0x00, true), Ok(()));
        assert_eq!(check_cla(0x10, true), Ok(()));
        assert_eq!(check_cla(0x10, false), Err(sw::CLA_NOT_SUPPORTED));
        for sm in [0x04, 0x08, 0x0C, 0x14, 0x1C, 0x0D] {
            assert_eq!(check_cla(sm, true), Err(sw::SM_NOT_SUPPORTED), "{sm:02X}");
            assert_eq!(check_cla(sm, false), Err(sw::SM_NOT_SUPPORTED), "{sm:02X}");
        }
        for channel in [0x01, 0x02, 0x03, 0x11] {
            assert_eq!(check_cla(channel, true), Err(sw::LOGICAL_CHANNEL_NOT_SUPPORTED), "{channel:02X}");
        }
        for other in [0x20, 0x40, 0x80, 0x84, 0x90, 0xFF] {
            assert_eq!(check_cla(other, true), Err(sw::CLA_NOT_SUPPORTED), "{other:02X}");
            assert_eq!(check_cla(other, false), Err(sw::CLA_NOT_SUPPORTED), "{other:02X}");
        }
    }

    /// Full codes are whole MACs (YKOATH §CALCULATE, P2 `00`), which a host can use as
    /// key-derived secrets, so the answers holding them are built at their final size:
    /// a buffer whose length equals its starting capacity was never reallocated, so no
    /// unwiped copy was freed (`docs/DESIGN.md` §8). TOTP credentials without touch are
    /// the case where `calculate_all_capacity` is exact.
    #[test]
    fn code_answers_are_allocated_at_their_final_size() {
        let mut host = TestHost::new();
        let mut oath = Oath::new(None, &mut host);
        for (name, alg) in [(&b"one"[..], Alg::Sha1), (&[b'x'; MAX_NAME_LEN][..], Alg::Sha256), (b"512", Alg::Sha512)] {
            oath.state.creds.push(Credential {
                name: name.to_vec(),
                kind: Kind::Totp,
                alg,
                digits: 6,
                key: SecretBytes::new(vec![0x3C; 32]),
                props: 0,
                counter: 0,
                last_challenge: Vec::new(),
            });
        }
        let challenge = [0, 0, 0, 0, 0x03, 0x5B, 0xB5, 0x2A];
        let mut apdu = vec![0x00, 0xA4, 0x00, 0x00, 10, 0x74, 8];
        apdu.extend_from_slice(&challenge);
        let cmd = Command::parse(&apdu).unwrap();
        let Ok(Reply::Data(all)) = oath.calculate_all(&cmd, &mut host) else {
            panic!("CALCULATE ALL failed");
        };
        assert_eq!(all.len(), calculate_all_capacity(&oath.state.creds));
        assert_eq!(all.capacity(), all.len());
        for index in 0..oath.state.creds.len() {
            for truncated in [false, true] {
                let code = oath.calculate_now(index, &challenge, truncated, &mut host).unwrap();
                assert_eq!(code.capacity(), code.len(), "credential {index}, truncated {truncated}");
            }
        }
    }

    #[test]
    fn debug_output_hides_secrets() {
        let mut host = TestHost::new();
        let mut oath = Oath::new(None, &mut host);
        ok(&put_hotp(b"h"), &mut oath, &mut host);
        let text = format!("{oath:?} {:?}", oath.state);
        assert!(!text.contains("49, 50, 51")); // "123" of the secret
        assert!(text.contains("redacted"));
    }
}
