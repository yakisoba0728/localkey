//! Commands on asymmetric key slots: GENERATE ASYMMETRIC KEY PAIR (`47`, SP 800-73-4
//! Part 2 §3.3.2), GENERAL AUTHENTICATE with a slot key (`87`, §3.2.4), and the Yubico
//! extensions IMPORT ASYMMETRIC KEY (`FE`), MOVE KEY / DELETE KEY (`F6`, firmware 5.7),
//! ATTEST (`F9`) and GET METADATA (`F7`) for key slots.
//!
//! Status words not given by the specifications or the Yubico documentation are model
//! policy (physical 5.7.4 status unmeasured) and listed in `docs/catalog/piv.md`.

use lk_codec::apdu::{Command, sw};
use lk_codec::tlv;
use lk_core::{Host, Millis};

use crate::admin::PendingTouch;
use crate::keys::{
    KeyAlg, Operation, PinPolicy, RSA_EXPONENT, SlotKey, TAG_PIN_POLICY, TAG_PUBLIC_KEY, TAG_TOUCH_POLICY, TouchPolicy,
    trimmed,
};
use crate::state::{SLOT_ATTESTATION, is_key_slot};
use crate::{Piv, Reply, Step, attest, explicit_le};

/// How long a touch satisfies the cached touch policy (Yubico PIV extensions: "Touch is
/// cached for 15s after use").
pub(crate) const TOUCH_CACHE_MS: Millis = 15_000;

/// Control reference template of GENERATE (SP 800-73-4 Part 2 Table 11): cryptographic
/// mechanism `80` and the mechanism-specific parameter `81`.
const TAG_CONTROL: u32 = 0xAC;
const TAG_ALGORITHM: u32 = 0x80;
const TAG_PARAMETER: u32 = 0x81;

/// Dynamic Authentication Template elements (SP 800-73-4 Part 2 Table 7).
const TAG_DYN_AUTH: u32 = 0x7C;
const TAG_CHALLENGE: u32 = 0x81;
const TAG_RESPONSE: u32 = 0x82;
const TAG_EXPONENTIATION: u32 = 0x85;

/// GET METADATA tags for key slots (Yubico PIV extensions, GET METADATA).
const MD_ALGORITHM: u32 = 0x01;
const MD_POLICY: u32 = 0x02;
const MD_ORIGIN: u32 = 0x03;
const MD_PUBLIC_KEY: u32 = 0x04;

/// MOVE KEY P1 that means DELETE KEY (Yubico PIV extensions).
const P1_DELETE: u8 = 0xFF;

/// `7C { 82 result }` (SP 800-73-4 Part 2 §3.2.4).
pub(crate) fn dyn_auth_response(result: &[u8]) -> Vec<u8> {
    tlv::encode(TAG_DYN_AUTH, &tlv::encode(TAG_RESPONSE, result))
}

/// Parse a slot GENERAL AUTHENTICATE request: `7C { 82 00, 81 data }` (sign or decrypt)
/// or `7C { 82 00, 85 data }` (key agreement), elements in either order (SP 800-73-4
/// Part 2 Appendix A.3-A.5: the empty `82` asks for the response). Anything else is
/// `6A80`.
fn parse_request(data: &[u8]) -> Result<(Operation, &[u8]), u16> {
    let (template, rest) = tlv::parse_one(data).map_err(|_| sw::INCORRECT_DATA)?;
    if template.tag != TAG_DYN_AUTH || !rest.is_empty() {
        return Err(sw::INCORRECT_DATA);
    }
    let items = template.children().map_err(|_| sw::INCORRECT_DATA)?;
    let (request, payload) = match items.as_slice() {
        [a, b] if a.tag == TAG_RESPONSE => (a, b),
        [a, b] if b.tag == TAG_RESPONSE => (b, a),
        _ => return Err(sw::INCORRECT_DATA),
    };
    if !request.value.is_empty() {
        return Err(sw::INCORRECT_DATA);
    }
    let op = match payload.tag {
        TAG_CHALLENGE => Operation::Challenge,
        TAG_EXPONENTIATION => Operation::Exponentiation,
        _ => return Err(sw::INCORRECT_DATA),
    };
    Ok((op, payload.value))
}

fn single(value: &[u8]) -> Result<u8, u16> {
    match value {
        [b] => Ok(*b),
        _ => Err(sw::INCORRECT_DATA),
    }
}

/// GET METADATA answer for an occupied key slot: `01` algorithm, `02` PIN policy and
/// touch policy (resolved, never "default"), `03` origin, `04` public key elements.
pub(crate) fn slot_metadata(key: &SlotKey) -> Vec<u8> {
    let mut out = tlv::encode(MD_ALGORITHM, &[key.alg.byte()]);
    tlv::encode_into(&mut out, MD_POLICY, &[key.pin.byte(), key.touch.byte()]);
    tlv::encode_into(&mut out, MD_ORIGIN, &[key.origin.byte()]);
    tlv::encode_into(&mut out, MD_PUBLIC_KEY, &key.public_elements());
    out
}

impl Piv {
    /// GENERATE ASYMMETRIC KEY PAIR (`INS 47`, SP 800-73-4 Part 2 §3.3.2): P1 `00`, P2 the
    /// slot, data `AC { 80 alg [81 parameter] [AA pin policy] [AB touch policy] }`. The
    /// mechanism-specific parameter `81` (Table 11, conditional) is accepted only for RSA
    /// and only as the public exponent 65537, the one exponent this model generates
    /// (`6A80` otherwise).
    ///
    /// Checks, in order, before anything is replaced: P1 `00` (`6A86`; catalog "GENERATE
    /// KEY PAIR rejects nonzero P1 before replacing an occupied private key"); P2 a key slot
    /// (`6A86`); management key authenticated (`6982`, Part 2 §3.3.2 access rule); the
    /// template, each element at most once, a known algorithm and valid policies (`6A80`).
    /// The attestation slot takes only the five issuer algorithms (`6A80`). The new key
    /// replaces any key in the slot and is persisted before its public key is answered as
    /// `7F49 { 81 n 82 e }` or `7F49 { 86 point }` (Part 2 Table 10). Le may be present:
    /// the command returns data, and OpenSC sends it as case 4.
    pub(crate) fn generate_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p1 != 0x00 {
            return Err(sw::INCORRECT_P1P2);
        }
        let slot = cmd.p2;
        if !is_key_slot(slot) {
            return Err(sw::INCORRECT_P1P2);
        }
        if !self.session.mgmt_authenticated {
            return Err(sw::SECURITY_STATUS);
        }
        let (template, rest) = tlv::parse_one(&cmd.data).map_err(|_| sw::INCORRECT_DATA)?;
        if template.tag != TAG_CONTROL || !rest.is_empty() {
            return Err(sw::INCORRECT_DATA);
        }
        let (mut alg, mut pin, mut touch, mut parameter) = (None, None, None, None);
        for item in template.children().map_err(|_| sw::INCORRECT_DATA)? {
            if item.tag == TAG_PARAMETER {
                if parameter.replace(item.value).is_some() {
                    return Err(sw::INCORRECT_DATA);
                }
                continue;
            }
            let target = match item.tag {
                TAG_ALGORITHM => &mut alg,
                TAG_PIN_POLICY => &mut pin,
                TAG_TOUCH_POLICY => &mut touch,
                _ => return Err(sw::INCORRECT_DATA),
            };
            if target.replace(single(item.value)?).is_some() {
                return Err(sw::INCORRECT_DATA);
            }
        }
        let alg = alg.and_then(KeyAlg::from_byte).ok_or(sw::INCORRECT_DATA)?;
        if let Some(parameter) = parameter
            && !(alg.rsa_bits().is_some() && trimmed(parameter) == RSA_EXPONENT)
        {
            return Err(sw::INCORRECT_DATA);
        }
        if slot == SLOT_ATTESTATION && !alg.can_attest() {
            return Err(sw::INCORRECT_DATA);
        }
        let pin = PinPolicy::parse(pin.unwrap_or(0), slot)?;
        let touch = TouchPolicy::parse(touch.unwrap_or(0))?;
        let key = SlotKey::generate(alg, pin, touch, host)?;
        let response = tlv::encode(TAG_PUBLIC_KEY, &key.public_elements());
        self.modify(host, |s| {
            s.slots.insert(slot, key);
        })?;
        Ok(response)
    }

    /// IMPORT ASYMMETRIC KEY (`INS FE`, Yubico extension): P1 the algorithm, P2 the slot,
    /// data the key elements (`keys::SlotKey::import`) plus optional `AA`/`AB` policies.
    ///
    /// Checks, in order: no explicit Le (`6700`; the command returns no data, catalog "PIV
    /// generate/import/PUT DATA absent-Le guards"); P1 a known algorithm and P2 a key slot
    /// (`6A86`); management key authenticated (`6982`); `F9` takes only the issuer
    /// algorithms, the elements must be well formed, complete and consistent (`6A80`).
    /// The key replaces any key in the slot; persist failure `6581`.
    pub(crate) fn import_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        let alg = KeyAlg::from_byte(cmd.p1).ok_or(sw::INCORRECT_P1P2)?;
        let slot = cmd.p2;
        if !is_key_slot(slot) {
            return Err(sw::INCORRECT_P1P2);
        }
        if !self.session.mgmt_authenticated {
            return Err(sw::SECURITY_STATUS);
        }
        if slot == SLOT_ATTESTATION && !alg.can_attest() {
            return Err(sw::INCORRECT_DATA);
        }
        let items = tlv::parse_all(&cmd.data).map_err(|_| sw::INCORRECT_DATA)?;
        let (mut pin, mut touch, mut elements) = (None, None, Vec::new());
        for item in items {
            let target = match item.tag {
                TAG_PIN_POLICY => &mut pin,
                TAG_TOUCH_POLICY => &mut touch,
                _ => {
                    elements.push(item);
                    continue;
                }
            };
            if target.replace(single(item.value)?).is_some() {
                return Err(sw::INCORRECT_DATA);
            }
        }
        let pin = PinPolicy::parse(pin.unwrap_or(0), slot)?;
        let touch = TouchPolicy::parse(touch.unwrap_or(0))?;
        let key = SlotKey::import(alg, pin, touch, &elements)?;
        self.modify(host, |s| {
            s.slots.insert(slot, key);
        })?;
        Ok(Vec::new())
    }

    /// GENERAL AUTHENTICATE with a slot key (`INS 87`, SP 800-73-4 Part 2 §3.2.4 and
    /// Appendix A.3-A.5): P1 the key's algorithm, P2 the slot.
    ///
    /// Checks, in order, all before the PIN-always authorization is consumed: P2 a key slot
    /// other than `F9` (`6A86`; model policy: the attestation key only signs attestation
    /// certificates); a key in the slot (`6A88`); P1 equal to its algorithm (`6A86`); the
    /// request template and its data (`6A80`, `keys::SlotKey::check_request`). A request
    /// rejected by these checks keeps the authorization (catalog: GENERAL AUTHENTICATE is
    /// rejected "before ... consuming PIN_ALWAYS signing authorization"). Then the PIN
    /// policy (`6982`): "once" needs the PIN verified in this session; "always" needs a
    /// successful VERIFY immediately before (`armed`; SP 800-73-4 Part 1 §3.2.1 "verified
    /// every time immediately before"; Yubico: "PIN is verified just before operation"),
    /// and the authorization is used up here, before any touch wait. Any request that
    /// reaches this point drops the authorization, whichever its slot. Touch policy
    /// "always", or "cached" with no touch in the last 15 s, answers `NeedTouch` and the
    /// operation runs in `touch_resolved`.
    ///
    /// Le may be present (Part 2 §3.2.4).
    pub(crate) fn slot_authenticate(
        &mut self,
        cmd: &Command,
        armed: bool,
        host: &mut dyn Host,
        max: usize,
    ) -> Result<Step, u16> {
        let (slot, key, op, input) = match self.check_slot_request(cmd) {
            Ok(checked) => checked,
            Err(status) => {
                self.session.pin_always = armed;
                return Err(status);
            }
        };
        let pin_ok = match key.pin {
            PinPolicy::Never => true,
            PinPolicy::Once => self.session.pin_verified,
            PinPolicy::Always => self.session.pin_verified && armed,
        };
        if !pin_ok {
            return Err(sw::SECURITY_STATUS);
        }
        let touch_needed = match key.touch {
            TouchPolicy::Never => false,
            TouchPolicy::Always => true,
            TouchPolicy::Cached => !self.touch_cached(host.now()),
        };
        if touch_needed {
            self.session.touch = Some(PendingTouch::SlotOperation { slot, op, input: input.to_vec(), max });
            return Ok(Step::Touch);
        }
        let result = key.compute(op, input, host)?;
        Ok(Step::Reply(Ok(dyn_auth_response(&result))))
    }

    /// The request checks of [`slot_authenticate`](Self::slot_authenticate) that come
    /// before the PIN policy: the slot, its key, the algorithm and the request data.
    fn check_slot_request<'a>(&self, cmd: &'a Command) -> Result<(u8, SlotKey, Operation, &'a [u8]), u16> {
        let slot = cmd.p2;
        if !is_key_slot(slot) || slot == SLOT_ATTESTATION {
            return Err(sw::INCORRECT_P1P2);
        }
        let key = self.state.slots.get(&slot).cloned().ok_or(sw::REF_NOT_FOUND)?;
        if KeyAlg::from_byte(cmd.p1) != Some(key.alg) {
            return Err(sw::INCORRECT_P1P2);
        }
        let (op, input) = parse_request(&cmd.data)?;
        key.check_request(op, input)?;
        Ok((slot, key, op, input))
    }

    /// Whether a touch within the last [`TOUCH_CACHE_MS`] satisfies the cached policy.
    fn touch_cached(&self, now: Millis) -> bool {
        self.touch_cache.is_some_and(|at| now.saturating_sub(at) < TOUCH_CACHE_MS)
    }

    /// Finish a slot operation after its touch: on touch the operation runs, and when it
    /// succeeds the cache time is recorded and the result answered; without a touch
    /// `6982` (model policy, as for the management key). A failed operation does not fill
    /// the cache.
    pub(crate) fn finish_slot_operation(
        &mut self,
        slot: u8,
        op: Operation,
        input: &[u8],
        max: usize,
        touched: bool,
        host: &mut dyn Host,
    ) -> Vec<u8> {
        if !touched {
            return lk_codec::apdu::status(sw::SECURITY_STATUS);
        }
        let result = match self.state.slots.get(&slot).cloned() {
            Some(key) => key.compute(op, input, host),
            None => Err(sw::REF_NOT_FOUND),
        };
        match result {
            Ok(result) => {
                self.touch_cache = Some(host.now());
                self.session.responses.start(dyn_auth_response(&result), sw::OK, max)
            }
            Err(status) => lk_codec::apdu::status(status),
        }
    }

    /// MOVE KEY / DELETE KEY (`INS F6`, Yubico extension, firmware 5.7): P1 the
    /// destination slot or `FF` for delete, P2 the source slot.
    ///
    /// Checks, in order, before any key changes: command data or an explicit Le (`6700`;
    /// catalog "MOVE KEY and DELETE KEY reject extra APDU data or explicit Le with 6700");
    /// P2 a key slot, and for a move P1 a key slot different from P2 with neither being
    /// `F9` (`6A86`; Yubico: "Move a key from any slot except F9 ... to any other slot except
    /// F9", while delete accepts `F9`); management key authenticated (`6982`); a key in the
    /// source slot (`6A88`); for a move an empty destination (`6985`; Yubico SDK: "the
    /// destination slot must be empty", status word model policy). The key keeps its
    /// policies and origin; certificate objects are not touched (Yubico: the move "only
    /// moves the key, not the certificate").
    pub(crate) fn move_or_delete_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if explicit_le(cmd) || !cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        let (dest, src) = (cmd.p1, cmd.p2);
        if !is_key_slot(src) {
            return Err(sw::INCORRECT_P1P2);
        }
        let delete = dest == P1_DELETE;
        if !delete && (!is_key_slot(dest) || dest == src || dest == SLOT_ATTESTATION || src == SLOT_ATTESTATION) {
            return Err(sw::INCORRECT_P1P2);
        }
        if !self.session.mgmt_authenticated {
            return Err(sw::SECURITY_STATUS);
        }
        if !self.state.slots.contains_key(&src) {
            return Err(sw::REF_NOT_FOUND);
        }
        if delete {
            self.modify(host, |s| {
                s.slots.remove(&src);
            })?;
        } else {
            if self.state.slots.contains_key(&dest) {
                return Err(sw::CONDITIONS);
            }
            self.modify(host, |s| {
                if let Some(key) = s.slots.remove(&src) {
                    s.slots.insert(dest, key);
                }
            })?;
        }
        Ok(Vec::new())
    }

    /// ATTEST (`INS F9`, Yubico extension): P1 the slot, P2 `00`; the answer is the DER
    /// attestation certificate (`attest::attestation_certificate`).
    ///
    /// P2 other than `00`, or P1 not a key slot or `F9` itself (`6A86`; Yubico: the
    /// attestable keys are those in `9A`, `9C`, `9D`, `9E` and `82`-`95`); command data
    /// (`6700`). Le may be present. Nothing is persisted and a failure changes nothing.
    pub(crate) fn attest(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p2 != 0x00 {
            return Err(sw::INCORRECT_P1P2);
        }
        let slot = cmd.p1;
        if !is_key_slot(slot) || slot == SLOT_ATTESTATION {
            return Err(sw::INCORRECT_P1P2);
        }
        if !cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        let profile = host.profile().clone();
        attest::attestation_certificate(&self.state, slot, &profile, host)
    }
}
