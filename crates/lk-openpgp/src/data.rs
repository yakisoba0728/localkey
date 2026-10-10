//! Data object commands: GET DATA (spec 3.4.1 §7.2.6), PUT DATA (§7.2.8), SELECT DATA
//! (§7.2.5) and GET NEXT DATA (§7.2.7), with the access rules of the §4.4.1 table.
//!
//! GET DATA returns constructed objects (65, 6E, 7A, FA) with their own tag and simple
//! objects as their bare value; F9 is returned as its contents, as GnuPG and YubiKit read
//! it. A tag outside the readable set answers `6B00`, the status the device gives for a
//! direct read of C0 (observation command `00ca00c000` -> `6b00`). The resetting code D3
//! is never readable (catalog).
//!
//! PUT DATA writes need PW3, except the private use DOs 0101 and 0103, which need PW1
//! verified with reference 82 (spec §4.4.1; legacy profile
//! `private_101_103_write_pin_reference = 0x82`). Read-only and undeclared tags answer
//! `6B00` (catalog: "read-only and undeclared PUT rejection"). Length violations answer
//! `6700`; invalid contents `6A80`. The KDF-DO F9 cannot change while the SIG, DEC or AUT
//! slot holds a key (`6985`, Yubico's documented KDF lock; see `holds_user_key`).

use lk_codec::apdu::{Command, sw};
use lk_codec::tlv;
use lk_core::Host;

use crate::auth::{RC_MIN, new_password_ok};
use crate::kdf::Kdf;
use crate::objects::{
    self, ALGORITHM_INFORMATION, EXTENDED_LENGTH_INFO, GENERAL_FEATURE_MANAGEMENT,
    HISTORICAL_BYTES, MAX_CERTIFICATE, MAX_LANGUAGE, MAX_NAME, MAX_SPECIAL_DO, Slot, tag,
};
use crate::state::{RC, State};
use crate::{OpenPgp, Reply, le_absent_or_zero};

/// UIF values (Yubico OpenPGP touch policy): 00 off, 01 on, 02 fixed, 03 cached,
/// 04 cached-fixed. "Fixed" values can only be left by a full application reset.
const UIF_MAX: u8 = 0x04;
const UIF_BUTTON: u8 = 0x20;

/// The highest 7F21 occurrence: AUT 0, DEC 1, SIG 2 (spec §7.2.5) and the catalog's
/// fourth occurrence, the attestation certificate.
const LAST_OCCURRENCE: u8 = 3;

/// Who may write a data object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// PW1 verified with reference 82.
    Pw1Other,
    /// PW3 verified.
    Pw3,
}

impl OpenPgp {
    fn has_access(&self, access: Access) -> bool {
        match access {
            Access::Pw1Other => self.session.pw1_other,
            Access::Pw3 => self.session.pw3,
        }
    }

    fn selected_certificate_slot(&self) -> Slot {
        Slot::from_occurrence(self.session.cert_occurrence).unwrap_or(Slot::Aut)
    }

    /// GET DATA (spec §7.2.6): P1 P2 is the tag. The command carries no data.
    pub(crate) fn get_data(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if !cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        let state = &self.state;
        let tag = u16::from_be_bytes([cmd.p1, cmd.p2]);
        let value = match tag {
            tag::PRIVATE_1 => state.private_do(0),
            tag::PRIVATE_2 => state.private_do(1),
            tag::PRIVATE_3 => {
                if !self.session.pw1_other {
                    return Err(sw::SECURITY_STATUS);
                }
                state.private_do(2)
            }
            tag::PRIVATE_4 => {
                if !self.session.pw3 {
                    return Err(sw::SECURITY_STATUS);
                }
                state.private_do(3)
            }
            tag::AID => objects::full_aid(host.profile()).to_vec(),
            tag::NAME => state.name.clone(),
            tag::LOGIN => state.login.clone(),
            tag::LANGUAGE => state.language.clone(),
            tag::SEX => vec![state.sex],
            tag::URL => state.url.clone(),
            tag::HISTORICAL => HISTORICAL_BYTES.to_vec(),
            tag::CARDHOLDER => objects::cardholder_data(state),
            tag::APPLICATION => objects::application_data(state, host.profile()),
            tag::SECURITY_SUPPORT => objects::security_support(state),
            tag::CERTIFICATE => state.slot(self.selected_certificate_slot()).certificate.clone(),
            tag::EXTENDED_LENGTH => EXTENDED_LENGTH_INFO.to_vec(),
            tag::FEATURES => GENERAL_FEATURE_MANAGEMENT.to_vec(),
            tag::PW_STATUS => objects::pw_status(state).to_vec(),
            tag::FINGERPRINTS => objects::fingerprints(state),
            tag::CA_FINGERPRINTS => objects::ca_fingerprints(state),
            tag::GENERATION_TIMES => objects::generation_times(state),
            tag::KEY_INFORMATION => objects::key_information(state),
            tag::KDF => state.kdf.clone(),
            tag::ALGORITHM_INFORMATION => ALGORITHM_INFORMATION.to_vec(),
            tag::ATTESTATION_CERTIFICATE => state.slot(Slot::Att).certificate.clone(),
            other => {
                if let Some(slot) = Slot::from_attributes_tag(other) {
                    state.slot(slot).attributes.clone()
                } else if let Some(slot) = Slot::from_uif_tag(other) {
                    state.slot(slot).uif.to_vec()
                } else {
                    // C0 (measured), D3 (never exposed) and every undeclared tag.
                    return Err(sw::WRONG_P1P2);
                }
            }
        };
        Ok(value)
    }

    /// SELECT DATA (spec §7.2.5): P1 = occurrence, P2 = 04, data `60 L 5C L 7F21`.
    /// An explicit non-zero Le is rejected before the selection changes (catalog).
    pub(crate) fn select_data(&mut self, cmd: &Command) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p2 != 0x04 {
            return Err(sw::INCORRECT_P1P2);
        }
        let selected = parse_tag_list(&cmd.data).ok_or(sw::INCORRECT_DATA)?;
        if selected != tag::CERTIFICATE {
            return Err(sw::REF_NOT_FOUND);
        }
        if cmd.p1 > LAST_OCCURRENCE {
            return Err(sw::INCORRECT_P1P2);
        }
        self.session.cert_occurrence = cmd.p1;
        Ok(Vec::new())
    }

    /// GET NEXT DATA (spec §7.2.7): P1 P2 = 7F21, no data. Selects and returns the next
    /// occurrence. Command data is `6700` before anything advances; past the last
    /// occurrence the answer is `6A88` and the current selection stays (catalog).
    pub(crate) fn get_next_data(&mut self, cmd: &Command) -> Reply {
        if !cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        if u16::from_be_bytes([cmd.p1, cmd.p2]) != tag::CERTIFICATE {
            return Err(sw::WRONG_P1P2);
        }
        let next = self.session.cert_occurrence.saturating_add(1);
        let slot = Slot::from_occurrence(next).ok_or(sw::REF_NOT_FOUND)?;
        self.session.cert_occurrence = next;
        Ok(self.state.slot(slot).certificate.clone())
    }

    /// PUT DATA (spec §7.2.8), even INS DA: P1 P2 is the tag, the data its new value.
    pub(crate) fn put_data(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        let tag = u16::from_be_bytes([cmd.p1, cmd.p2]);
        let access = write_access(tag).ok_or(sw::WRONG_P1P2)?;
        if !self.has_access(access) {
            return Err(sw::SECURITY_STATUS);
        }
        let value = cmd.data.as_slice();
        let mut next = self.state.clone();
        let mut drop_access = false;
        match tag {
            tag::PRIVATE_1 | tag::PRIVATE_2 | tag::PRIVATE_3 | tag::PRIVATE_4 => {
                max_len(value, MAX_SPECIAL_DO)?;
                let index = usize::from(cmd.p2).saturating_sub(1);
                if let Some(slot) = next.private.get_mut(index) {
                    *slot = value.to_vec();
                }
            }
            tag::NAME => {
                max_len(value, MAX_NAME)?;
                next.name = value.to_vec();
            }
            tag::LOGIN => {
                max_len(value, MAX_SPECIAL_DO)?;
                next.login = value.to_vec();
            }
            tag::URL => {
                max_len(value, MAX_SPECIAL_DO)?;
                next.url = value.to_vec();
            }
            tag::LANGUAGE => {
                // spec §4.4.3.4: up to four two-character ISO 639 codes.
                if value.len() > MAX_LANGUAGE || !value.len().is_multiple_of(2) {
                    return Err(sw::WRONG_LENGTH);
                }
                next.language = value.to_vec();
            }
            tag::SEX => {
                // spec §4.4.3.5: one ISO 5218 ASCII digit.
                next.sex = match value {
                    [b @ (b'0' | b'1' | b'2' | b'9')] => *b,
                    [_] => return Err(sw::INCORRECT_DATA),
                    _ => return Err(sw::WRONG_LENGTH),
                };
            }
            tag::CERTIFICATE => {
                max_len(value, MAX_CERTIFICATE)?;
                next.slot_mut(self.selected_certificate_slot()).certificate = value.to_vec();
            }
            tag::ATTESTATION_CERTIFICATE => {
                max_len(value, MAX_CERTIFICATE)?;
                next.slot_mut(Slot::Att).certificate = value.to_vec();
            }
            tag::PW_STATUS => {
                // spec §4.4.3.6: only the first byte (PW1 validity) is writable.
                next.pw1_multi = match value {
                    [0x00] => false,
                    [0x01] => true,
                    [_] => return Err(sw::INCORRECT_DATA),
                    _ => return Err(sw::WRONG_LENGTH),
                };
            }
            tag::RESETTING_CODE => put_resetting_code(&mut next, value)?,
            tag::KDF => {
                if holds_user_key(&self.state) {
                    return Err(sw::CONDITIONS);
                }
                put_kdf(&mut next, value)?;
                drop_access = true;
            }
            other => put_slot_object(&mut next, other, value)?,
        }
        self.commit(host, next)?;
        if drop_access {
            // The passwords were replaced: no earlier verification still applies.
            self.session.pw1_cds = false;
            self.session.pw1_other = false;
            self.session.pw3 = false;
        }
        Ok(Vec::new())
    }
}

impl State {
    fn private_do(&self, index: usize) -> Vec<u8> {
        self.private.get(index).cloned().unwrap_or_default()
    }
}

/// The access condition for writing `tag`, or `None` if it cannot be written.
fn write_access(tag: u16) -> Option<Access> {
    match tag {
        tag::PRIVATE_1 | tag::PRIVATE_3 => Some(Access::Pw1Other),
        tag::PRIVATE_2
        | tag::PRIVATE_4
        | tag::NAME
        | tag::LOGIN
        | tag::LANGUAGE
        | tag::SEX
        | tag::URL
        | tag::CERTIFICATE
        | tag::ATTESTATION_CERTIFICATE
        | tag::PW_STATUS
        | tag::RESETTING_CODE
        | tag::KDF => Some(Access::Pw3),
        other => {
            let slot_object = Slot::from_attributes_tag(other).is_some()
                || Slot::from_fingerprint_tag(other).is_some()
                || Slot::from_ca_fingerprint_tag(other).is_some()
                || Slot::from_generation_time_tag(other).is_some()
                || Slot::from_uif_tag(other).is_some();
            slot_object.then_some(Access::Pw3)
        }
    }
}

fn max_len(value: &[u8], max: usize) -> Result<(), u16> {
    if value.len() > max {
        Err(sw::WRONG_LENGTH)
    } else {
        Ok(())
    }
}

/// D3 (spec §4.3.4): empty removes the resetting code; otherwise the new code (8-127
/// bytes, or the hash length under a KDF-DO) with its counter refilled.
fn put_resetting_code(next: &mut State, value: &[u8]) -> Result<(), u16> {
    if value.is_empty() {
        next.rc = None;
        if let Some(slot) = next.retries.get_mut(RC) {
            *slot = 0;
        }
        return Ok(());
    }
    if value.len() > 127 {
        return Err(sw::WRONG_LENGTH);
    }
    if !new_password_ok(next, value, RC_MIN) {
        return Err(sw::INCORRECT_DATA);
    }
    next.rc = Some(value.to_vec());
    let max = next.max_retries.get(RC).copied().unwrap_or(0);
    if let Some(slot) = next.retries.get_mut(RC) {
        *slot = max;
    }
    Ok(())
}

/// Whether the SIG, DEC or AUT slot holds a key (generated or imported).
///
/// Yubico ("YubiKey 5.2.3 Enhancements to OpenPGP 3.4", Key Derived Format): "Once a key
/// has been placed on the YubiKey any changes to the KDF settings will be prevented until
/// the OpenPGP application has been reset", and the attempt fails with "Conditions of use
/// not satisfied" (`6985`). The attestation slot does not count: every YubiKey ships with
/// an attestation key, the reset keeps it, and the document's `kdf-setup` flow runs on such
/// a card. The check follows the PW3 access check and precedes the validation of the new
/// F9 value (model policy for the order: a state condition before the data).
fn holds_user_key(state: &State) -> bool {
    [Slot::Sig, Slot::Dec, Slot::Aut]
        .into_iter()
        .any(|slot| state.slot(slot).key.is_some())
}

/// F9 (spec §4.3.2): store the KDF-DO, reset PW1/PW3 to their initial values with full
/// counters, and remove the resetting code. Refused while a key exists (see
/// [`holds_user_key`]).
fn put_kdf(next: &mut State, value: &[u8]) -> Result<(), u16> {
    let kdf = Kdf::parse(value)?;
    let (pw1, pw3) = kdf.initial_references()?;
    next.kdf = value.to_vec();
    next.pw1 = pw1;
    next.pw3 = pw3;
    next.rc = None;
    let [pw1_max, _, pw3_max] = next.max_retries;
    next.retries = [pw1_max, 0, pw3_max];
    Ok(())
}

/// Per-slot objects: algorithm attributes, fingerprints, CA fingerprints, generation times
/// and UIF (spec §4.4.3.9-§4.4.3.10; Yubico DA-DD and D6-D9).
fn put_slot_object(next: &mut State, tag: u16, value: &[u8]) -> Result<(), u16> {
    if let Some(slot) = Slot::from_attributes_tag(tag) {
        if !objects::attributes_supported(slot, value) {
            return Err(sw::INCORRECT_DATA);
        }
        let data = next.slot_mut(slot);
        if data.attributes != value {
            // A key of the previous algorithm cannot stay in the slot (spec §4.4.3.10):
            // the key is deleted, also the attestation key (catalog: a deliberately deleted
            // issuer key is not resurrected).
            data.attributes = value.to_vec();
            data.clear_key();
        }
        return Ok(());
    }
    if let Some(slot) = Slot::from_fingerprint_tag(tag) {
        next.slot_mut(slot).fingerprint = value.try_into().map_err(|_| sw::WRONG_LENGTH)?;
        return Ok(());
    }
    if let Some(slot) = Slot::from_ca_fingerprint_tag(tag) {
        next.slot_mut(slot).ca_fingerprint = value.try_into().map_err(|_| sw::WRONG_LENGTH)?;
        return Ok(());
    }
    if let Some(slot) = Slot::from_generation_time_tag(tag) {
        next.slot_mut(slot).generation_time = value.try_into().map_err(|_| sw::WRONG_LENGTH)?;
        return Ok(());
    }
    if let Some(slot) = Slot::from_uif_tag(tag) {
        let uif: [u8; 2] = value.try_into().map_err(|_| sw::WRONG_LENGTH)?;
        let [policy, feature] = uif;
        if policy > UIF_MAX || feature != UIF_BUTTON {
            return Err(sw::INCORRECT_DATA);
        }
        let data = next.slot_mut(slot);
        if matches!(data.uif.first(), Some(0x02 | 0x04)) && data.uif != uif {
            // A fixed policy is permanent until the application is reset.
            return Err(sw::SECURITY_STATUS);
        }
        data.uif = uif;
        return Ok(());
    }
    Err(sw::WRONG_P1P2)
}

/// Parse the SELECT DATA tag list `60 L 5C L <tag>` (spec §7.2.5) into the tag.
fn parse_tag_list(data: &[u8]) -> Option<u16> {
    let (outer, rest) = tlv::parse_one(data).ok()?;
    if outer.tag != 0x60 || !rest.is_empty() {
        return None;
    }
    let (list, rest) = tlv::parse_one(outer.value).ok()?;
    if list.tag != 0x5C || !rest.is_empty() {
        return None;
    }
    match list.value {
        [b] => Some(u16::from(*b)),
        [hi, lo] => Some(u16::from_be_bytes([*hi, *lo])),
        _ => None,
    }
}
