//! Secure channel handshakes: INITIALIZE UPDATE and EXTERNAL AUTHENTICATE for SCP03,
//! MUTUAL AUTHENTICATE and INTERNAL AUTHENTICATE for SCP11, and the attempt accounting
//! they share.
//!
//! Sources: GP Card Specification v2.3.1 Amendment D v1.1.2 ("Amd D") §7.1.1
//! INITIALIZE UPDATE, §7.1.2 EXTERNAL AUTHENTICATE, §6.2.1-6.2.4; Amendment F (SCP11)
//! §3.1.2, §7.6, §7.7; Yubico yk5-apps-scp; yubikit `scp.py`/`securitydomain.py` (the
//! wire format Yubico's SDK sends, including its reset); `reference/BEHAVIOR_CATALOG.md`
//! sections SCP03, SCP11, SecurityDomain_profile, SecurityDomain_versions,
//! SecurityDomain_scp11c and SecurityDomain_oce_cache.
//!
//! Authentication attempts (model, see [`crate::SecurityDomain`]):
//! - every INITIALIZE UPDATE that selects a key set uses one try of that set, persisted
//!   before the response that carries the card cryptogram; a successful EXTERNAL
//!   AUTHENTICATE restores the full count. yubikit's Security Domain reset relies on
//!   this: it repeats INITIALIZE UPDATE without ever authenticating until `6983`;
//! - every failed SCP11 request uses one try of the SCP11 key, and every malformed OCE
//!   certificate one try of the CA key the chain started with; success restores them;
//! - the last try can still succeed;
//! - a key with no tries left is removed when it is next selected (`6983`), and an
//!   SCP03 set also when the EXTERNAL AUTHENTICATE after its last INITIALIZE UPDATE
//!   fails (Yubico: "When authentication with a key set fails repeatedly ... that key
//!   set is deleted");
//! - when no key remains, the Security Domain resets to its factory state ("When the
//!   last key set is deleted, the security domain is automatically reset with the
//!   default key set installed").

use lk_codec::apdu::{self, Command, sw};
use lk_codec::tlv;
use lk_core::Host;
use lk_crypto::{Curve, EcPrivateKey};

use crate::channel::{SecureChannel, Shared, level};
use crate::data::{SCP03_I, SCP03_ID};
use crate::scp03::{self, Key, SessionKeys};
use crate::scp11::{self, Variant};
use crate::state::{AUTH_TRIES, KID_SCP11A, KID_SCP11B, KID_SCP11C, State};
use crate::{LevelPolicy, SecurityDomain};

/// Amd D §7.1.2 EXTERNAL AUTHENTICATE response: `6300`, "Authentication of host
/// cryptogram failed".
pub(crate) const SW_HOST_CRYPTOGRAM_FAILED: u16 = 0x6300;

/// Key diversification data in the INITIALIZE UPDATE response (Amd D §7.1.1.3). The
/// YubiKey's value is not published; this model returns ten zero bytes.
const KEY_DIVERSIFICATION: [u8; 10] = [0; 10];

/// A half-open SCP03 session between INITIALIZE UPDATE and EXTERNAL AUTHENTICATE.
pub(crate) struct Pending {
    kvn: u8,
    context: [u8; 16],
    keys: SessionKeys,
    dek: Key,
}

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pending").field("kvn", &self.kvn).finish_non_exhaustive()
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        scp03::wipe(&mut self.dek);
    }
}

/// A key that authentication attempts are counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRow {
    /// An SCP03 key set.
    Scp03 { kvn: u8 },
    /// An SCP11 private key.
    Ec { kid: u8, kvn: u8 },
    /// An OCE CA public key (tries count malformed certificate uploads).
    Ca { kid: u8, kvn: u8 },
}

impl KeyRow {
    pub(crate) fn tries(self, state: &State) -> Option<u8> {
        match self {
            KeyRow::Scp03 { kvn } => state.scp03.iter().find(|s| s.kvn == kvn).map(|s| s.tries),
            KeyRow::Ec { kid, kvn } => {
                state.ec_private.iter().find(|k| k.kid == kid && k.kvn == kvn).map(|k| k.tries)
            }
            KeyRow::Ca { kid, kvn } => state.public_key(kid, kvn).map(|k| k.tries),
        }
    }

    pub(crate) fn set_tries(self, state: &mut State, tries: u8) {
        match self {
            KeyRow::Scp03 { kvn } => {
                if let Some(s) = state.scp03.iter_mut().find(|s| s.kvn == kvn) {
                    s.tries = tries;
                }
            }
            KeyRow::Ec { kid, kvn } => {
                if let Some(k) = state.ec_private.iter_mut().find(|k| k.kid == kid && k.kvn == kvn) {
                    k.tries = tries;
                }
            }
            KeyRow::Ca { kid, kvn } => {
                if let Some(k) = state.ec_public.iter_mut().find(|k| k.kid == kid && k.kvn == kvn) {
                    k.tries = tries;
                }
            }
        }
    }

    fn remove(self, state: &mut State) {
        match self {
            KeyRow::Scp03 { kvn } => state.scp03.retain(|s| s.kvn != kvn),
            KeyRow::Ec { kid, kvn } => {
                state.ec_private.retain(|k| !(k.kid == kid && k.kvn == kvn));
                state.drop_key_data(kid, kvn);
            }
            KeyRow::Ca { kid, kvn } => {
                state.ec_public.retain(|k| !(k.kid == kid && k.kvn == kvn));
                state.drop_key_data(kid, kvn);
            }
        }
    }
}

impl SecurityDomain {
    /// INITIALIZE UPDATE (Amd D §7.1.1): `80 50 KVN 00 08 <host challenge> [00]`.
    ///
    /// - Le must be absent or the maximum (`00`); any other explicit Le is rejected with
    ///   `6700` before a pending handshake is dropped or a try is used (catalog SCP03,
    ///   model status: the physical one is unmeasured).
    /// - P2 must be `00` (`6A86`); the host challenge is 8 bytes (S8 mode; `i = 60`
    ///   does not offer S16) or `6A80`.
    /// - P1 `00` selects the key set with the highest KVN (catalog SecurityDomain_versions:
    ///   "numeric wildcard selects highest usable high-byte version"); any other P1
    ///   selects that version exactly and never falls back. No such set: `6A88`.
    /// - A selected set with no tries left is removed and the command answers `6983`.
    /// - Response: key diversification data (10) || KVN || `03` || `60` || card
    ///   challenge (8, random) || card cryptogram (8).
    pub(crate) fn initialize_update(&mut self, cmd: &Command, host: &mut dyn Host) -> Vec<u8> {
        if matches!(cmd.le, Some(n) if n != 0) {
            return apdu::status(sw::WRONG_LENGTH);
        }
        self.pending = None;
        if cmd.p2 != 0x00 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        let Ok(host_challenge) = <[u8; 8]>::try_from(cmd.data.as_slice()) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let selected = if cmd.p1 == 0x00 {
            self.state.scp03.iter().map(|s| s.kvn).max()
        } else {
            self.state.scp03.iter().find(|s| s.kvn == cmd.p1).map(|s| s.kvn)
        };
        let Some(kvn) = selected else {
            return apdu::status(sw::REF_NOT_FOUND);
        };
        let row = KeyRow::Scp03 { kvn };
        if let Err(status) = self.use_try(row, host) {
            return apdu::status(status);
        }
        let Some(set) = self.state.scp03.iter().find(|s| s.kvn == kvn) else {
            return apdu::status(sw::REF_NOT_FOUND);
        };
        let (k_enc, k_mac, dek) = (set.enc, set.mac, set.dek);

        let mut card_challenge = [0u8; 8];
        host.fill(&mut card_challenge);
        let mut context = [0u8; 16];
        context[..8].copy_from_slice(&host_challenge);
        context[8..].copy_from_slice(&card_challenge);
        let result = scp03::derive_session_keys(&k_enc, &k_mac, &context).and_then(|keys| {
            let card_cryptogram = scp03::cryptogram(&keys.mac, scp03::DC_CARD_CRYPTOGRAM, &context)?;
            Ok((keys, card_cryptogram))
        });
        let (keys, card_cryptogram) = match result {
            Ok(v) => v,
            Err(status) => return apdu::status(status),
        };
        self.pending = Some(Pending { kvn, context, keys, dek });

        let mut data = Vec::with_capacity(29);
        data.extend_from_slice(&KEY_DIVERSIFICATION);
        data.extend_from_slice(&[kvn, SCP03_ID, SCP03_I]);
        data.extend_from_slice(&card_challenge);
        data.extend_from_slice(&card_cryptogram);
        apdu::response(&data, sw::OK)
    }

    /// EXTERNAL AUTHENTICATE (Amd D §7.1.2): `84 82 <level> 00 10 <host cryptogram> <C-MAC>`.
    ///
    /// P2 `00` is SCP03. P2 `11`/`15` addresses an SCP11a/SCP11c key (GP Amendment F,
    /// handled by [`SecurityDomain::scp11_authenticate`]); any other P2 is `6A86`.
    ///
    /// SCP03 checks, in order: a pending INITIALIZE UPDATE (`6985`), Lc = 16 (`6700`),
    /// the security level (`6A86`; by default only `33`, see [`LevelPolicy`]), the C-MAC
    /// over `MCV(0) || CLA|04 82 P1 P2 Lc || host cryptogram` with Lc in the form the
    /// command was sent (`10`, or `00 00 10` extended; `6982`), and the host cryptogram
    /// (`6300`). The pending handshake is consumed by every attempt.
    pub(crate) fn external_authenticate(
        &mut self,
        cmd: &Command,
        host: &mut dyn Host,
    ) -> (Vec<u8>, Option<SecureChannel>) {
        match cmd.p2 {
            0x00 => {}
            KID_SCP11A => return self.scp11_authenticate(cmd, Variant::A, host),
            KID_SCP11C => return self.scp11_authenticate(cmd, Variant::C, host),
            _ => return (apdu::status(sw::INCORRECT_P1P2), None),
        }
        let Some(pending) = self.pending.take() else {
            return (apdu::status(sw::CONDITIONS), None);
        };
        let row = KeyRow::Scp03 { kvn: pending.kvn };
        if cmd.data.len() != 16 {
            return (self.attempt_failed(row, sw::WRONG_LENGTH, host), None);
        }
        let allowed = match self.policy {
            LevelPolicy::FullOnly => cmd.p1 == level::FULL,
            LevelPolicy::AmendmentD => level::AMENDMENT_D.contains(&cmd.p1),
        };
        if !allowed {
            return (self.attempt_failed(row, sw::INCORRECT_P1P2, host), None);
        }
        let (host_cryptogram, mac) = cmd.data.split_at(8);

        // Amd D §6.2.4 / §7.1.2.1: the C-MAC covers the header and Lc as sent, so an
        // extended EXTERNAL AUTHENTICATE MACs `00 00 10`. yubikit sends it that way on
        // a session configured for extended APDUs (`ScpProcessor.send_apdu` formats the
        // APDU with the session formatter and MACs everything before the MAC), which is
        // how `SecurityDomainSession` runs on USB.
        let mut input = Vec::with_capacity(16 + 7 + 8);
        input.extend_from_slice(&[0u8; 16]);
        input.extend_from_slice(&[cmd.cla | 0x04, cmd.ins, cmd.p1, cmd.p2]);
        if cmd.extended {
            input.extend_from_slice(&[0x00, 0x00, 0x10]);
        } else {
            input.push(0x10);
        }
        input.extend_from_slice(host_cryptogram);
        let full = match scp03::cmac(&pending.keys.mac, &input) {
            Ok(full) => full,
            Err(status) => return (apdu::status(status), None),
        };
        if !lk_crypto::ct_eq(&full[..8], mac) {
            return (self.attempt_failed(row, sw::SECURITY_STATUS, host), None);
        }
        let expected = match scp03::cryptogram(&pending.keys.mac, scp03::DC_HOST_CRYPTOGRAM, &pending.context) {
            Ok(c) => c,
            Err(status) => return (apdu::status(status), None),
        };
        if !lk_crypto::ct_eq(&expected, host_cryptogram) {
            return (self.attempt_failed(row, SW_HOST_CRYPTOGRAM_FAILED, host), None);
        }

        // Success: restore the tries (persisted before the session is reported).
        if row.tries(&self.state).is_some_and(|t| t != AUTH_TRIES) {
            let mut next = self.state.clone();
            row.set_tries(&mut next, AUTH_TRIES);
            if let Err(status) = self.commit(next, host) {
                return (apdu::status(status), None);
            }
        }
        let channel = SecureChannel::scp03(
            pending.kvn,
            cmd.p1,
            pending.keys.clone(),
            pending.dek,
            full,
            self.shared.clone(),
        );
        (apdu::status(sw::OK), Some(channel))
    }

    /// INTERNAL AUTHENTICATE (GP Amendment F §7.7): `80 88 KVN 13 <request>`, SCP11b
    /// only; any other P2 is `6A86`.
    pub(crate) fn internal_authenticate(
        &mut self,
        cmd: &Command,
        host: &mut dyn Host,
    ) -> (Vec<u8>, Option<SecureChannel>) {
        if cmd.p2 != KID_SCP11B {
            return (apdu::status(sw::INCORRECT_P1P2), None);
        }
        self.scp11_authenticate(cmd, Variant::B, host)
    }

    /// An SCP11 handshake (GP Amendment F §7.6 MUTUAL AUTHENTICATE for SCP11a/c, §7.7
    /// INTERNAL AUTHENTICATE for SCP11b) with the private key (`kid`, P1); KVN `00`
    /// selects the highest version with that KID.
    ///
    /// Order of checks, each answered before the next is looked at:
    /// 1. no such key: `6A88`; a key without tries is deleted (and the Security Domain
    ///    reset if it was the last key): `6983`;
    /// 2. the request (see [`scp11::parse_request`]) is malformed or names another
    ///    variant: `6A80`;
    /// 3. SCP11a/c without a verified OCE certificate chain (missing, incomplete or
    ///    revoked): `6985` (catalog SecurityDomain_oce_cache, GP public-review model);
    /// 4. the key agreement fails on the host's point: `6A80`.
    ///
    /// Steps 2-4 use one try of the key, persisted before the answer (catalog: "malformed
    /// c request only consumes modeled retry"); a key whose last try fails stays until it
    /// is next selected, when step 1 deletes it. yubikit's reset relies on this order: it
    /// sends eight zero bytes, continues on `6A80` and stops on `6983`.
    ///
    /// Success restores the key's tries (persisted before the response) and answers
    /// `5F49 <SD key> 86 10 <receipt>`:
    /// - SCP11a/b: a fresh ephemeral key eSK.SD; ShSee = ECDH(eSK.SD, ePK.OCE), ShSes =
    ///   ECDH(SK.SD, PK.OCE), where PK.OCE is the OCE certificate key (a) or ePK.OCE (b);
    /// - SCP11c: no fresh key; the response carries PK.SD and both terms use SK.SD
    ///   (catalog SecurityDomain_scp11c), so the same request gets the same response.
    ///   The new session supersedes any earlier SCP11c session.
    pub(crate) fn scp11_authenticate(
        &mut self,
        cmd: &Command,
        variant: Variant,
        host: &mut dyn Host,
    ) -> (Vec<u8>, Option<SecureChannel>) {
        self.pending = None;
        // An authenticate request ends a certificate upload: a partial chain is dropped.
        self.oce_chain = None;
        let kid = variant.kid();
        let selected = self
            .state
            .ec_private
            .iter()
            .filter(|k| k.kid == kid && (cmd.p1 == 0 || k.kvn == cmd.p1))
            .max_by_key(|k| k.kvn)
            .map(|k| (k.kvn, k.tries, k.scalar.clone()));
        let Some((kvn, tries, mut scalar)) = selected else {
            return (apdu::status(sw::REF_NOT_FOUND), None);
        };
        let row = KeyRow::Ec { kid, kvn };
        let key = EcPrivateKey::from_scalar(Curve::P256, &scalar);
        scp03::wipe(&mut scalar);
        if tries == 0 {
            let status = match self.remove_rows(&[row], host) {
                Ok(()) => sw::AUTH_BLOCKED,
                Err(status) => status,
            };
            return (apdu::status(status), None);
        }
        let Ok(key) = key else {
            return (apdu::status(scp03::CRYPTO_FAILURE), None);
        };
        let Some(epk_oce) = scp11::parse_request(&cmd.data, variant) else {
            return (self.scp11_failed(row, sw::INCORRECT_DATA, host), None);
        };
        let pk_oce = match variant {
            Variant::B => epk_oce.clone(),
            Variant::A | Variant::C => match self.current_oce() {
                Some(oce) => oce.point.clone(),
                None => return (self.scp11_failed(row, sw::CONDITIONS, host), None),
            },
        };
        let (sd_point, sh_see) = match variant {
            Variant::C => (key.public_uncompressed(), key.ecdh(&epk_oce)),
            Variant::A | Variant::B => {
                let ephemeral = EcPrivateKey::generate(Curve::P256, host);
                (ephemeral.public_uncompressed(), ephemeral.ecdh(&epk_oce))
            }
        };
        let sh_ses = key.ecdh(&pk_oce);
        let (Ok(sh_see), Ok(sh_ses)) = (sh_see, sh_ses) else {
            return (self.scp11_failed(row, sw::INCORRECT_DATA, host), None);
        };
        let epk_object = tlv::encode(scp11::TAG_EPK, &sd_point);
        let Some(agreement) = scp11::agree(&sh_see, &sh_ses, &cmd.data, &epk_object) else {
            return (apdu::status(scp03::CRYPTO_FAILURE), None);
        };
        if tries != AUTH_TRIES {
            let mut next = self.state.clone();
            row.set_tries(&mut next, AUTH_TRIES);
            if let Err(status) = self.commit(next, host) {
                return (apdu::status(status), None);
            }
        }
        if variant == Variant::C {
            Shared::bump(&self.shared.c_epoch);
        }
        let channel = SecureChannel::scp11(
            variant.protocol(),
            kvn,
            agreement.keys.clone(),
            agreement.dek,
            agreement.receipt,
            self.shared.clone(),
        );
        let mut data = epk_object;
        tlv::encode_into(&mut data, scp11::TAG_RECEIPT, &agreement.receipt);
        (apdu::response(&data, sw::OK), Some(channel))
    }

    /// Drop a half-open SCP03 handshake whose key set is in `kvns` (replaced, removed or
    /// overwritten by PUT KEY / DELETE KEY), so that EXTERNAL AUTHENTICATE can never
    /// open a session under keys that are no longer installed (it then answers `6985`,
    /// as without INITIALIZE UPDATE).
    pub(crate) fn drop_pending_for(&mut self, kvns: &[u8]) {
        if self.pending.as_ref().is_some_and(|p| kvns.contains(&p.kvn)) {
            self.pending = None;
        }
    }

    /// A failed SCP11 attempt: one try is used (persisted; `6581` if that fails) and the
    /// answer is `failure`. A key left without tries is deleted when next selected.
    fn scp11_failed(&mut self, row: KeyRow, failure: u16, host: &mut dyn Host) -> Vec<u8> {
        let Some(tries) = row.tries(&self.state) else {
            return apdu::status(failure);
        };
        let mut next = self.state.clone();
        row.set_tries(&mut next, tries.saturating_sub(1));
        match self.commit(next, host) {
            Ok(()) => apdu::status(failure),
            Err(status) => apdu::status(status),
        }
    }

    /// Use one try of `row`, persisted before anything that depends on it is revealed.
    /// A row without tries is removed instead and the attempt refused with `6983`.
    fn use_try(&mut self, row: KeyRow, host: &mut dyn Host) -> Result<(), u16> {
        let tries = row.tries(&self.state).ok_or(sw::REF_NOT_FOUND)?;
        if tries == 0 {
            self.remove_rows(&[row], host)?;
            return Err(sw::AUTH_BLOCKED);
        }
        let mut next = self.state.clone();
        row.set_tries(&mut next, tries - 1);
        self.commit(next, host)
    }

    /// Record a failed SCP03 authentication: a set whose last try this was is removed.
    /// The answer is `failure`, or `6581` if the removal could not be persisted.
    fn attempt_failed(&mut self, row: KeyRow, failure: u16, host: &mut dyn Host) -> Vec<u8> {
        if row.tries(&self.state) == Some(0)
            && let Err(status) = self.remove_rows(&[row], host)
        {
            return apdu::status(status);
        }
        apdu::status(failure)
    }

    /// Remove exhausted keys (with the data attached to them); reset the Security
    /// Domain if no key is left.
    pub(crate) fn remove_rows(&mut self, rows: &[KeyRow], host: &mut dyn Host) -> Result<(), u16> {
        let mut next = self.state.clone();
        for row in rows {
            row.remove(&mut next);
        }
        if !next.has_any_key() {
            return self.factory_reset(host);
        }
        self.commit(next, host)?;
        if rows.iter().any(|r| matches!(r, KeyRow::Ca { .. })) {
            self.oce_chain = None;
            if self.oce.as_ref().is_some_and(|o| rows.contains(&KeyRow::Ca { kid: o.anchor.0, kvn: o.anchor.1 })) {
                self.oce = None;
            }
        }
        Ok(())
    }
}
