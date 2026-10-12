//! Key management and data retrieval: GET DATA, PUT KEY, GENERATE EC KEY, DELETE KEY and
//! STORE DATA.
//!
//! Sources: GP Card Specification v2.3.1 §11.2 DELETE, §11.3 GET DATA, §11.8 PUT KEY,
//! §11.11 STORE DATA; Amendment D v1.1.2 (AES keys); Amendment F (SCP11 key types `B0`
//! public, `B1` private, `F0` key parameter reference, certificate store `BF21`, CA
//! identifiers `FF33`/`FF34`); Yubico yk5-apps-scp ("The YubiKey only allows putting or
//! deleting a whole key set at a time", "When a new key set is installed, it replaces
//! the default key set", "To delete the last key set on purpose and force a reset, send
//! the delete instruction with p2=1"); the data layouts Yubico's SDK sends (yubikit
//! `securitydomain.py`: `put_key`, `generate_ec_key`, `store_certificate_bundle`,
//! `store_allowlist`, `store_ca_issuer`, `get_certificate_bundle`,
//! `get_supported_ca_identifiers`); `reference/BEHAVIOR_CATALOG.md` SecurityDomain,
//! SecurityDomain_versions, SecurityDomain_scp11c, SecurityDomain_allowlist and
//! SecurityDomain_oce_cache.
//!
//! Which session may run these commands is decided in `lib.rs` (`dispatch`).

use lk_codec::apdu::{self, Command, sw};
use lk_codec::{der, tlv};
use lk_core::Host;
use lk_crypto::{Curve, EcPrivateKey};

use crate::SecurityDomain;
use crate::cert::normalize_serial;
use crate::channel::{SecureChannel, Shared};
use crate::data::{self, CARD_RECOGNITION, KEY_TYPE_AES, KEY_TYPE_EC_PARAMETERS, KEY_TYPE_EC_PRIVATE, KEY_TYPE_EC_PUBLIC};
use crate::scp03::{self, Key};
use crate::state::{
    AUTH_TRIES, Allowlist, CaIdentifier, CertStore, EcPrivate, EcPublic, FACTORY_KVN, MAX_ALLOWLIST, MAX_CERTIFICATES,
    MAX_EC_ROWS, MAX_LIST_COUNTER, MAX_SCP03_SETS, MAX_SKI_LEN, Scp03Set, State, is_ca_kid, is_scp11_kvn, is_sd_kid,
};

/// PUT KEY P2 for a whole SCP03 key set: b8 set ("multiple keys", GP 2.3.1 §11.8.2.2)
/// and the first key identifier `01`.
const P2_SCP03_SET: u8 = 0x81;

/// DELETE KEY data object tags (GP 2.3.1 §11.2.2.3): key identifier and key version.
const TAG_KEY_ID: u32 = 0xD0;
const TAG_KEY_VERSION: u32 = 0xD2;

/// Data object tags of STORE DATA and GET DATA (GP Amendment F; yubikit).
mod tag {
    /// Control reference template holding the key reference.
    pub(super) const CRT: u32 = 0xA6;
    /// Key reference: KID || KVN.
    pub(super) const KEY_REF: u32 = 0x83;
    /// Key kind in a CA identifier: `00` KLOC (OCE CA keys), `01` KLCC (SD keys).
    pub(super) const CA_KIND: u32 = 0x80;
    /// Subject key identifier of the CA.
    pub(super) const SKI: u32 = 0x42;
    /// Certificate store.
    pub(super) const CERT_STORE: u32 = 0xBF21;
    /// Allowlist template and one serial number in it.
    pub(super) const ALLOWLIST: u32 = 0x70;
    pub(super) const SERIAL: u32 = 0x93;
    /// SCP11c replay counter of an allowlist (catalog SecurityDomain_scp11c).
    pub(super) const COUNTER: u32 = 0x92;
}

/// An EC key PUT KEY or GENERATE installs.
enum NewEc {
    Private(Vec<u8>),
    Public(Vec<u8>),
}

impl Drop for NewEc {
    fn drop(&mut self) {
        if let NewEc::Private(scalar) = self {
            scp03::wipe(scalar);
        }
    }
}

impl SecurityDomain {
    /// GET DATA (GP 2.3.1 §11.3), readable without a session:
    /// - `0066` card recognition data, `00E0` key information, `9F7F` CPLC;
    /// - `BF21` with `A6 { 83 KID KVN }`: the certificates stored for that key,
    ///   concatenated, leaf last (`6A88` if none, `6A80` for other data);
    /// - `FF33` / `FF34`: `42 <SKI> 83 <KID KVN>` for every CA identifier of an OCE CA
    ///   key (KLOC) / of a Security Domain key (KLCC); `6A88` if none.
    ///
    /// Any other tag: `6A88`.
    ///
    /// Response form by class (GP 2.3.1 §11.3.3.1: with CLA bit b8 = 1 the whole BER-TLV
    /// data object is returned, with b8 = 0 only its value, for every P1P2 except
    /// `2F00`): with `gp_class` (CLA `80`, or `84` unwrapped to `80` by a secure
    /// channel; §11.1.4.1 Table 11-11) every object comes inside the tag P1P2 names, so
    /// `66 3F 73 3D ...` (65 bytes), `E0 L C0 ...` (§11.3.3.1.1: "the key information is
    /// returned in the template 'E0'"), `9F7F 2A <CPLC>`, `BF21 L <certificates>` and
    /// `FF33`/`FF34 L <identifiers>`. The Amendment F tags follow the same base rule;
    /// Amendment F's own text was not checked. CLA `00` (and `04` through a channel)
    /// gets the bare value, as observed: `00 CA 00 66` 63 bytes, `00 CA 00 E0` the `C0`
    /// list, `00 CA 9F 7F` 42 bytes. yubikit's `SecurityDomainSession` always sends CLA
    /// `00` (`04` under SCP), so its reads are unaffected.
    ///
    /// A YubiKey 5C Nano 5.7.4 answers plaintext `80 CA 00 66` with the `66` template as
    /// well (`docs/MEASUREMENT.md`, probe `cla-variants-sd`). Its other GP-class forms
    /// (`80` for `00E0`/`9F7F`/`BF21`/`FF33`/`FF34`, and `84` through a channel) are
    /// unmeasured; this follows the specification.
    pub(crate) fn get_data(&self, cmd: &Command, gp_class: bool) -> Vec<u8> {
        let value = match (cmd.p1, cmd.p2) {
            (0x00, 0x66) => CARD_RECOGNITION.to_vec(),
            (0x00, 0xE0) => data::key_information(&self.state),
            (0x9F, 0x7F) => self.state.cplc.to_vec(),
            (0xBF, 0x21) => {
                let Some((kid, kvn)) = parse_ref_only(&cmd.data) else {
                    return apdu::status(sw::INCORRECT_DATA);
                };
                match self.state.cert_store(kid, kvn) {
                    Some(store) => store.certs.concat(),
                    None => return apdu::status(sw::REF_NOT_FOUND),
                }
            }
            (0xFF, 0x33 | 0x34) => {
                let kloc = cmd.p2 == 0x33;
                let mut out = Vec::new();
                for id in self.state.ca_ids.iter().filter(|c| if kloc { is_ca_kid(c.kid) } else { is_sd_kid(c.kid) }) {
                    tlv::encode_into(&mut out, tag::SKI, &id.ski);
                    tlv::encode_into(&mut out, tag::KEY_REF, &[id.kid, id.kvn]);
                }
                if out.is_empty() {
                    return apdu::status(sw::REF_NOT_FOUND);
                }
                out
            }
            _ => return apdu::status(sw::REF_NOT_FOUND),
        };
        if gp_class {
            // P1P2 is the tag of the object (`0066` is `66`, `00E0` is `E0`).
            let object_tag = u32::from(u16::from_be_bytes([cmd.p1, cmd.p2]));
            apdu::response(&tlv::encode(object_tag, &value), sw::OK)
        } else {
            apdu::response(&value, sw::OK)
        }
    }

    /// PUT KEY (GP 2.3.1 §11.8; Amd D for AES; Amd F for EC keys).
    ///
    /// SCP03 key set: `80 D8 <replace KVN> 81 <new KVN> { 88 L <key encrypted with the
    /// DEK> 03 <KCV> } x3`.
    /// - P1 `00` adds a set; another P1 replaces the set with that version (`6A88` if
    ///   absent). Only whole sets (P2 `81`) are accepted.
    /// - The new version is 1..=254; 0 and the factory version 255 are refused, as is a
    ///   version another set already uses (`6A80`).
    /// - Each key is AES-128, encrypted with AES-CBC (zero ICV) under the session's DEK;
    ///   the key data is the 16 encrypted bytes or, as some hosts send it, a length
    ///   byte `10` followed by them. A present KCV must match (`6A80`).
    /// - At most three sets (`6A84`). Installing a set removes the factory set.
    /// - Response: new KVN || the three KCVs.
    ///
    /// EC key: `80 D8 <replace KVN> <KID> <new KVN> <key> F0 01 00 [00]` (yubikit
    /// `put_key`): for an SCP11 private key (KID `11`/`13`/`15`) the key is `B1 20
    /// <scalar encrypted with the DEK, AES-CBC, zero ICV>`; for an OCE CA public key
    /// (KID `10`, `20`-`2F`) it is `B0 41 <uncompressed point>`. The trailing `00` is an
    /// empty key check value. The new version is 1..=127 (`6A80`), the curve P-256
    /// (`F0` value `00`). Response: the new KVN. See [`SecurityDomain::install_ec`] for
    /// replacement and capacity.
    ///
    /// Any other P2: `6A86`.
    pub(crate) fn put_key(&mut self, cmd: &Command, channel: &SecureChannel, host: &mut dyn Host) -> Vec<u8> {
        if cmd.p2 == P2_SCP03_SET {
            return self.put_scp03_set(cmd, channel.dek(), host);
        }
        let kid = cmd.p2;
        if !is_sd_kid(kid) && !is_ca_kid(kid) {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        let key = match parse_ec_key(&cmd.data, kid, channel.dek()) {
            Ok(key) => key,
            Err(status) => return apdu::status(status),
        };
        let (new_kvn, key) = key;
        match self.install_ec(kid, cmd.p1, new_kvn, key, host) {
            Ok(()) => apdu::response(&[new_kvn], sw::OK),
            Err(status) => apdu::status(status),
        }
    }

    fn put_scp03_set(&mut self, cmd: &Command, dek: &Key, host: &mut dyn Host) -> Vec<u8> {
        let Some((&new_kvn, mut rest)) = cmd.data.split_first() else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        if new_kvn == 0 || new_kvn == FACTORY_KVN {
            return apdu::status(sw::INCORRECT_DATA);
        }
        let mut keys: [Key; 3] = [[0; 16]; 3];
        let mut kcvs = [[0u8; 3]; 3];
        for (key, kcv) in keys.iter_mut().zip(kcvs.iter_mut()) {
            match parse_aes_key(rest, dek) {
                Ok((k, check, next)) => {
                    *key = k;
                    *kcv = check;
                    rest = next;
                }
                Err(status) => return apdu::status(status),
            }
        }
        if !rest.is_empty() {
            return apdu::status(sw::INCORRECT_DATA);
        }
        let replace = cmd.p1;
        if replace != 0 && !self.state.scp03.iter().any(|s| s.kvn == replace) {
            return apdu::status(sw::REF_NOT_FOUND);
        }
        if self.state.scp03.iter().any(|s| s.kvn == new_kvn && s.kvn != replace) {
            return apdu::status(sw::INCORRECT_DATA);
        }
        let mut next = self.state.clone();
        next.scp03.retain(|s| s.kvn != replace && s.kvn != FACTORY_KVN);
        let [enc, mac, dek] = keys;
        next.scp03.push(Scp03Set { kvn: new_kvn, enc, mac, dek, tries: AUTH_TRIES });
        if next.scp03.len() > MAX_SCP03_SETS {
            return apdu::status(sw::NO_SPACE);
        }
        next.normalize();
        if let Err(status) = self.commit(next, host) {
            return apdu::status(status);
        }
        // A half-open handshake under a set that was replaced, overwritten or removed
        // (the factory set) cannot be completed.
        self.drop_pending_for(&[replace, new_kvn, FACTORY_KVN]);
        let mut data = Vec::with_capacity(10);
        data.push(new_kvn);
        data.extend_from_slice(kcvs.as_flattened());
        apdu::response(&data, sw::OK)
    }

    /// GENERATE EC KEY (Yubico proprietary, yubikit `generate_ec_key`): `80 F1 <replace
    /// KVN> <KID> <new KVN> F0 01 00`. KID `11`, `13` or `15` (`6A86` otherwise), new
    /// version 1..=127, curve P-256 (`6A80` otherwise). The key is drawn from host
    /// entropy and installed like an imported one; the response is `B0 41 <point>`.
    pub(crate) fn generate_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Vec<u8> {
        let kid = cmd.p2;
        if !is_sd_kid(kid) {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        let new_kvn = match cmd.data.as_slice() {
            [kvn, 0xF0, 0x01, 0x00] if is_scp11_kvn(*kvn) => *kvn,
            _ => return apdu::status(sw::INCORRECT_DATA),
        };
        let key = EcPrivateKey::generate(Curve::P256, host);
        let point = key.public_uncompressed();
        match self.install_ec(kid, cmd.p1, new_kvn, NewEc::Private(key.scalar().to_vec()), host) {
            Ok(()) => apdu::response(&tlv::encode(u32::from(KEY_TYPE_EC_PUBLIC), &point), sw::OK),
            Err(status) => apdu::status(status),
        }
    }

    /// Install an EC key at (`kid`, `new_kvn`), replacing (`kid`, `replace`) when
    /// `replace` is not zero.
    ///
    /// - Replacing a missing key: `6A88`. A new version another key of this KID already
    ///   uses: `6A80`. More than sixteen EC keys in all: `6A84`.
    /// - Replacing an SCP11 private key drops its certificate store and CA identifier
    ///   (they described the old key).
    /// - Replacing an OCE CA key keeps its allowlist and SCP11c counter (moved to the new
    ///   version) and drops its CA identifier and certificates (catalog
    ///   SecurityDomain_oce_cache: "CA-key replacement retains linked allowlist and
    ///   cached OCE while discarding old SKI"). The cached OCE is kept; a partial chain
    ///   is dropped.
    fn install_ec(&mut self, kid: u8, replace: u8, new_kvn: u8, key: NewEc, host: &mut dyn Host) -> Result<(), u16> {
        let exists = |state: &State, kvn: u8| state.ec_exists(kid, kvn);
        if replace != 0 && !exists(&self.state, replace) {
            return Err(sw::REF_NOT_FOUND);
        }
        if new_kvn != replace && exists(&self.state, new_kvn) {
            return Err(sw::INCORRECT_DATA);
        }
        let mut next = self.state.clone();
        if replace != 0 {
            let list = next.allowlist(kid, replace).cloned();
            let counter = next.counter(kid, replace);
            next.ec_private.retain(|k| !(k.kid == kid && k.kvn == replace));
            next.ec_public.retain(|k| !(k.kid == kid && k.kvn == replace));
            next.drop_key_data(kid, replace);
            if let (Some(list), NewEc::Public(_)) = (list, &key) {
                next.allowlists.push(Allowlist { kvn: new_kvn, ..list });
            }
            if counter > next.counter(kid, new_kvn) {
                next.set_counter(kid, new_kvn, counter);
            }
        }
        match &key {
            NewEc::Private(scalar) => {
                next.ec_private.push(EcPrivate { kid, kvn: new_kvn, scalar: scalar.clone(), tries: AUTH_TRIES })
            }
            NewEc::Public(point) => {
                next.ec_public.push(EcPublic { kid, kvn: new_kvn, point: point.clone(), tries: AUTH_TRIES })
            }
        }
        if next.ec_rows() > MAX_EC_ROWS {
            return Err(sw::NO_SPACE);
        }
        next.normalize();
        self.commit(next, host)?;
        // A chain being presented under the replaced CA key is not a fresh PSO for the
        // replacement (catalog SecurityDomain_shared_state: "fresh PSO enforces the
        // replacement CA"); a complete, verified OCE stays cached.
        if replace != 0 && is_ca_kid(kid) {
            self.oce_chain = None;
        }
        Ok(())
    }

    /// DELETE KEY (GP 2.3.1 §11.2): `80 E4 00 <00|01> { D0 01 KID } { D2 01 KVN }`.
    ///
    /// Every key matching the given KID and/or KVN is deleted; an SCP03 set matches as a
    /// whole when its KVN matches and the KID (if given) is 1, 2 or 3. No match: `6A88`.
    /// P1 must be `00` and P2 `00` or `01` (`6A86`); a data field without exactly the
    /// known objects is `6A80`. A deleted EC key takes its certificate store, CA
    /// identifier and allowlist with it ("deletion discards list"); SCP11c counters stay.
    /// Deleting the CA of the cached OCE drops the cache; deleting any CA drops a
    /// partial certificate chain; deleting an SCP03 set drops a half-open handshake
    /// under it.
    ///
    /// Deleting the last key that can manage the domain (every SCP03 set and SCP11a/c
    /// key) needs P2 `01` (otherwise `6985`, nothing deleted) and resets the Security
    /// Domain to its factory state (Yubico yk5-apps-scp; catalog SecurityDomain_metadata:
    /// "explicit last-management-key deletion restores fresh default Domain identity and
    /// rotates CPLC"). The current session protects this response and then ends.
    pub(crate) fn delete_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Vec<u8> {
        if cmd.p1 != 0x00 || cmd.p2 > 0x01 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        let Ok(items) = tlv::parse_all(&cmd.data) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let mut kid = None;
        let mut kvn = None;
        for item in &items {
            let slot = match item.tag {
                TAG_KEY_ID => &mut kid,
                TAG_KEY_VERSION => &mut kvn,
                _ => return apdu::status(sw::INCORRECT_DATA),
            };
            match (item.value, slot.is_some()) {
                ([value], false) => *slot = Some(*value),
                _ => return apdu::status(sw::INCORRECT_DATA),
            }
        }
        if kid.is_none() && kvn.is_none() {
            return apdu::status(sw::INCORRECT_DATA);
        }
        let set_matches =
            |set_kvn: u8| kvn.is_none_or(|v| v == set_kvn) && kid.is_none_or(|k| (1..=3).contains(&k));
        let ec_matches = |k_kid: u8, k_kvn: u8| kvn.is_none_or(|v| v == k_kvn) && kid.is_none_or(|k| k == k_kid);

        let mut next = self.state.clone();
        let removed_sets: Vec<u8> = next.scp03.iter().map(|s| s.kvn).filter(|&v| set_matches(v)).collect();
        let removed_ec: Vec<(u8, u8)> = next
            .ec_private
            .iter()
            .map(|k| (k.kid, k.kvn))
            .chain(next.ec_public.iter().map(|k| (k.kid, k.kvn)))
            .filter(|&(k, v)| ec_matches(k, v))
            .collect();
        let before = next.scp03.len() + next.ec_rows();
        next.scp03.retain(|s| !set_matches(s.kvn));
        next.ec_private.retain(|k| !ec_matches(k.kid, k.kvn));
        next.ec_public.retain(|k| !ec_matches(k.kid, k.kvn));
        if next.scp03.len() + next.ec_rows() == before {
            return apdu::status(sw::REF_NOT_FOUND);
        }
        for &(k, v) in &removed_ec {
            next.drop_key_data(k, v);
        }
        let result = if next.has_management_key() {
            self.commit(next, host)
        } else if cmd.p2 == 0x01 {
            self.factory_reset(host)
        } else {
            return apdu::status(sw::CONDITIONS);
        };
        if let Err(status) = result {
            return apdu::status(status);
        }
        self.drop_pending_for(&removed_sets);
        if removed_ec.iter().any(|&(k, _)| is_ca_kid(k)) {
            self.oce_chain = None;
            if self.oce.as_ref().is_some_and(|o| removed_ec.contains(&o.anchor)) {
                self.oce = None;
            }
        }
        apdu::status(sw::OK)
    }

    /// STORE DATA (GP 2.3.1 §11.11; Amendment F objects; yubikit layouts), one block:
    /// P1 `80` or `90` (last block, no encryption, no or BER-TLV structure) and P2 `00`
    /// (`6A86` otherwise). The data is one of:
    /// - certificate store: `A6 { 83 KID KVN } BF21 { DER certificates }` (at most
    ///   eight; empty removes the store) for an existing EC key;
    /// - allowlist: `A6 { 83 KID KVN } 70 { 93 <serial> ... }` (at most 64; empty clears
    ///   the list) for an existing OCE CA key, with `92 02 <counter>` (inside `A6` or at
    ///   the top level, exactly once) in an SCP11c session and nowhere else;
    /// - CA identifier: `A6 { 80 01 <00 KLOC | 01 KLCC> 42 <SKI> 83 KID KVN }` for an
    ///   existing EC key of the matching kind.
    ///
    /// Malformed or ambiguous data: `6A80`; unknown key: `6A88`; too many entries:
    /// `6A84`. In an SCP11c session only the allowlist form is accepted (`6985`
    /// otherwise), because a replayed session could repeat any other write.
    pub(crate) fn store_data(&mut self, cmd: &Command, scp11c: bool, host: &mut dyn Host) -> Vec<u8> {
        // b8 last block; b7-b6 `00` no encryption; b5-b4 `00` or `10` (BER-TLV); b3-b1 `000`.
        let p1_ok = cmd.p1 & 0x80 != 0 && cmd.p1 & 0x6F == 0;
        if !p1_ok || cmd.p2 != 0x00 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        let Ok(items) = tlv::parse_all(&cmd.data) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let tags: Vec<u32> = items.iter().map(|i| i.tag).collect();
        let once = |t: u32| tags.iter().filter(|&&x| x == t).count() == 1;
        let Some(crt) = tlv::find(&items, tag::CRT).filter(|_| once(tag::CRT)) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let Ok(children) = tlv::parse_all(crt.value) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let has = |t: u32| tags.contains(&t);
        let others_only = |allowed: &[u32]| tags.iter().all(|t| *t == tag::CRT || allowed.contains(t));
        if has(tag::CERT_STORE) && once(tag::CERT_STORE) && others_only(&[tag::CERT_STORE]) {
            if scp11c {
                return apdu::status(sw::CONDITIONS);
            }
            let (Some(cert_store), Some((kid, kvn))) = (tlv::find(&items, tag::CERT_STORE), ref_only(&children)) else {
                return apdu::status(sw::INCORRECT_DATA);
            };
            return self.store_certificates(kid, kvn, cert_store.value, host);
        }
        if has(tag::ALLOWLIST) && once(tag::ALLOWLIST) && others_only(&[tag::ALLOWLIST, tag::COUNTER]) {
            return self.store_allowlist(&items, &children, scp11c, host);
        }
        if tags.len() == 1 {
            if scp11c {
                return apdu::status(sw::CONDITIONS);
            }
            return self.store_ca_identifier(&children, host);
        }
        apdu::status(sw::INCORRECT_DATA)
    }

    fn store_certificates(&mut self, kid: u8, kvn: u8, value: &[u8], host: &mut dyn Host) -> Vec<u8> {
        let mut certs = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            let Ok((element, next)) = der::split_der(rest) else {
                return apdu::status(sw::INCORRECT_DATA);
            };
            if element.first() != Some(&der::tag::SEQUENCE) {
                return apdu::status(sw::INCORRECT_DATA);
            }
            certs.push(element.to_vec());
            rest = next;
        }
        if certs.len() > MAX_CERTIFICATES {
            return apdu::status(sw::NO_SPACE);
        }
        if !self.state.ec_exists(kid, kvn) {
            return apdu::status(sw::REF_NOT_FOUND);
        }
        let mut next = self.state.clone();
        next.certs.retain(|c| !(c.kid == kid && c.kvn == kvn));
        if !certs.is_empty() {
            next.certs.push(CertStore { kid, kvn, certs });
        }
        next.normalize();
        match self.commit(next, host) {
            Ok(()) => apdu::status(sw::OK),
            Err(status) => apdu::status(status),
        }
    }

    /// The allowlist form of STORE DATA. Every successful update, even an identical one
    /// or a clear, drops the cached OCE and any partial chain (catalog
    /// SecurityDomain_oce_cache); a refused one changes nothing. In an SCP11c session the
    /// counter must be above the last one accepted for this CA (a replay answers
    /// `6982`), and list and counter are committed together; if that commit fails the
    /// SCP11c session ends (catalog SecurityDomain_scp11c).
    fn store_allowlist(
        &mut self,
        items: &[tlv::Tlv<'_>],
        children: &[tlv::Tlv<'_>],
        scp11c: bool,
        host: &mut dyn Host,
    ) -> Vec<u8> {
        // The key reference, and the counter inside A6 or at the top level (not both).
        let mut key_ref = None;
        let mut counters: Vec<&[u8]> = items.iter().filter(|i| i.tag == tag::COUNTER).map(|i| i.value).collect();
        for child in children {
            match (child.tag, child.value) {
                (tag::KEY_REF, [kid, kvn]) if key_ref.is_none() => key_ref = Some((*kid, *kvn)),
                (tag::COUNTER, value) => counters.push(value),
                _ => return apdu::status(sw::INCORRECT_DATA),
            }
        }
        let Some((kid, kvn)) = key_ref else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let Some(list) = tlv::find(items, tag::ALLOWLIST) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let Ok(entries) = tlv::parse_all(list.value) else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let mut serials: Vec<Vec<u8>> = Vec::new();
        for entry in &entries {
            if entry.tag != tag::SERIAL {
                return apdu::status(sw::INCORRECT_DATA);
            }
            let Ok(serial) = normalize_serial(entry.value) else {
                return apdu::status(sw::INCORRECT_DATA);
            };
            if !serials.contains(&serial) {
                serials.push(serial);
            }
        }
        let counter = match (scp11c, counters.as_slice()) {
            (false, []) => None,
            (true, [[hi, lo]]) => {
                let value = u16::from_be_bytes([*hi, *lo]);
                if value == 0 || value > MAX_LIST_COUNTER {
                    return apdu::status(sw::INCORRECT_DATA);
                }
                Some(value)
            }
            _ => return apdu::status(sw::INCORRECT_DATA),
        };
        if serials.len() > MAX_ALLOWLIST {
            return apdu::status(sw::NO_SPACE);
        }
        if self.state.public_key(kid, kvn).is_none() {
            return apdu::status(sw::REF_NOT_FOUND);
        }
        if let Some(value) = counter
            && value <= self.state.counter(kid, kvn)
        {
            return apdu::status(sw::SECURITY_STATUS);
        }
        let mut next = self.state.clone();
        next.allowlists.retain(|a| !(a.kid == kid && a.kvn == kvn));
        if !serials.is_empty() {
            next.allowlists.push(Allowlist { kid, kvn, serials });
        }
        if let Some(value) = counter {
            next.set_counter(kid, kvn, value);
        }
        next.normalize();
        if let Err(status) = self.commit(next, host) {
            if scp11c {
                Shared::bump(&self.shared.c_epoch);
            }
            return apdu::status(status);
        }
        self.clear_oce();
        apdu::status(sw::OK)
    }

    fn store_ca_identifier(&mut self, children: &[tlv::Tlv<'_>], host: &mut dyn Host) -> Vec<u8> {
        let tags: Vec<u32> = children.iter().map(|c| c.tag).collect();
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        if sorted != [tag::SKI, tag::CA_KIND, tag::KEY_REF] {
            return apdu::status(sw::INCORRECT_DATA);
        }
        let value = |t: u32| tlv::find(children, t).map_or(&[][..], |c| c.value);
        let (kind, ski, key_ref) = (value(tag::CA_KIND), value(tag::SKI), value(tag::KEY_REF));
        let &[kid, kvn] = key_ref else {
            return apdu::status(sw::INCORRECT_DATA);
        };
        let kind_ok = match kind {
            [0x00] => is_ca_kid(kid),
            [0x01] => is_sd_kid(kid),
            _ => false,
        };
        if !kind_ok || ski.is_empty() || ski.len() > MAX_SKI_LEN {
            return apdu::status(sw::INCORRECT_DATA);
        }
        if !self.state.ec_exists(kid, kvn) {
            return apdu::status(sw::REF_NOT_FOUND);
        }
        let mut next = self.state.clone();
        next.ca_ids.retain(|c| !(c.kid == kid && c.kvn == kvn));
        next.ca_ids.push(CaIdentifier { kid, kvn, ski: ski.to_vec() });
        next.normalize();
        match self.commit(next, host) {
            Ok(()) => apdu::status(sw::OK),
            Err(status) => apdu::status(status),
        }
    }
}

/// `A6 { 83 02 KID KVN }` and nothing else.
fn parse_ref_only(data: &[u8]) -> Option<(u8, u8)> {
    let (crt, rest) = tlv::parse_one(data).ok()?;
    if crt.tag != tag::CRT || !rest.is_empty() {
        return None;
    }
    ref_only(&tlv::parse_all(crt.value).ok()?)
}

/// The children of `A6` are exactly `83 02 KID KVN`.
fn ref_only(children: &[tlv::Tlv<'_>]) -> Option<(u8, u8)> {
    match children {
        [child] if child.tag == tag::KEY_REF => match child.value {
            [kid, kvn] => Some((*kid, *kvn)),
            _ => None,
        },
        _ => None,
    }
}

/// The data of an EC PUT KEY: new KVN, the key object of the kind `kid` asks for, the
/// key parameter reference `F0 01 00`, and an optional empty KCV (`00`).
fn parse_ec_key(data: &[u8], kid: u8, dek: &Key) -> Result<(u8, NewEc), u16> {
    let (&new_kvn, mut rest) = data.split_first().ok_or(sw::INCORRECT_DATA)?;
    if !is_scp11_kvn(new_kvn) {
        return Err(sw::INCORRECT_DATA);
    }
    let private = is_sd_kid(kid);
    let mut key = None;
    let mut params = None;
    while !rest.is_empty() && rest != [0x00] {
        let (object, next) = tlv::parse_one(rest).map_err(|_| sw::INCORRECT_DATA)?;
        let slot = match object.tag {
            t if t == u32::from(KEY_TYPE_EC_PRIVATE) && private => &mut key,
            t if t == u32::from(KEY_TYPE_EC_PUBLIC) && !private => &mut key,
            t if t == u32::from(KEY_TYPE_EC_PARAMETERS) => &mut params,
            _ => return Err(sw::INCORRECT_DATA),
        };
        if slot.replace(object.value).is_some() {
            return Err(sw::INCORRECT_DATA);
        }
        rest = next;
    }
    if params != Some(&[0x00][..]) {
        return Err(sw::INCORRECT_DATA);
    }
    let value = key.ok_or(sw::INCORRECT_DATA)?;
    if private {
        if value.len() != 32 {
            return Err(sw::INCORRECT_DATA);
        }
        let mut scalar = lk_crypto::aes_cbc_decrypt(dek, &[0u8; 16], value).map_err(|_| sw::INCORRECT_DATA)?;
        if EcPrivateKey::from_scalar(Curve::P256, &scalar).is_err() {
            scp03::wipe(&mut scalar);
            return Err(sw::INCORRECT_DATA);
        }
        Ok((new_kvn, NewEc::Private(scalar)))
    } else if lk_crypto::ec_public_is_valid(Curve::P256, value) {
        Ok((new_kvn, NewEc::Public(value.to_vec())))
    } else {
        Err(sw::INCORRECT_DATA)
    }
}

/// One AES key block of PUT KEY: `88 L <encrypted key> <KCV length> <KCV>`. Returns the
/// clear key, its computed KCV and the bytes after the block.
fn parse_aes_key<'a>(input: &'a [u8], dek: &Key) -> Result<(Key, [u8; 3], &'a [u8]), u16> {
    let (object, rest) = tlv::parse_one(input).map_err(|_| sw::INCORRECT_DATA)?;
    if object.tag != u32::from(KEY_TYPE_AES) {
        return Err(sw::INCORRECT_DATA);
    }
    let encrypted = match object.value {
        v if v.len() == 16 => v,
        [0x10, v @ ..] if v.len() == 16 => v,
        _ => return Err(sw::INCORRECT_DATA),
    };
    let mut clear = lk_crypto::aes_cbc_decrypt(dek, &[0u8; 16], encrypted).map_err(|_| sw::INCORRECT_DATA)?;
    let key = scp03::to_key(&clear);
    scp03::wipe(&mut clear);
    let key = key.ok_or(sw::INCORRECT_DATA)?;
    let computed = scp03::key_check_value(&key)?;
    let (&kcv_len, rest) = rest.split_first().ok_or(sw::INCORRECT_DATA)?;
    let (kcv, rest) = rest.split_at_checked(usize::from(kcv_len)).ok_or(sw::INCORRECT_DATA)?;
    match kcv_len {
        0 => {}
        3 if lk_crypto::ct_eq(kcv, &computed) => {}
        _ => return Err(sw::INCORRECT_DATA),
    }
    Ok((key, computed, rest))
}
