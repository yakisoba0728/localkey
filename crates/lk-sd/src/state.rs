//! Persistent Security Domain state and its serialized form.
//!
//! Format (`docs/CONTRACTS.md`, "Persisted state"): version byte `0x01`, then BER-TLV
//! objects (ISO/IEC 7816-4 §5.2.2) via `lk_codec::tlv`:
//!
//! | Tag | Content |
//! | --- | --- |
//! | `81` | CPLC, 42 bytes |
//! | `82` | content revision, `02` (absent in records written before SCP11 support) |
//! | `A1` | one SCP03 key set: `80` KVN, `81` K-ENC, `82` K-MAC, `83` K-DEK, `84` tries left |
//! | `A2` | one SCP11 private key: `80` KID, `81` KVN, `82` curve parameter reference (`00` = P-256), `83` scalar, `84` tries left |
//! | `A3` | one OCE CA public key: `80` KID, `81` KVN, `82` curve (`00`), `83` point, `84` tries left |
//! | `A4` | certificate store of one key: `80` KID, `81` KVN, `83` one DER certificate (repeated, in order) |
//! | `A5` | CA issuer identifier of one key: `80` KID, `81` KVN, `83` subject key identifier |
//! | `A6` | serial allowlist of one CA key: `80` KID, `81` KVN, `83` one serial magnitude (repeated) |
//! | `A7` | SCP11c allowlist counter of one CA reference: `80` KID, `81` KVN, `84` counter (2 bytes) |
//! | other | kept byte for byte and written back (fields of a later format revision) |
//!
//! Unknown child tags inside the templates are skipped. A record that is not version
//! `01`, is not well-formed BER-TLV, holds no key at all, or breaks an invariant below is
//! unreadable, and the Security Domain starts from its factory state. A readable record
//! without a CPLC gets a new one while keys and counters are kept, and a record without
//! the revision object gets a self-signed certificate for each SCP11b key that has no
//! certificate store (catalog SecurityDomain_metadata and SecurityDomain_shared_state:
//! absent metadata is added on load without replacing keys, certificates, retries or the
//! CPLC).

use lk_codec::tlv;
use lk_core::Host;
use lk_crypto::{Curve, EcPrivateKey};

use crate::cert;
use crate::scp03::{self, Key};

/// Serialization format version.
pub(crate) const FORMAT_VERSION: u8 = 0x01;

/// Content revision written in tag `82`. Records without it predate SCP11 support.
pub(crate) const CONTENT_REVISION: u8 = 0x02;

/// Authentication attempts per key before it is removed. Yubico does not publish the
/// number ("for example, 32 times in a row", yk5-apps-scp); this model keeps the value
/// of `reference/legacy-v0.64-profiles.json` `security_domain_profile.software_authentication_tries`.
/// yubikit's `SecurityDomainSession.reset()` tries each key 65 times, which fits.
pub(crate) const AUTH_TRIES: u8 = 64;

/// The factory SCP03 key version (Yubico yk5-apps-scp: "one key set installed with key
/// version 255").
pub(crate) const FACTORY_KVN: u8 = 0xFF;

/// The factory SCP03 keys, Yubico's published test keys `40 41 .. 4F` for K-ENC, K-MAC
/// and K-DEK (yk5-apps-scp).
pub(crate) const FACTORY_KEY: Key = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

/// SCP03 key sets the YubiKey stores at once ("up to three key sets", yk5-apps-scp).
pub(crate) const MAX_SCP03_SETS: usize = 3;

/// EC keys (SCP11 private keys and OCE CA public keys together) the model stores
/// (`reference/legacy-v0.64-profiles.json` `software_combined_ec_row_capacity`; the
/// physical capacity is unpublished).
pub(crate) const MAX_EC_ROWS: usize = 16;

/// Certificates per stored bundle and per presented OCE chain
/// (`software_certificate_chain_capacity`).
pub(crate) const MAX_CERTIFICATES: usize = 8;

/// Serial numbers per allowlist (`software_serial_allowlist_capacity`).
pub(crate) const MAX_ALLOWLIST: usize = 64;

/// Largest serial number magnitude: RFC 5280 §4.1.2.2 allows at most 20 octets.
pub(crate) const MAX_SERIAL_LEN: usize = 20;

/// Largest subject key identifier accepted in STORE DATA. RFC 5280 §4.2.1.2 leaves the
/// length open; 20 bytes (SHA-1) is usual.
pub(crate) const MAX_SKI_LEN: usize = 64;

/// Largest SCP11c allowlist counter: tag `92` holds two bytes, positive
/// (catalog SecurityDomain_scp11c: "1..32767").
pub(crate) const MAX_LIST_COUNTER: u16 = 0x7FFF;

/// Key identifiers (GP Amendment F, Yubico SD documentation): SCP03 keys are KID 1-3
/// of a set; SCP11a, SCP11b and SCP11c private keys are `11`, `13` and `15`; OCE CA
/// public keys (CA-KLOC) are `10` and `20`-`2F`.
pub(crate) const KID_SCP03_ENC: u8 = 0x01;
pub(crate) const KID_SCP03_MAC: u8 = 0x02;
pub(crate) const KID_SCP03_DEK: u8 = 0x03;
pub(crate) const KID_OCE: u8 = 0x10;
pub(crate) const KID_SCP11A: u8 = 0x11;
pub(crate) const KID_SCP11B: u8 = 0x13;
pub(crate) const KID_SCP11C: u8 = 0x15;

/// Key version of the factory SCP11b key.
pub(crate) const FACTORY_SCP11B_KVN: u8 = 0x01;

/// Length of the CPLC data (GP Card Specification v2.3.1 Annex H, tag `9F7F`).
pub(crate) const CPLC_LEN: usize = 42;

/// Whether `kid` names an SCP11 Security Domain private key.
pub(crate) fn is_sd_kid(kid: u8) -> bool {
    matches!(kid, KID_SCP11A | KID_SCP11B | KID_SCP11C)
}

/// Whether `kid` names an OCE CA public key (CA-KLOC).
pub(crate) fn is_ca_kid(kid: u8) -> bool {
    kid == KID_OCE || (0x20..=0x2F).contains(&kid)
}

/// SCP11 key versions are 1-127 (catalog SecurityDomain_versions: "seven-bit 1..127
/// profile; 0/128/255 rejected").
pub(crate) fn is_scp11_kvn(kvn: u8) -> bool {
    (1..=0x7F).contains(&kvn)
}

mod tag {
    pub(super) const CPLC: u32 = 0x81;
    pub(super) const REVISION: u32 = 0x82;
    pub(super) const SCP03_SET: u32 = 0xA1;
    pub(super) const EC_PRIVATE: u32 = 0xA2;
    pub(super) const EC_PUBLIC: u32 = 0xA3;
    pub(super) const CERTIFICATES: u32 = 0xA4;
    pub(super) const CA_IDENTIFIER: u32 = 0xA5;
    pub(super) const ALLOWLIST: u32 = 0xA6;
    pub(super) const LIST_COUNTER: u32 = 0xA7;
    pub(super) const F0: u32 = 0x80;
    pub(super) const F1: u32 = 0x81;
    pub(super) const F2: u32 = 0x82;
    pub(super) const F3: u32 = 0x83;
    pub(super) const F4: u32 = 0x84;
}

/// One SCP03 key set (GP Amd D §6.1: K-ENC, K-MAC, K-DEK under one key version).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Scp03Set {
    pub(crate) kvn: u8,
    pub(crate) enc: Key,
    pub(crate) mac: Key,
    pub(crate) dek: Key,
    pub(crate) tries: u8,
}

impl core::fmt::Debug for Scp03Set {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scp03Set")
            .field("kvn", &self.kvn)
            .field("tries", &self.tries)
            .finish_non_exhaustive()
    }
}

impl Drop for Scp03Set {
    fn drop(&mut self) {
        scp03::wipe(&mut self.enc);
        scp03::wipe(&mut self.mac);
        scp03::wipe(&mut self.dek);
    }
}

/// One SCP11 private key on P-256 (key parameter reference `00`).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EcPrivate {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
    pub(crate) scalar: Vec<u8>,
    pub(crate) tries: u8,
}

impl core::fmt::Debug for EcPrivate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcPrivate")
            .field("kid", &self.kid)
            .field("kvn", &self.kvn)
            .field("tries", &self.tries)
            .finish_non_exhaustive()
    }
}

impl Drop for EcPrivate {
    fn drop(&mut self) {
        scp03::wipe(&mut self.scalar);
    }
}

/// One OCE CA public key (CA-KLOC, GP Amendment F) on P-256: the trust anchor that
/// PERFORM SECURITY OPERATION verifies OCE certificate chains against. Its tries count
/// malformed certificate uploads (yubikit's reset blocks these rows with PSO).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EcPublic {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
    /// Uncompressed SEC1 point.
    pub(crate) point: Vec<u8>,
    pub(crate) tries: u8,
}

/// The certificate store of one key (GET DATA / STORE DATA `BF21`), leaf last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertStore {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
    pub(crate) certs: Vec<Vec<u8>>,
}

/// The CA issuer subject key identifier of one key (STORE DATA `A6 { 80, 42, 83 }`,
/// GET DATA `FF33` for KLOC keys and `FF34` for KLCC keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaIdentifier {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
    pub(crate) ski: Vec<u8>,
}

/// The serial number allowlist of one OCE CA key (STORE DATA `70 { 93 .. }`). Serials
/// are kept as unsigned magnitudes without leading zero bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Allowlist {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
    pub(crate) serials: Vec<Vec<u8>>,
}

/// The last SCP11c allowlist counter accepted for a CA reference. Never reset, not even
/// when the list is cleared or the CA key replaced or deleted (catalog
/// SecurityDomain_scp11c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListCounter {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
    pub(crate) value: u16,
}

/// Everything the Security Domain persists.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct State {
    /// Sorted by KVN.
    pub(crate) scp03: Vec<Scp03Set>,
    /// Sorted by (KID, KVN).
    pub(crate) ec_private: Vec<EcPrivate>,
    /// Sorted by (KID, KVN).
    pub(crate) ec_public: Vec<EcPublic>,
    /// Sorted by (KID, KVN).
    pub(crate) certs: Vec<CertStore>,
    /// Sorted by (KID, KVN).
    pub(crate) ca_ids: Vec<CaIdentifier>,
    /// Sorted by (KID, KVN).
    pub(crate) allowlists: Vec<Allowlist>,
    /// Sorted by (KID, KVN).
    pub(crate) counters: Vec<ListCounter>,
    pub(crate) cplc: [u8; CPLC_LEN],
    /// Top-level objects this revision does not know, written back unchanged.
    pub(crate) extra: Vec<Vec<u8>>,
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("State")
            .field("scp03", &self.scp03)
            .field("ec_private", &self.ec_private)
            .field("ec_public", &self.ec_public)
            .field("cert_stores", &self.certs.len())
            .field("ca_ids", &self.ca_ids)
            .field("allowlists", &self.allowlists)
            .field("counters", &self.counters)
            .field("extra_objects", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// A parsed record and what it lacked.
pub(crate) struct Parsed {
    pub(crate) state: State,
    pub(crate) missing_cplc: bool,
    /// The record predates SCP11 support (no revision object).
    pub(crate) missing_revision: bool,
}

impl State {
    fn empty() -> Self {
        Self {
            scp03: Vec::new(),
            ec_private: Vec::new(),
            ec_public: Vec::new(),
            certs: Vec::new(),
            ca_ids: Vec::new(),
            allowlists: Vec::new(),
            counters: Vec::new(),
            cplc: [0; CPLC_LEN],
            extra: Vec::new(),
        }
    }

    /// The factory state: the default SCP03 key set (KVN `FF`, keys `40..4F`), a fresh
    /// SCP11b P-256 key (KID `13`, KVN `01`) with its own self-signed certificate, and a
    /// fresh CPLC identifier. This is also the state after a Security Domain reset
    /// (Yubico: "the security domain is automatically reset with the default key set
    /// installed"; catalog SecurityDomain: "fresh own SCP11b identity").
    pub(crate) fn factory(host: &mut dyn Host) -> Self {
        let key = EcPrivateKey::generate(Curve::P256, host);
        let certificate = cert::own_certificate(&key, host);
        let cplc = new_cplc(host);
        let mut state = Self::empty();
        state.scp03.push(Scp03Set {
            kvn: FACTORY_KVN,
            enc: FACTORY_KEY,
            mac: FACTORY_KEY,
            dek: FACTORY_KEY,
            tries: AUTH_TRIES,
        });
        state.ec_private.push(EcPrivate {
            kid: KID_SCP11B,
            kvn: FACTORY_SCP11B_KVN,
            scalar: key.scalar().to_vec(),
            tries: AUTH_TRIES,
        });
        state.certs.push(CertStore { kid: KID_SCP11B, kvn: FACTORY_SCP11B_KVN, certs: vec![certificate] });
        state.cplc = cplc;
        state
    }

    /// Give every SCP11b key without a certificate store its own self-signed
    /// certificate (migration of records written before SCP11 support).
    pub(crate) fn add_own_certificates(&mut self, host: &mut dyn Host) {
        let missing: Vec<(u8, u8, Vec<u8>)> = self
            .ec_private
            .iter()
            .filter(|k| k.kid == KID_SCP11B && self.cert_store(k.kid, k.kvn).is_none())
            .map(|k| (k.kid, k.kvn, k.scalar.clone()))
            .collect();
        for (kid, kvn, mut scalar) in missing {
            if let Ok(key) = EcPrivateKey::from_scalar(Curve::P256, &scalar) {
                let certificate = cert::own_certificate(&key, host);
                self.certs.push(CertStore { kid, kvn, certs: vec![certificate] });
            }
            scp03::wipe(&mut scalar);
        }
        self.normalize();
    }

    /// Whether any key is left. When the last one is removed by repeated failures the
    /// Security Domain resets (Yubico yk5-apps-scp: "When the last key set is deleted,
    /// the security domain is automatically reset"). OCE CA keys count: yubikit's reset
    /// blocks them too, and resetting earlier would leave its remaining requests
    /// pointing at keys that no longer exist.
    pub(crate) fn has_any_key(&self) -> bool {
        !self.scp03.is_empty() || !self.ec_private.is_empty() || !self.ec_public.is_empty()
    }

    /// Whether any key can open a session that manages keys: an SCP03 set or an SCP11a
    /// or SCP11c private key (SCP11b cannot provision keys; catalog SCP11).
    pub(crate) fn has_management_key(&self) -> bool {
        !self.scp03.is_empty()
            || self.ec_private.iter().any(|k| k.kid == KID_SCP11A || k.kid == KID_SCP11C)
    }

    /// Number of EC rows (private and public).
    pub(crate) fn ec_rows(&self) -> usize {
        self.ec_private.len() + self.ec_public.len()
    }

    /// Whether an EC key (private or public) with this reference exists.
    pub(crate) fn ec_exists(&self, kid: u8, kvn: u8) -> bool {
        self.ec_private.iter().any(|k| k.kid == kid && k.kvn == kvn)
            || self.ec_public.iter().any(|k| k.kid == kid && k.kvn == kvn)
    }

    pub(crate) fn public_key(&self, kid: u8, kvn: u8) -> Option<&EcPublic> {
        self.ec_public.iter().find(|k| k.kid == kid && k.kvn == kvn)
    }

    pub(crate) fn cert_store(&self, kid: u8, kvn: u8) -> Option<&CertStore> {
        self.certs.iter().find(|c| c.kid == kid && c.kvn == kvn)
    }

    pub(crate) fn ca_identifier(&self, kid: u8, kvn: u8) -> Option<&CaIdentifier> {
        self.ca_ids.iter().find(|c| c.kid == kid && c.kvn == kvn)
    }

    pub(crate) fn allowlist(&self, kid: u8, kvn: u8) -> Option<&Allowlist> {
        self.allowlists.iter().find(|a| a.kid == kid && a.kvn == kvn)
    }

    pub(crate) fn counter(&self, kid: u8, kvn: u8) -> u16 {
        self.counters.iter().find(|c| c.kid == kid && c.kvn == kvn).map_or(0, |c| c.value)
    }

    pub(crate) fn set_counter(&mut self, kid: u8, kvn: u8, value: u16) {
        match self.counters.iter_mut().find(|c| c.kid == kid && c.kvn == kvn) {
            Some(c) => c.value = value,
            None => self.counters.push(ListCounter { kid, kvn, value }),
        }
        self.normalize();
    }

    /// Drop the certificate store, CA identifier and allowlist attached to a key that
    /// is being deleted. SCP11c counters stay (they must never go backwards).
    pub(crate) fn drop_key_data(&mut self, kid: u8, kvn: u8) {
        self.certs.retain(|c| !(c.kid == kid && c.kvn == kvn));
        self.ca_ids.retain(|c| !(c.kid == kid && c.kvn == kvn));
        self.allowlists.retain(|a| !(a.kid == kid && a.kvn == kvn));
    }

    /// Restore the sort orders after an edit.
    pub(crate) fn normalize(&mut self) {
        self.scp03.sort_by_key(|s| s.kvn);
        self.ec_private.sort_by_key(|k| (k.kid, k.kvn));
        self.ec_public.sort_by_key(|k| (k.kid, k.kvn));
        self.certs.sort_by_key(|c| (c.kid, c.kvn));
        self.ca_ids.sort_by_key(|c| (c.kid, c.kvn));
        self.allowlists.sort_by_key(|a| (a.kid, a.kvn));
        self.counters.sort_by_key(|c| (c.kid, c.kvn));
    }

    /// The serialized record.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        tlv::encode_into(&mut out, tag::CPLC, &self.cplc);
        tlv::encode_into(&mut out, tag::REVISION, &[CONTENT_REVISION]);
        for set in &self.scp03 {
            let mut body = Vec::with_capacity(64);
            tlv::encode_into(&mut body, tag::F0, &[set.kvn]);
            tlv::encode_into(&mut body, tag::F1, &set.enc);
            tlv::encode_into(&mut body, tag::F2, &set.mac);
            tlv::encode_into(&mut body, tag::F3, &set.dek);
            tlv::encode_into(&mut body, tag::F4, &[set.tries]);
            tlv::encode_into(&mut out, tag::SCP03_SET, &body);
            scp03::wipe(&mut body);
        }
        for key in &self.ec_private {
            let mut body = Vec::with_capacity(48);
            tlv::encode_into(&mut body, tag::F0, &[key.kid]);
            tlv::encode_into(&mut body, tag::F1, &[key.kvn]);
            tlv::encode_into(&mut body, tag::F2, &[0x00]);
            tlv::encode_into(&mut body, tag::F3, &key.scalar);
            tlv::encode_into(&mut body, tag::F4, &[key.tries]);
            tlv::encode_into(&mut out, tag::EC_PRIVATE, &body);
            scp03::wipe(&mut body);
        }
        for key in &self.ec_public {
            let mut body = Vec::with_capacity(80);
            tlv::encode_into(&mut body, tag::F0, &[key.kid]);
            tlv::encode_into(&mut body, tag::F1, &[key.kvn]);
            tlv::encode_into(&mut body, tag::F2, &[0x00]);
            tlv::encode_into(&mut body, tag::F3, &key.point);
            tlv::encode_into(&mut body, tag::F4, &[key.tries]);
            tlv::encode_into(&mut out, tag::EC_PUBLIC, &body);
        }
        for store in &self.certs {
            let mut body = Vec::new();
            tlv::encode_into(&mut body, tag::F0, &[store.kid]);
            tlv::encode_into(&mut body, tag::F1, &[store.kvn]);
            for c in &store.certs {
                tlv::encode_into(&mut body, tag::F3, c);
            }
            tlv::encode_into(&mut out, tag::CERTIFICATES, &body);
        }
        for id in &self.ca_ids {
            let mut body = Vec::new();
            tlv::encode_into(&mut body, tag::F0, &[id.kid]);
            tlv::encode_into(&mut body, tag::F1, &[id.kvn]);
            tlv::encode_into(&mut body, tag::F3, &id.ski);
            tlv::encode_into(&mut out, tag::CA_IDENTIFIER, &body);
        }
        for list in &self.allowlists {
            let mut body = Vec::new();
            tlv::encode_into(&mut body, tag::F0, &[list.kid]);
            tlv::encode_into(&mut body, tag::F1, &[list.kvn]);
            for s in &list.serials {
                tlv::encode_into(&mut body, tag::F3, s);
            }
            tlv::encode_into(&mut out, tag::ALLOWLIST, &body);
        }
        for counter in &self.counters {
            let mut body = Vec::new();
            tlv::encode_into(&mut body, tag::F0, &[counter.kid]);
            tlv::encode_into(&mut body, tag::F1, &[counter.kvn]);
            tlv::encode_into(&mut body, tag::F4, &counter.value.to_be_bytes());
            tlv::encode_into(&mut out, tag::LIST_COUNTER, &body);
        }
        for raw in &self.extra {
            out.extend_from_slice(raw);
        }
        out
    }

    /// Parse a record; `None` if it is unreadable.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Parsed> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let items = tlv::parse_all(body).ok()?;
        let mut state = State::empty();
        let mut cplc_seen = false;
        let mut revision_seen = false;
        for item in &items {
            match item.tag {
                tag::CPLC => {
                    if cplc_seen {
                        return None;
                    }
                    state.cplc = item.value.try_into().ok()?;
                    cplc_seen = true;
                }
                tag::REVISION => {
                    if revision_seen || item.value.is_empty() {
                        return None;
                    }
                    revision_seen = true;
                }
                tag::SCP03_SET => state.scp03.push(parse_scp03_set(item.value)?),
                tag::EC_PRIVATE => state.ec_private.push(parse_ec_private(item.value)?),
                tag::EC_PUBLIC => state.ec_public.push(parse_ec_public(item.value)?),
                tag::CERTIFICATES => state.certs.push(parse_cert_store(item.value)?),
                tag::CA_IDENTIFIER => state.ca_ids.push(parse_ca_identifier(item.value)?),
                tag::ALLOWLIST => state.allowlists.push(parse_allowlist(item.value)?),
                tag::LIST_COUNTER => state.counters.push(parse_counter(item.value)?),
                _ => state.extra.push(item.raw.to_vec()),
            }
        }
        state.normalize();
        state.check_invariants().then_some(Parsed {
            state,
            missing_cplc: !cplc_seen,
            missing_revision: !revision_seen,
        })
    }

    /// Invariants every command maintains; a record breaking one is unreadable.
    fn check_invariants(&self) -> bool {
        // At most three sets, and the factory set never next to a custom one ("When a
        // new key set is installed, it replaces the default key set", Yubico yk5-apps-scp).
        let factory_with_custom = self.scp03.len() > 1 && self.scp03.iter().any(|s| s.kvn == FACTORY_KVN);
        let kvns_unique = self.scp03.windows(2).all(|w| w[0].kvn != w[1].kvn);
        let refs_unique = |refs: Vec<(u8, u8)>| refs.windows(2).all(|w| w[0] != w[1]);
        let ec_unique = refs_unique(self.ec_private.iter().map(|k| (k.kid, k.kvn)).collect())
            && refs_unique(self.ec_public.iter().map(|k| (k.kid, k.kvn)).collect());
        let meta_unique = refs_unique(self.certs.iter().map(|c| (c.kid, c.kvn)).collect())
            && refs_unique(self.ca_ids.iter().map(|c| (c.kid, c.kvn)).collect())
            && refs_unique(self.allowlists.iter().map(|a| (a.kid, a.kvn)).collect())
            && refs_unique(self.counters.iter().map(|c| (c.kid, c.kvn)).collect());
        // Metadata belongs to an existing key: certificates and CA identifiers to any EC
        // key, allowlists to a CA key.
        let attached = self.certs.iter().all(|c| self.ec_exists(c.kid, c.kvn))
            && self.ca_ids.iter().all(|c| self.ec_exists(c.kid, c.kvn))
            && self.allowlists.iter().all(|a| self.public_key(a.kid, a.kvn).is_some());
        // Every command keeps at least one key: removing the last one resets the domain
        // (Yubico yk5-apps-scp: "When the last key set is deleted, the security domain is
        // automatically reset"). A record without any key could never be authenticated to
        // nor reset, so it is unreadable and the domain starts from its factory state.
        self.has_any_key()
            && self.scp03.len() <= MAX_SCP03_SETS
            && !factory_with_custom
            && kvns_unique
            && ec_unique
            && meta_unique
            && attached
            && self.ec_rows() <= MAX_EC_ROWS
    }
}

/// The value of the single child with `tag`, if present exactly once.
fn field<'a>(children: &[tlv::Tlv<'a>], tag: u32) -> Option<&'a [u8]> {
    let mut found = children.iter().filter(|c| c.tag == tag);
    let first = found.next()?;
    found.next().is_none().then_some(first.value)
}

/// The values of every child with `tag`, in order.
fn fields<'a>(children: &[tlv::Tlv<'a>], tag: u32) -> Vec<&'a [u8]> {
    children.iter().filter(|c| c.tag == tag).map(|c| c.value).collect()
}

fn byte(value: &[u8]) -> Option<u8> {
    match value {
        [b] => Some(*b),
        _ => None,
    }
}

/// `80` KID and `81` KVN of a metadata template.
fn key_ref(children: &[tlv::Tlv<'_>]) -> Option<(u8, u8)> {
    Some((byte(field(children, tag::F0)?)?, byte(field(children, tag::F1)?)?))
}

fn parse_scp03_set(value: &[u8]) -> Option<Scp03Set> {
    let children = tlv::parse_all(value).ok()?;
    let kvn = byte(field(&children, tag::F0)?)?;
    let tries = byte(field(&children, tag::F4)?)?;
    if kvn == 0 || tries > AUTH_TRIES {
        return None;
    }
    Some(Scp03Set {
        kvn,
        enc: scp03::to_key(field(&children, tag::F1)?)?,
        mac: scp03::to_key(field(&children, tag::F2)?)?,
        dek: scp03::to_key(field(&children, tag::F3)?)?,
        tries,
    })
}

fn parse_ec_private(value: &[u8]) -> Option<EcPrivate> {
    let children = tlv::parse_all(value).ok()?;
    let (kid, kvn) = key_ref(&children)?;
    let curve = byte(field(&children, tag::F2)?)?;
    let scalar = field(&children, tag::F3)?;
    let tries = byte(field(&children, tag::F4)?)?;
    if !is_sd_kid(kid) || !is_scp11_kvn(kvn) || curve != 0x00 || tries > AUTH_TRIES {
        return None;
    }
    EcPrivateKey::from_scalar(Curve::P256, scalar).ok()?;
    Some(EcPrivate { kid, kvn, scalar: scalar.to_vec(), tries })
}

fn parse_ec_public(value: &[u8]) -> Option<EcPublic> {
    let children = tlv::parse_all(value).ok()?;
    let (kid, kvn) = key_ref(&children)?;
    let curve = byte(field(&children, tag::F2)?)?;
    let point = field(&children, tag::F3)?;
    let tries = byte(field(&children, tag::F4)?)?;
    if !is_ca_kid(kid) || !is_scp11_kvn(kvn) || curve != 0x00 || tries > AUTH_TRIES {
        return None;
    }
    if !lk_crypto::ec_public_is_valid(Curve::P256, point) {
        return None;
    }
    Some(EcPublic { kid, kvn, point: point.to_vec(), tries })
}

fn parse_cert_store(value: &[u8]) -> Option<CertStore> {
    let children = tlv::parse_all(value).ok()?;
    let (kid, kvn) = key_ref(&children)?;
    let certs: Vec<Vec<u8>> = fields(&children, tag::F3).into_iter().map(<[u8]>::to_vec).collect();
    if certs.is_empty() || certs.len() > MAX_CERTIFICATES || certs.iter().any(Vec::is_empty) {
        return None;
    }
    Some(CertStore { kid, kvn, certs })
}

fn parse_ca_identifier(value: &[u8]) -> Option<CaIdentifier> {
    let children = tlv::parse_all(value).ok()?;
    let (kid, kvn) = key_ref(&children)?;
    let ski = field(&children, tag::F3)?;
    if ski.is_empty() || ski.len() > MAX_SKI_LEN {
        return None;
    }
    Some(CaIdentifier { kid, kvn, ski: ski.to_vec() })
}

fn parse_allowlist(value: &[u8]) -> Option<Allowlist> {
    let children = tlv::parse_all(value).ok()?;
    let (kid, kvn) = key_ref(&children)?;
    let serials: Vec<Vec<u8>> = fields(&children, tag::F3).into_iter().map(<[u8]>::to_vec).collect();
    let canonical = |s: &Vec<u8>| !s.is_empty() && s.len() <= MAX_SERIAL_LEN && (s.len() == 1 || s[0] != 0);
    if serials.is_empty() || serials.len() > MAX_ALLOWLIST || !serials.iter().all(canonical) {
        return None;
    }
    Some(Allowlist { kid, kvn, serials })
}

fn parse_counter(value: &[u8]) -> Option<ListCounter> {
    let children = tlv::parse_all(value).ok()?;
    let (kid, kvn) = key_ref(&children)?;
    let raw: [u8; 2] = field(&children, tag::F4)?.try_into().ok()?;
    let value = u16::from_be_bytes(raw);
    if value == 0 || value > MAX_LIST_COUNTER {
        return None;
    }
    Some(ListCounter { kid, kvn, value })
}

/// A fresh CPLC (GP Card Specification v2.3.1 Annex H, `9F7F`, 42 bytes).
///
/// The catalog (SecurityDomain_metadata) fixes the layout: "software platform marker
/// 0000 and independent random identifier; physical 4090 silicon identity not
/// claimed". Here the IC fabricator (bytes 0-1) is `0000` and the IC serial number
/// (bytes 12-15) and IC batch identifier (bytes 16-17) are random; every other field is
/// zero. The same layout is used in both device profiles.
pub(crate) fn new_cplc(host: &mut dyn Host) -> [u8; CPLC_LEN] {
    let mut identifier = [0u8; 6];
    host.fill(&mut identifier);
    let mut cplc = [0u8; CPLC_LEN];
    if let Some(slot) = cplc.get_mut(12..18) {
        slot.copy_from_slice(&identifier);
    }
    cplc
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lk_testkit::TestHost;

    fn point(host: &mut TestHost) -> Vec<u8> {
        EcPrivateKey::generate(Curve::P256, host).public_uncompressed()
    }

    #[test]
    fn factory_state_round_trips() {
        let mut host = TestHost::new();
        let state = State::factory(&mut host);
        let bytes = state.serialize();
        assert_eq!(bytes[0], FORMAT_VERSION);
        let parsed = State::parse(&bytes).unwrap();
        assert!(!parsed.missing_cplc);
        assert!(!parsed.missing_revision);
        assert_eq!(parsed.state, state);
        assert_eq!(state.cert_store(KID_SCP11B, FACTORY_SCP11B_KVN).unwrap().certs.len(), 1);
    }

    #[test]
    fn full_state_round_trips() {
        let mut host = TestHost::new();
        let mut state = State::factory(&mut host);
        let p = point(&mut host);
        state.ec_public.push(EcPublic { kid: KID_OCE, kvn: 3, point: p, tries: 7 });
        state.ca_ids.push(CaIdentifier { kid: KID_OCE, kvn: 3, ski: vec![9; 20] });
        state.allowlists.push(Allowlist { kid: KID_OCE, kvn: 3, serials: vec![vec![1], vec![0x80, 0]] });
        state.certs.push(CertStore { kid: KID_OCE, kvn: 3, certs: vec![vec![0x30, 0x00], vec![0x30, 0x01, 0x00]] });
        state.counters.push(ListCounter { kid: 0x20, kvn: 9, value: 0x7FFF });
        state.normalize();
        let parsed = State::parse(&state.serialize()).unwrap();
        assert_eq!(parsed.state, state);
    }

    #[test]
    fn unknown_top_level_objects_are_kept_and_unknown_children_skipped() {
        let mut host = TestHost::new();
        let mut bytes = State::factory(&mut host).serialize();
        let extra = tlv::encode(0xBF20, &[1, 2, 3]);
        bytes.extend_from_slice(&extra);
        let parsed = State::parse(&bytes).unwrap();
        assert_eq!(parsed.state.extra, vec![extra.clone()]);
        assert!(parsed.state.serialize().ends_with(&extra));

        let mut set = Vec::new();
        tlv::encode_into(&mut set, 0x80, &[0x05]);
        tlv::encode_into(&mut set, 0x81, &[0x11; 16]);
        tlv::encode_into(&mut set, 0x82, &[0x22; 16]);
        tlv::encode_into(&mut set, 0x83, &[0x33; 16]);
        tlv::encode_into(&mut set, 0x84, &[0x07]);
        tlv::encode_into(&mut set, 0x85, &[0xEE]);
        let mut record = vec![FORMAT_VERSION];
        tlv::encode_into(&mut record, 0xA1, &set);
        let parsed = State::parse(&record).unwrap();
        assert!(parsed.missing_cplc);
        assert!(parsed.missing_revision);
        assert_eq!(parsed.state.scp03.len(), 1);
        assert_eq!(parsed.state.scp03[0].kvn, 5);
        assert_eq!(parsed.state.scp03[0].tries, 7);
    }

    #[test]
    fn invariant_violations_are_unreadable() {
        let mut host = TestHost::new();
        let good = State::factory(&mut host);
        // Wrong version.
        let mut bytes = good.serialize();
        bytes[0] = 0x02;
        assert!(State::parse(&bytes).is_none());
        // Truncated TLV.
        let bytes = good.serialize();
        assert!(State::parse(&bytes[..bytes.len() - 1]).is_none());
        // Duplicate KVN.
        let mut dup = good.clone();
        dup.scp03.push(dup.scp03[0].clone());
        assert!(State::parse(&dup.serialize()).is_none());
        // Too many custom sets.
        let mut many = good.clone();
        many.scp03 = (1..=4)
            .map(|kvn| Scp03Set { kvn, enc: [1; 16], mac: [2; 16], dek: [3; 16], tries: 1 })
            .collect();
        assert!(State::parse(&many.serialize()).is_none());
        // The factory set next to a custom set.
        let mut mixed = good.clone();
        mixed.scp03.push(Scp03Set { kvn: 1, enc: [1; 16], mac: [2; 16], dek: [3; 16], tries: 1 });
        assert!(State::parse(&mixed.serialize()).is_none());
        // Three custom sets are fine.
        let mut three = good.clone();
        three.scp03 = (1..=3)
            .map(|kvn| Scp03Set { kvn, enc: [1; 16], mac: [2; 16], dek: [3; 16], tries: 1 })
            .collect();
        assert!(State::parse(&three.serialize()).is_some());
        // Tries above the maximum.
        let mut tries = good.clone();
        tries.scp03[0].tries = AUTH_TRIES + 1;
        assert!(State::parse(&tries.serialize()).is_none());
        // Invalid scalar.
        let mut scalar = good.clone();
        scalar.ec_private[0].scalar = vec![0; 32];
        assert!(State::parse(&scalar.serialize()).is_none());
        // Empty record.
        assert!(State::parse(&[]).is_none());
        // Invalid CA point, wrong CA KID, SCP11 KVN 128.
        let p = point(&mut host);
        let mut bad_point = good.clone();
        bad_point.ec_public.push(EcPublic { kid: KID_OCE, kvn: 1, point: vec![4; 65], tries: 1 });
        assert!(State::parse(&bad_point.serialize()).is_none());
        let mut bad_kid = good.clone();
        bad_kid.ec_public.push(EcPublic { kid: 0x13, kvn: 1, point: p.clone(), tries: 1 });
        assert!(State::parse(&bad_kid.serialize()).is_none());
        let mut bad_kvn = good.clone();
        bad_kvn.ec_public.push(EcPublic { kid: KID_OCE, kvn: 0x80, point: p.clone(), tries: 1 });
        assert!(State::parse(&bad_kvn.serialize()).is_none());
        // More than sixteen EC rows.
        let mut rows = good.clone();
        rows.ec_public = (1..=16).map(|kvn| EcPublic { kid: KID_OCE, kvn, point: p.clone(), tries: 1 }).collect();
        assert!(State::parse(&rows.serialize()).is_none());
        rows.ec_public.pop();
        assert!(State::parse(&rows.serialize()).is_some());
        // Metadata of a missing key; an allowlist on a private key.
        let mut orphan = good.clone();
        orphan.ca_ids.push(CaIdentifier { kid: KID_OCE, kvn: 9, ski: vec![1] });
        assert!(State::parse(&orphan.serialize()).is_none());
        let mut private_list = good.clone();
        private_list.allowlists.push(Allowlist { kid: KID_SCP11B, kvn: 1, serials: vec![vec![1]] });
        assert!(State::parse(&private_list.serialize()).is_none());
        // Non-canonical serial, zero counter.
        let mut serial = good.clone();
        serial.ec_public.push(EcPublic { kid: KID_OCE, kvn: 1, point: p, tries: 1 });
        serial.allowlists.push(Allowlist { kid: KID_OCE, kvn: 1, serials: vec![vec![0, 1]] });
        assert!(State::parse(&serial.serialize()).is_none());
        let mut counter = good.clone();
        counter.counters.push(ListCounter { kid: KID_OCE, kvn: 1, value: 0 });
        assert!(State::parse(&counter.serialize()).is_none());
        // No key of any kind (only reachable by tampering): unreadable.
        let mut keyless = good.clone();
        keyless.scp03.clear();
        keyless.ec_private.clear();
        keyless.certs.clear();
        assert!(State::parse(&keyless.serialize()).is_none());
        // One CA key alone is a key (the blocking reset may leave such a state).
        keyless.ec_public.push(EcPublic { kid: KID_OCE, kvn: 1, point: point(&mut host), tries: 1 });
        assert!(State::parse(&keyless.serialize()).is_some());
    }

    #[test]
    fn cplc_layout() {
        let mut host = TestHost::new();
        host.push_entropy(&[1, 2, 3, 4, 5, 6]);
        let cplc = new_cplc(&mut host);
        assert_eq!(&cplc[..2], &[0, 0]);
        assert_eq!(&cplc[12..18], &[1, 2, 3, 4, 5, 6]);
        assert!(cplc[18..].iter().all(|&b| b == 0));
    }
}
