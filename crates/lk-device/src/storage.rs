//! Sealing of application records with AES-256-GCM before they reach the host `Store`.
//!
//! Format (`docs/CONTRACTS.md`, lk-device; `docs/DESIGN.md` §7):
//!
//! ```text
//! sealed = version (1, = 0x01) || nonce (12) || ciphertext || tag (16)
//! AAD    = b"localkey" || record id (1) || version (1)
//! ```
//!
//! AES-256-GCM is NIST SP 800-38D with a 96-bit nonce drawn from host entropy for every
//! seal. Binding the record id into the AAD means bytes sealed for one record never open
//! as another, and binding the version means a future format cannot be confused with this
//! one. The store only ever sees sealed bytes.

use core::fmt;

use lk_core::{Entropy, Record};

/// The sealed-record format version, the first byte of every sealed record.
pub const FORMAT_VERSION: u8 = 0x01;

/// AES-GCM nonce length (SP 800-38D §5.2.1.1, the recommended 96-bit IV).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length (SP 800-38D §5.2.1.2, the full 128-bit tag).
pub const TAG_LEN: usize = 16;

/// Bytes a sealed record adds to its plaintext.
pub const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// Prefix of the additional authenticated data.
const AAD_LABEL: &[u8] = b"localkey";

/// Why a sealed record could not be opened. The caller treats every case as unreadable
/// state, which the application loads as factory state (`docs/CONTRACTS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The first byte names a format this engine does not know.
    UnsupportedVersion(u8),
    /// Too short to hold the version, nonce and tag.
    Truncated,
    /// The tag did not verify: wrong key, wrong record, or modified bytes.
    AuthenticationFailed,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(f, "unsupported sealed record version {version:#04x}"),
            Self::Truncated => f.write_str("sealed record is truncated"),
            Self::AuthenticationFailed => f.write_str("sealed record failed authentication"),
        }
    }
}

impl std::error::Error for SealError {}

/// The stable on-disk id of each record. These values are part of the sealed format
/// (they enter the AAD) and must never be renumbered.
pub fn record_id(record: Record) -> u8 {
    match record {
        Record::Device => 1,
        Record::Fido => 2,
        Record::Oath => 3,
        Record::Otp => 4,
        Record::Piv => 5,
        Record::OpenPgp => 6,
        Record::HsmAuth => 7,
        Record::SecurityDomain => 8,
    }
}

/// `b"localkey" || record id || version`. `open` passes the version byte it read from the
/// header (after checking it), so the AAD authenticates exactly the header that was stored.
fn aad(record: Record, version: u8) -> [u8; AAD_LABEL.len() + 2] {
    let mut aad = [0; AAD_LABEL.len() + 2];
    aad[..AAD_LABEL.len()].copy_from_slice(AAD_LABEL);
    aad[AAD_LABEL.len()] = record_id(record);
    aad[AAD_LABEL.len() + 1] = version;
    aad
}

/// Seal `plaintext` for `record` under `key` with a fresh nonce from `entropy`.
///
/// Every call draws exactly [`NONCE_LEN`] bytes from `entropy` for the nonce, so a device
/// that keeps one advancing entropy source does not reuse a nonce under its key
/// (SP 800-38D §8.2.2, RBG-based construction; §8.3 allows 2^32 such seals per key, far
/// beyond any device's write count).
///
/// # Panics
///
/// Only if `plaintext` is longer than AES-GCM's limit of 2^36 - 32 bytes
/// (SP 800-38D §5.2.1.1), which no application record approaches. The contract fixes the
/// infallible signature (`docs/CONTRACTS.md` "Phase 0 as implemented", lk-device::storage).
pub fn seal(key: &[u8; 32], record: Record, plaintext: &[u8], entropy: &mut dyn Entropy) -> Vec<u8> {
    let mut nonce = [0; NONCE_LEN];
    entropy.fill(&mut nonce);
    // `aes_gcm_seal` fails only for a key that is not 32 bytes, a nonce that is not 12
    // bytes, or a plaintext over 2^36 - 32 bytes (SP 800-38D §5.2.1.1). The types rule
    // out the first two and no record comes near the third.
    let ciphertext = lk_crypto::aes_gcm_seal(key, &nonce, &aad(record, FORMAT_VERSION), plaintext)
        .expect("AES-256-GCM accepts a 32-byte key, a 12-byte nonce and any record-sized plaintext");
    let mut sealed = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    sealed.push(FORMAT_VERSION);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed
}

/// Open bytes produced by [`seal`] for the same `key` and `record`.
///
/// Checks run in this order, and never panic whatever the input:
/// 1. no bytes at all: [`SealError::Truncated`];
/// 2. a first byte other than [`FORMAT_VERSION`]: [`SealError::UnsupportedVersion`], decided
///    before any decryption is attempted;
/// 3. fewer than [`OVERHEAD`] bytes: [`SealError::Truncated`];
/// 4. any GCM tag failure (wrong key, wrong record, modified bytes):
///    [`SealError::AuthenticationFailed`].
pub fn open(key: &[u8; 32], record: Record, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    let (&version, rest) = sealed.split_first().ok_or(SealError::Truncated)?;
    if version != FORMAT_VERSION {
        return Err(SealError::UnsupportedVersion(version));
    }
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(SealError::Truncated);
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    lk_crypto::aes_gcm_open(key, nonce, &aad(record, version), ciphertext).map_err(|_| SealError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use lk_core::Host;
    use lk_testkit::{ScriptedEntropy, SeededEntropy, TestHost};

    const ALL: [Record; 8] = [
        Record::Device,
        Record::Fido,
        Record::Oath,
        Record::Otp,
        Record::Piv,
        Record::OpenPgp,
        Record::HsmAuth,
        Record::SecurityDomain,
    ];

    const KEY: [u8; 32] = [0x42; 32];

    fn sample(record: Record) -> Vec<u8> {
        // A versioned state blob as an application would persist it, distinct per record.
        let mut plaintext = vec![0x01, record_id(record)];
        plaintext.extend((0u8..40).map(|i| i.wrapping_mul(7)));
        plaintext
    }

    /// Strict hex decoding for test vectors: a typo fails loudly instead of dropping a byte.
    fn hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "odd-length hex vector");
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit")).collect()
    }

    /// A value in `0..bound` from a fixed-seed fuzz stream (modulo bias is irrelevant here).
    fn below(fuzz: &mut SeededEntropy, bound: usize) -> usize {
        let mut bytes = [0u8; 4];
        fuzz.fill(&mut bytes);
        u32::from_be_bytes(bytes) as usize % bound
    }

    /// The only error `open` may give for bytes that are not a genuine seal, decided by the
    /// documented check order (empty, version, length, then GCM).
    fn expected_rejection(bytes: &[u8]) -> SealError {
        match bytes.first() {
            None => SealError::Truncated,
            Some(&version) if version != FORMAT_VERSION => SealError::UnsupportedVersion(version),
            Some(_) if bytes.len() < OVERHEAD => SealError::Truncated,
            Some(_) => SealError::AuthenticationFailed,
        }
    }

    /// `header || nonce || AES-256-GCM(key, nonce, aad, plaintext)`, built directly with
    /// lk_crypto so a test can choose the header and AAD independently of `seal`.
    fn craft(key: &[u8; 32], header: u8, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut sealed = vec![header];
        sealed.extend_from_slice(nonce);
        sealed.extend(lk_crypto::aes_gcm_seal(key, nonce, aad, plaintext).expect("valid GCM inputs"));
        sealed
    }

    /// Format vectors computed independently with Python `cryptography` 46.0.7:
    ///
    /// ```text
    /// key = bytes(range(32)); nonce = bytes(range(0xa0, 0xac))
    /// aad = b"localkey" + bytes([record_id, 0x01])
    /// sealed = b"\x01" + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    /// ```
    ///
    /// They pin the byte order of the layout and the AAD, which round-trip tests cannot.
    #[test]
    fn matches_independent_format_vectors() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = core::array::from_fn(|i| 0xa0 + i as u8);
        let vectors: [(Record, &[u8], &str); 2] = [
            (
                Record::Oath,
                b"\x01localkey sealed record",
                "01a0a1a2a3a4a5a6a7a8a9aaabe774134e24a769da1b45f4b66616a5ba50de3c73fdc526b21d936260ed9ed0658dd6f1f1ed58ad",
            ),
            (Record::Device, b"", "01a0a1a2a3a4a5a6a7a8a9aaabade018dd53c24fda2b8095f0ca718e97"),
        ];
        for (record, plaintext, expected) in vectors {
            let mut entropy = ScriptedEntropy::new(0, [nonce]);
            let sealed = seal(&key, record, plaintext, &mut entropy);
            assert_eq!(sealed, hex(expected), "{record:?}");
            assert_eq!(open(&key, record, &sealed), Ok(plaintext.to_vec()), "{record:?}");
        }
    }

    #[test]
    fn record_ids_are_stable_and_distinct() {
        // docs/CONTRACTS.md (lk-device) and the task contract fix these values.
        let ids: Vec<u8> = ALL.into_iter().map(record_id).collect();
        assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn layout_is_version_nonce_ciphertext_tag() {
        let nonce = [0x5c; NONCE_LEN];
        let mut entropy = ScriptedEntropy::new(0, [nonce]);
        let plaintext = sample(Record::Piv);
        let sealed = seal(&KEY, Record::Piv, &plaintext, &mut entropy);
        assert_eq!(sealed.len(), plaintext.len() + OVERHEAD);
        assert_eq!(sealed[0], FORMAT_VERSION);
        assert_eq!(sealed[1..1 + NONCE_LEN], nonce);
        // The remainder is exactly the AES-256-GCM output for the documented AAD.
        let aad = [b"localkey".as_slice(), &[5, 0x01]].concat();
        let expected = lk_crypto::aes_gcm_seal(&KEY, &nonce, &aad, &plaintext);
        assert_eq!(Ok(sealed[1 + NONCE_LEN..].to_vec()), expected);
    }

    #[test]
    fn round_trips_every_record() {
        let mut entropy = SeededEntropy::new(1);
        for record in ALL {
            for plaintext in [Vec::new(), vec![0x01], sample(record), vec![0xa5; 4096]] {
                let sealed = seal(&KEY, record, &plaintext, &mut entropy);
                assert_eq!(sealed.len(), plaintext.len() + OVERHEAD);
                assert_eq!(open(&KEY, record, &sealed), Ok(plaintext), "{record:?}");
            }
        }
    }

    #[test]
    fn tampering_with_any_single_byte_fails() {
        let mut entropy = SeededEntropy::new(2);
        let sealed = seal(&KEY, Record::Fido, &sample(Record::Fido), &mut entropy);
        for position in 0..sealed.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut tampered = sealed.clone();
                tampered[position] ^= flip;
                let expected = if position == 0 {
                    SealError::UnsupportedVersion(FORMAT_VERSION ^ flip)
                } else {
                    SealError::AuthenticationFailed
                };
                assert_eq!(open(&KEY, Record::Fido, &tampered), Err(expected), "byte {position} ^ {flip:#04x}");
            }
        }
    }

    #[test]
    fn appended_bytes_fail() {
        let mut entropy = SeededEntropy::new(3);
        let mut sealed = seal(&KEY, Record::Otp, &sample(Record::Otp), &mut entropy);
        sealed.push(0x00);
        assert_eq!(open(&KEY, Record::Otp, &sealed), Err(SealError::AuthenticationFailed));
    }

    #[test]
    fn opening_as_another_record_fails() {
        let mut entropy = SeededEntropy::new(4);
        for sealed_as in ALL {
            let sealed = seal(&KEY, sealed_as, &sample(sealed_as), &mut entropy);
            for opened_as in ALL.into_iter().filter(|&r| r != sealed_as) {
                assert_eq!(
                    open(&KEY, opened_as, &sealed),
                    Err(SealError::AuthenticationFailed),
                    "{sealed_as:?} opened as {opened_as:?}"
                );
            }
        }
    }

    #[test]
    fn wrong_key_fails() {
        let mut entropy = SeededEntropy::new(5);
        let sealed = seal(&KEY, Record::OpenPgp, &sample(Record::OpenPgp), &mut entropy);
        for position in [0, 15, 31] {
            let mut other = KEY;
            other[position] ^= 0x01;
            assert_eq!(open(&other, Record::OpenPgp, &sealed), Err(SealError::AuthenticationFailed));
        }
        assert_eq!(open(&[0; 32], Record::OpenPgp, &sealed), Err(SealError::AuthenticationFailed));
    }

    #[test]
    fn every_truncation_fails() {
        let mut entropy = SeededEntropy::new(6);
        let sealed = seal(&KEY, Record::HsmAuth, &sample(Record::HsmAuth), &mut entropy);
        for len in 0..sealed.len() {
            let expected = if len < OVERHEAD { SealError::Truncated } else { SealError::AuthenticationFailed };
            assert_eq!(open(&KEY, Record::HsmAuth, &sealed[..len]), Err(expected), "prefix of {len} bytes");
        }
    }

    #[test]
    fn unknown_versions_are_rejected_before_length_checks() {
        for version in [0x00, 0x02, 0xff] {
            assert_eq!(open(&KEY, Record::Device, &[version]), Err(SealError::UnsupportedVersion(version)));
        }
    }

    #[test]
    fn each_seal_draws_a_fresh_nonce() {
        // One advancing entropy source, as the device holds: the same plaintext sealed
        // twice must not reuse a nonce (SP 800-38D §8: IV uniqueness).
        let mut entropy = SeededEntropy::new(7);
        let plaintext = sample(Record::SecurityDomain);
        let seals: Vec<Vec<u8>> =
            (0..16).map(|_| seal(&KEY, Record::SecurityDomain, &plaintext, &mut entropy)).collect();
        for (i, a) in seals.iter().enumerate() {
            for b in &seals[i + 1..] {
                assert_ne!(a[1..1 + NONCE_LEN], b[1..1 + NONCE_LEN]);
                assert_ne!(a, b);
            }
            assert_eq!(open(&KEY, Record::SecurityDomain, a), Ok(plaintext.clone()));
        }
    }

    #[test]
    fn nonce_comes_from_entropy() {
        let mut entropy = SeededEntropy::new(8);
        let sealed = seal(&KEY, Record::Device, b"x", &mut entropy);
        assert_eq!(sealed[1..1 + NONCE_LEN], SeededEntropy::new(8).bytes(NONCE_LEN)[..]);
    }

    #[test]
    fn aad_binds_label_record_and_version() {
        // docs/CONTRACTS.md (lk-device): AAD = b"localkey" || record id || format version.
        // A ciphertext made under any other AAD, even with a valid header, must not open.
        let nonce = [0x24; NONCE_LEN];
        let plaintext = sample(Record::Oath);
        let id = record_id(Record::Oath);
        let documented = [b"localkey".as_slice(), &[id, FORMAT_VERSION]].concat();
        assert_eq!(
            open(&KEY, Record::Oath, &craft(&KEY, FORMAT_VERSION, &nonce, &documented, &plaintext)),
            Ok(plaintext.clone())
        );

        let wrong: Vec<(&str, Vec<u8>)> = vec![
            ("version 0x00 in AAD", [b"localkey".as_slice(), &[id, 0x00]].concat()),
            ("version 0x02 in AAD", [b"localkey".as_slice(), &[id, 0x02]].concat()),
            ("version 0xff in AAD", [b"localkey".as_slice(), &[id, 0xff]].concat()),
            ("version missing", [b"localkey".as_slice(), &[id]].concat()),
            ("record id missing", [b"localkey".as_slice(), &[FORMAT_VERSION]].concat()),
            ("id and version swapped", [b"localkey".as_slice(), &[FORMAT_VERSION, id]].concat()),
            ("zero-based record id", [b"localkey".as_slice(), &[id - 1, FORMAT_VERSION]].concat()),
            ("label only", b"localkey".to_vec()),
            ("empty AAD", Vec::new()),
            ("label case", [b"localkeY".as_slice(), &[id, FORMAT_VERSION]].concat()),
            ("label NUL-terminated", [b"localkey\0".as_slice(), &[id, FORMAT_VERSION]].concat()),
            ("no label", vec![id, FORMAT_VERSION]),
            ("trailing byte", [documented.as_slice(), &[0x00]].concat()),
        ];
        for (what, aad) in wrong {
            let sealed = craft(&KEY, FORMAT_VERSION, &nonce, &aad, &plaintext);
            assert_eq!(open(&KEY, Record::Oath, &sealed), Err(SealError::AuthenticationFailed), "{what}");
        }
    }

    #[test]
    fn version_is_checked_before_decryption() {
        // A well-formed record of a hypothetical format 0x02 (header and AAD both 0x02)
        // that would authenticate under the right key is still refused, by version alone.
        let nonce = [0x33; NONCE_LEN];
        let aad_v2 = [b"localkey".as_slice(), &[record_id(Record::Piv), 0x02]].concat();
        let future = craft(&KEY, 0x02, &nonce, &aad_v2, b"format 2 state");
        assert_eq!(open(&KEY, Record::Piv, &future), Err(SealError::UnsupportedVersion(0x02)));
        // The verdict is the same under a wrong key and a wrong record: it is reached
        // without consulting the GCM tag.
        assert_eq!(open(&[0; 32], Record::Fido, &future), Err(SealError::UnsupportedVersion(0x02)));

        // A genuine v1 record whose header byte alone is changed reports the version, not an
        // authentication failure, whatever the key.
        let mut entropy = SeededEntropy::new(12);
        let mut sealed = seal(&KEY, Record::Piv, &sample(Record::Piv), &mut entropy);
        sealed[0] = 0x02;
        for key in [KEY, [0; 32]] {
            assert_eq!(open(&key, Record::Piv, &sealed), Err(SealError::UnsupportedVersion(0x02)));
        }
    }

    #[test]
    fn arbitrary_bytes_never_open_and_never_panic() {
        // Fixed-seed fuzz: 10,000 inputs of 0..=96 bytes. Three in four start with the
        // current version byte so most of them reach the length and GCM checks.
        let mut fuzz = SeededEntropy::new(0xf022);
        for case in 0..10_000 {
            let len = below(&mut fuzz, 97);
            let mut input = fuzz.bytes(len);
            if len > 0 && below(&mut fuzz, 4) != 0 {
                input[0] = FORMAT_VERSION;
            }
            let record = ALL[below(&mut fuzz, ALL.len())];
            let mut key = KEY;
            if below(&mut fuzz, 2) == 0 {
                fuzz.fill(&mut key);
            }
            assert_eq!(open(&key, record, &input), Err(expected_rejection(&input)), "case {case}");
        }
    }

    #[test]
    fn mutated_seals_never_open() {
        // Fixed-seed fuzz over genuine seals: XOR 1-4 random bytes with non-zero masks,
        // truncate to a random length, or append 1-16 random bytes.
        let mut fuzz = SeededEntropy::new(0x5ea1);
        let mut checked = 0;
        for case in 0..3_000 {
            let record = ALL[below(&mut fuzz, ALL.len())];
            let plaintext_len = below(&mut fuzz, 64);
            let plaintext = fuzz.bytes(plaintext_len);
            let sealed = seal(&KEY, record, &plaintext, &mut fuzz);
            let mut mutated = sealed.clone();
            match below(&mut fuzz, 3) {
                0 => {
                    for _ in 0..=below(&mut fuzz, 4) {
                        let position = below(&mut fuzz, mutated.len());
                        mutated[position] ^= 1 + below(&mut fuzz, 255) as u8;
                    }
                }
                1 => mutated.truncate(below(&mut fuzz, sealed.len())),
                _ => {
                    let extra = 1 + below(&mut fuzz, 16);
                    mutated.extend(fuzz.bytes(extra));
                }
            }
            if mutated == sealed {
                // Two masks at one position cancelled out; nothing was modified.
                continue;
            }
            assert_eq!(open(&KEY, record, &mutated), Err(expected_rejection(&mutated)), "case {case}");
            checked += 1;
        }
        assert!(checked > 2_900, "only {checked} cases exercised");
    }

    #[test]
    fn random_records_round_trip() {
        // Fixed-seed fuzz: random keys, records and plaintexts of 0..512 bytes.
        let mut fuzz = SeededEntropy::new(0x7007);
        for case in 0..500 {
            let mut key = [0u8; 32];
            fuzz.fill(&mut key);
            let record = ALL[below(&mut fuzz, ALL.len())];
            let len = below(&mut fuzz, 512);
            let plaintext = fuzz.bytes(len);
            let sealed = seal(&key, record, &plaintext, &mut fuzz);
            assert_eq!(sealed.len(), len + OVERHEAD, "case {case}");
            assert_eq!(open(&key, record, &sealed), Ok(plaintext), "case {case}");
        }
    }

    #[test]
    fn nonces_never_repeat_over_many_seals() {
        // SP 800-38D §8: a (key, IV) pair must never repeat. 4,096 seals of the same
        // plaintext for the same record from one advancing entropy source.
        let mut entropy = SeededEntropy::new(13);
        let mut nonces = BTreeSet::new();
        let mut seals = BTreeSet::new();
        for _ in 0..4_096 {
            let sealed = seal(&KEY, Record::Device, b"same state", &mut entropy);
            assert!(nonces.insert(sealed[1..1 + NONCE_LEN].to_vec()), "nonce reused");
            assert!(seals.insert(sealed), "identical sealed bytes");
        }
    }

    #[test]
    fn each_seal_consumes_exactly_one_nonce_from_the_stream() {
        // Seal i's nonce is stream bytes 12i..12i+12: nothing is skipped or drawn twice, so
        // sealing stays reproducible and consecutive seals never share nonce bytes.
        let stream = SeededEntropy::new(14).bytes(NONCE_LEN * 32);
        let mut entropy = SeededEntropy::new(14);
        for (i, expected) in stream.chunks(NONCE_LEN).enumerate() {
            let sealed = seal(&KEY, ALL[i % ALL.len()], &[i as u8; 3], &mut entropy);
            assert_eq!(&sealed[1..1 + NONCE_LEN], expected, "seal {i}");
        }
    }

    #[test]
    fn seals_with_a_test_host_as_the_entropy_source() {
        // The device passes its host entropy as `&mut dyn Entropy`; a `TestHost` works the
        // same way and its persist path draws no entropy.
        let mut host = TestHost::new();
        let first = seal(&KEY, Record::Oath, b"one", &mut host);
        assert_eq!(host.persist(Record::Oath, &first), Ok(()));
        let second = seal(&KEY, Record::Oath, b"one", &mut host);
        let stream = SeededEntropy::new(TestHost::DEFAULT_SEED).bytes(2 * NONCE_LEN);
        assert_eq!(first[1..1 + NONCE_LEN], stream[..NONCE_LEN]);
        assert_eq!(second[1..1 + NONCE_LEN], stream[NONCE_LEN..]);
        assert_eq!(open(&KEY, Record::Oath, &second), Ok(b"one".to_vec()));
    }

    #[test]
    fn errors_display_their_cause() {
        assert_eq!(SealError::UnsupportedVersion(2).to_string(), "unsupported sealed record version 0x02");
        assert_eq!(SealError::Truncated.to_string(), "sealed record is truncated");
        assert_eq!(SealError::AuthenticationFailed.to_string(), "sealed record failed authentication");
    }
}
