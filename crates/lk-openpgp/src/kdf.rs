//! KDF-DO F9 (OpenPGP card 3.4.1 §4.3.2) and the iterated-salted S2K it names
//! (RFC 4880 §3.7.1.3).
//!
//! With a KDF-DO the host derives each password before sending it, and the card stores
//! and compares only the derived value. Writing F9 resets PW1 and PW3 to their initial
//! values and removes the resetting code (spec §4.3.2, and Yubico's documented behaviour
//! of `set_kdf`): with `KDF_NONE` these are `123456` / `12345678`; with
//! `KDF_ITERSALTED_S2K` they are the initial hashes 87 / 88 when the host supplies them,
//! otherwise the card derives them itself from the default PINs.
//!
//! Layout of the DO contents (spec §4.3.2 table; GET/PUT DATA F9 carry the contents
//! without the F9 tag, as GnuPG and YubiKit read them):
//!
//! | Tag | Length | Meaning |
//! | --- | --- | --- |
//! | 81 | 1 | algorithm: 00 none, 03 iterated-salted S2K |
//! | 82 | 1 | hash: 08 SHA-256, 0A SHA-512 |
//! | 83 | 4 | iteration count in bytes hashed |
//! | 84 | 8 | salt for PW1 |
//! | 85 | 8 | salt for the resetting code (optional) |
//! | 86 | 8 | salt for PW3 (optional; PW1's salt is used when absent) |
//! | 87 | hash | initial PW1 hash (optional) |
//! | 88 | hash | initial PW3 hash (optional) |

use lk_codec::apdu::sw;
use lk_codec::tlv;
use lk_crypto::HashAlg;

use crate::objects::MAX_SPECIAL_DO;
use crate::state::{DEFAULT_PW1, DEFAULT_PW3};

/// The factory KDF-DO: `81 01 00` (KDF_NONE).
pub(crate) const KDF_NONE: [u8; 3] = [0x81, 0x01, 0x00];

const ALG_NONE: u8 = 0x00;
const ALG_ITERSALTED_S2K: u8 = 0x03;
const HASH_SHA256: u8 = 0x08;
const HASH_SHA512: u8 = 0x0A;
const SALT_LEN: usize = 8;

/// The largest count the card derives itself: the largest count an RFC 4880 §3.7.1.3
/// coded count can express, `(16 + 15) << (15 + 6)` = 65 011 712 bytes. lk-crypto only
/// offers one-shot digests, so the derivation buffers `count` bytes; this bound keeps that
/// buffer finite. A KDF-DO with a larger count is accepted when it carries both initial
/// hashes (nothing is derived on the card).
pub(crate) const MAX_ON_CARD_COUNT: u32 = 65_011_712;

/// A parsed KDF-DO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kdf {
    None,
    IterSaltedS2k(S2k),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S2k {
    pub hash: HashAlg,
    pub count: u32,
    pub salt_pw1: Vec<u8>,
    pub salt_rc: Option<Vec<u8>>,
    pub salt_pw3: Option<Vec<u8>>,
    pub initial_pw1: Option<Vec<u8>>,
    pub initial_pw3: Option<Vec<u8>>,
}

impl Kdf {
    /// Validate and parse F9 contents. Errors are status words: wrong overall length is
    /// `6700`, any malformed or unsupported field `6A80`.
    pub(crate) fn parse(data: &[u8]) -> Result<Kdf, u16> {
        if data.len() > MAX_SPECIAL_DO {
            return Err(sw::WRONG_LENGTH);
        }
        let fields = tlv::parse_all(data).map_err(|_| sw::INCORRECT_DATA)?;
        let mut seen: Vec<u32> = Vec::new();
        for field in &fields {
            if !(0x81..=0x88).contains(&field.tag) || seen.contains(&field.tag) {
                return Err(sw::INCORRECT_DATA);
            }
            seen.push(field.tag);
        }
        let get = |tag: u32| tlv::find(&fields, tag).map(|f| f.value);
        let algorithm = match get(0x81) {
            Some([alg]) => *alg,
            _ => return Err(sw::INCORRECT_DATA),
        };
        match algorithm {
            ALG_NONE => Ok(Kdf::None),
            ALG_ITERSALTED_S2K => {
                let hash = match get(0x82) {
                    Some([HASH_SHA256]) => HashAlg::Sha256,
                    Some([HASH_SHA512]) => HashAlg::Sha512,
                    _ => return Err(sw::INCORRECT_DATA),
                };
                let count = match get(0x83) {
                    Some(&[a, b, c, d]) => u32::from_be_bytes([a, b, c, d]),
                    _ => return Err(sw::INCORRECT_DATA),
                };
                if count == 0 {
                    return Err(sw::INCORRECT_DATA);
                }
                let salt = |tag: u32| -> Result<Option<Vec<u8>>, u16> {
                    match get(tag) {
                        None => Ok(None),
                        Some(v) if v.len() == SALT_LEN => Ok(Some(v.to_vec())),
                        Some(_) => Err(sw::INCORRECT_DATA),
                    }
                };
                let initial = |tag: u32| -> Result<Option<Vec<u8>>, u16> {
                    match get(tag) {
                        None => Ok(None),
                        Some(v) if v.len() == hash.output_len() => Ok(Some(v.to_vec())),
                        Some(_) => Err(sw::INCORRECT_DATA),
                    }
                };
                let salt_pw1 = salt(0x84)?.ok_or(sw::INCORRECT_DATA)?;
                Ok(Kdf::IterSaltedS2k(S2k {
                    hash,
                    count,
                    salt_pw1,
                    salt_rc: salt(0x85)?,
                    salt_pw3: salt(0x86)?,
                    initial_pw1: initial(0x87)?,
                    initial_pw3: initial(0x88)?,
                }))
            }
            _ => Err(sw::INCORRECT_DATA),
        }
    }

    /// Length of a derived password while this KDF is active.
    pub(crate) fn hash_len(&self) -> Option<usize> {
        match self {
            Kdf::None => None,
            Kdf::IterSaltedS2k(s2k) => Some(s2k.hash.output_len()),
        }
    }

    /// The PW1 and PW3 references installed when this KDF-DO is written.
    pub(crate) fn initial_references(&self) -> Result<(Vec<u8>, Vec<u8>), u16> {
        match self {
            Kdf::None => Ok((DEFAULT_PW1.to_vec(), DEFAULT_PW3.to_vec())),
            Kdf::IterSaltedS2k(s2k) => {
                let derive = |pin: &[u8], salt: &[u8]| -> Result<Vec<u8>, u16> {
                    if s2k.count > MAX_ON_CARD_COUNT {
                        return Err(sw::INCORRECT_DATA);
                    }
                    Ok(iterated_salted_s2k(s2k.hash, salt, pin, s2k.count as usize))
                };
                let pw1 = match &s2k.initial_pw1 {
                    Some(hash) => hash.clone(),
                    None => derive(DEFAULT_PW1, &s2k.salt_pw1)?,
                };
                let pw3_salt = s2k.salt_pw3.as_deref().unwrap_or(&s2k.salt_pw1);
                let pw3 = match &s2k.initial_pw3 {
                    Some(hash) => hash.clone(),
                    None => derive(DEFAULT_PW3, pw3_salt)?,
                };
                Ok((pw1, pw3))
            }
        }
    }
}

/// Iterated and salted S2K (RFC 4880 §3.7.1.3): hash `salt || pin` repeated until `count`
/// bytes have been hashed. When `count` is smaller than one `salt || pin` block, the whole
/// block is hashed once ("the full salt plus passphrase will be hashed even though that is
/// greater than the octet count"); this is the catalog's low-count rule.
pub(crate) fn iterated_salted_s2k(hash: HashAlg, salt: &[u8], pin: &[u8], count: usize) -> Vec<u8> {
    let mut block = Vec::with_capacity(salt.len() + pin.len());
    block.extend_from_slice(salt);
    block.extend_from_slice(pin);
    if block.is_empty() {
        return lk_crypto::digest(hash, &[]);
    }
    let total = count.max(block.len());
    let mut input = Vec::with_capacity(total);
    while input.len() < total {
        let take = (total - input.len()).min(block.len());
        input.extend_from_slice(block.get(..take).unwrap_or(&block));
    }
    lk_crypto::digest(hash, &input)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    // Expected digests computed independently with Python's hashlib, hashing
    // (salt || pin) repeated and truncated to max(count, len(salt || pin)) bytes, which is
    // the RFC 4880 §3.7.1.3 definition.

    #[test]
    fn s2k_sha256_vectors() {
        assert_eq!(
            iterated_salted_s2k(HashAlg::Sha256, &SALT, b"123456", 122_880),
            hex("818e6e7faa56aabbd337684ea24642f2ec252ca627461debd9fb3bc640920d8c")
        );
        assert_eq!(
            iterated_salted_s2k(HashAlg::Sha256, &SALT, b"12345678", 100_000),
            hex("b02e17de50dc5428904e4764e9cb24079541f7623584effd0625a8102d019094")
        );
        // count 15 = one block (14 bytes) plus one byte of the next.
        assert_eq!(
            iterated_salted_s2k(HashAlg::Sha256, &SALT, b"123456", 15),
            hex("b2b79246be1906a565f9e381c07e406f86901d31de8af33ef99a9d366de01069")
        );
    }

    #[test]
    fn s2k_sha512_vectors() {
        assert_eq!(
            iterated_salted_s2k(HashAlg::Sha512, &SALT, b"123456", 122_880),
            hex(concat!(
                "33e00284999f11f942e312d5d4a522b42bc5edbe4dfa50e5d905d4b93fcc9c3b",
                "cc3ae6152f439cbef906ea4a4b3e64e01dccdf37b12c28baf06f3f656e6ec83b"
            ))
        );
        assert_eq!(
            iterated_salted_s2k(HashAlg::Sha512, &SALT, b"12345678", 100_000),
            hex(concat!(
                "765553e68fb8ef6abf16b18743c8b4821648af47149392d54618bbb84ee21db6",
                "c80819f2acfae7ec7b756e40fdce60f3f69ffcd96d11af34ef2d98574136c196"
            ))
        );
    }

    #[test]
    fn s2k_low_count_hashes_one_full_block() {
        // RFC 4880 §3.7.1.3 exception: count 3 < 14-byte block -> hash the whole block once.
        let expected = hex("1ae0f1043e1492a1acffc2319de52fa4713cf4bfd7123563345550f0da8eee9a");
        assert_eq!(iterated_salted_s2k(HashAlg::Sha256, &SALT, b"123456", 3), expected);
        assert_eq!(iterated_salted_s2k(HashAlg::Sha256, &SALT, b"123456", 14), expected);
        let mut block = SALT.to_vec();
        block.extend_from_slice(b"123456");
        assert_eq!(expected, lk_crypto::sha256(&block).to_vec());
        // Not the truncated block a naive "hash count bytes" loop would produce.
        assert_ne!(expected, lk_crypto::sha256(&block[..3]).to_vec());
        let sha512 = iterated_salted_s2k(HashAlg::Sha512, &SALT, b"123456", 1);
        assert_eq!(
            sha512,
            hex(concat!(
                "aac09812feb262c34917f3a810ab49c573a2b840a31883a916107074d377ada7",
                "7652a290f43ea00ba634235dc6220d40b6a9e86a346af967906ef3ac51a4bee1"
            ))
        );
    }

    #[test]
    fn parse_none_and_s2k() {
        assert_eq!(Kdf::parse(&KDF_NONE), Ok(Kdf::None));
        let mut data = hex("810103820108830400010000");
        data.extend_from_slice(&tlv::encode(0x84, &SALT));
        let kdf = Kdf::parse(&data).unwrap();
        assert_eq!(kdf.hash_len(), Some(32));
        let (pw1, pw3) = kdf.initial_references().unwrap();
        assert_eq!(pw1, iterated_salted_s2k(HashAlg::Sha256, &SALT, b"123456", 0x10000));
        // PW3 salt absent: PW1's salt is used (spec §4.3.2).
        assert_eq!(pw3, iterated_salted_s2k(HashAlg::Sha256, &SALT, b"12345678", 0x10000));
    }

    #[test]
    fn parse_rejections() {
        for bad in [
            "",                       // 81 missing
            "810101",                 // unknown algorithm
            "81020300",               // algorithm wrong length
            "810103",                 // S2K without hash/count/salt
            "810103820109830400010000", // unsupported hash
            "8101038201088303000100", // count wrong length
            "810103820108830400000000", // zero count
            "810100810100",           // duplicate field
            "81",                     // truncated TLV
        ] {
            assert!(Kdf::parse(&hex(bad)).is_err(), "{bad}");
        }
        // Unknown field.
        assert!(Kdf::parse(&hex("8101008901ff")).is_err());
        // Salt of the wrong length.
        let mut data = hex("810103820108830400010000");
        data.extend_from_slice(&tlv::encode(0x84, &[1, 2, 3]));
        assert!(Kdf::parse(&data).is_err());
        // Initial hash of the wrong length.
        let mut data = hex("810103820108830400010000");
        data.extend_from_slice(&tlv::encode(0x84, &SALT));
        data.extend_from_slice(&tlv::encode(0x87, &[0; 31]));
        assert!(Kdf::parse(&data).is_err());
        // Longer than the special DO limit (C0: 255).
        assert_eq!(Kdf::parse(&[0x81; 256]), Err(sw::WRONG_LENGTH));
    }

    #[test]
    fn large_count_needs_initial_hashes() {
        let mut data = hex("8101038201088304ffffffff");
        data.extend_from_slice(&tlv::encode(0x84, &SALT));
        let kdf = Kdf::parse(&data).unwrap();
        assert_eq!(kdf.initial_references(), Err(sw::INCORRECT_DATA));
        data.extend_from_slice(&tlv::encode(0x87, &[0x11; 32]));
        data.extend_from_slice(&tlv::encode(0x88, &[0x22; 32]));
        let kdf = Kdf::parse(&data).unwrap();
        assert_eq!(kdf.initial_references(), Ok((vec![0x11; 32], vec![0x22; 32])));
    }
}
