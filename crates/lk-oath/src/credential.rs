//! OATH credentials and the HOTP/TOTP computations of RFC 4226 and RFC 6238.

use std::cmp::Ordering;
use std::fmt;

use lk_crypto::HashAlg;

/// Credential type: the high nibble of the YKOATH type/algorithm byte
/// (YKOATH §PUT, "Type").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Event-based one-time password (RFC 4226).
    Hotp,
    /// Time-based one-time password (RFC 6238); the host sends the time step.
    Totp,
}

impl Kind {
    /// YKOATH §PUT: `0x10` HOTP, `0x20` TOTP.
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0x10 => Some(Self::Hotp),
            0x20 => Some(Self::Totp),
            _ => None,
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Hotp => 0x10,
            Self::Totp => 0x20,
        }
    }
}

/// HMAC algorithm: the low nibble of the YKOATH type/algorithm byte
/// (YKOATH §PUT, "Algorithm").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Sha1,
    Sha256,
    Sha512,
}

impl Alg {
    /// YKOATH §PUT: `0x01` HMAC-SHA1, `0x02` HMAC-SHA256, `0x03` HMAC-SHA512.
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Sha1),
            0x02 => Some(Self::Sha256),
            0x03 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Sha1 => 0x01,
            Self::Sha256 => 0x02,
            Self::Sha512 => 0x03,
        }
    }

    pub(crate) fn hash(self) -> HashAlg {
        match self {
            Self::Sha1 => HashAlg::Sha1,
            Self::Sha256 => HashAlg::Sha256,
            Self::Sha512 => HashAlg::Sha512,
        }
    }

    /// The hash block size `B` of RFC 2104 §2 (FIPS 180-4 §1: 512 bits for SHA-1 and
    /// SHA-256, 1024 bits for SHA-512).
    pub(crate) fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// HMAC output length in bytes.
    pub(crate) fn output_len(self) -> usize {
        self.hash().output_len()
    }

    /// HMAC with this algorithm (RFC 2104).
    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        lk_crypto::hmac(self.hash(), key, data)
    }

    /// Key shortening of RFC 2104 §2: a key longer than the block size is replaced by
    /// its hash. HMAC does this itself, so the stored key gives the same MAC as the
    /// key the host sent; shortening on entry only bounds the storage per credential
    /// (YKOATH clients shorten before PUT for the same reason).
    pub(crate) fn shorten(self, key: &[u8]) -> Vec<u8> {
        if key.len() > self.block_size() {
            lk_crypto::digest(self.hash(), key)
        } else {
            key.to_vec()
        }
    }
}

/// Property bit "only increasing" (YKOATH §PUT, "Property" `0x01`): a TOTP challenge
/// must never be lower than the previous one.
pub const PROP_ONLY_INCREASING: u8 = 0x01;
/// Property bit "require touch" (YKOATH §PUT, "Property" `0x02`).
pub const PROP_REQUIRE_TOUCH: u8 = 0x02;
/// Every property bit this applet accepts.
pub(crate) const PROP_ALL: u8 = PROP_ONLY_INCREASING | PROP_REQUIRE_TOUCH;

/// The HOTP counter value that marks an exhausted credential. RFC 4226 §5.1 makes `C`
/// an 8-byte counter, so the counters `0 ..= u64::MAX - 1` can be used; after the last
/// of them the stored next counter is this sentinel and calculation is refused.
pub(crate) const HOTP_EXHAUSTED: u64 = u64::MAX;

/// One stored OATH credential.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    /// Binary credential name (YKOATH §PUT "Name", at most 64 bytes, any byte values).
    pub(crate) name: Vec<u8>,
    pub(crate) kind: Kind,
    pub(crate) alg: Alg,
    /// Number of digits the client should display (RFC 4226 §5.3 "Digit").
    pub(crate) digits: u8,
    /// HMAC key, shortened per RFC 2104 §2.
    pub(crate) key: Vec<u8>,
    /// Property bits ([`PROP_ONLY_INCREASING`], [`PROP_REQUIRE_TOUCH`]).
    pub(crate) props: u8,
    /// HOTP: the next moving factor `C` (RFC 4226 §5.2); unused for TOTP.
    pub(crate) counter: u64,
    /// TOTP with "only increasing": the highest challenge used so far.
    pub(crate) last_challenge: Vec<u8>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("alg", &self.alg)
            .field("digits", &self.digits)
            .field("key", &"<redacted>")
            .field("props", &self.props)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl Credential {
    /// The YKOATH type/algorithm byte (YKOATH §PUT, §LIST).
    pub(crate) fn type_alg(&self) -> u8 {
        self.kind.code() | self.alg.code()
    }

    pub(crate) fn requires_touch(&self) -> bool {
        self.props & PROP_REQUIRE_TOUCH != 0
    }

    pub(crate) fn only_increasing(&self) -> bool {
        self.props & PROP_ONLY_INCREASING != 0
    }

    /// `HMAC(K, message)` with this credential's key and algorithm (RFC 4226 §5.3 step 1,
    /// RFC 6238 §4).
    pub(crate) fn hmac(&self, message: &[u8]) -> Vec<u8> {
        self.alg.hmac(&self.key, message)
    }
}

/// Dynamic truncation of RFC 4226 §5.3 step 2: four bytes at the offset given by the
/// low nibble of the last MAC byte, with the top bit cleared (`Snum` is 31 bits). RFC
/// 6238 §1.2 and its Appendix A apply the same function to SHA-256 and SHA-512 MACs.
pub(crate) fn dynamic_truncate(mac: &[u8]) -> Option<[u8; 4]> {
    let last = *mac.last()?;
    let offset = usize::from(last & 0x0F);
    let bytes = mac.get(offset..offset.checked_add(4)?)?;
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    out[0] &= 0x7F;
    Some(out)
}

/// Compare two challenges as unsigned big-endian integers of any length, so that a
/// shorter encoding of the same time step compares equal (RFC 6238 §4.2: `T` is an
/// integer).
pub(crate) fn compare_challenges(a: &[u8], b: &[u8]) -> Ordering {
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    bytes.get(skip..).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D: the truncation of the count-0 HMAC-SHA-1 value
    /// `cc93cf18508d94934c64b65d8ba7667fb7cde4b0` is `0x4c93cf18` = 1284755224.
    #[test]
    fn dynamic_truncate_rfc4226_appendix_d_count0() {
        let mac = [
            0xcc, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d, 0x8b, 0xa7, 0x66, 0x7f, 0xb7,
            0xcd, 0xe4, 0xb0,
        ];
        assert_eq!(dynamic_truncate(&mac), Some([0x4c, 0x93, 0xcf, 0x18]));
        assert_eq!(u32::from_be_bytes([0x4c, 0x93, 0xcf, 0x18]), 1_284_755_224);
    }

    /// RFC 4226 §5.4: the worked example's MAC
    /// `1f8698690e02ca16618550ef7f19da8e945b555a` has offset 0xa and `DBC1` 0x50ef7f19.
    #[test]
    fn dynamic_truncate_rfc4226_section_5_4_example() {
        let mac = [
            0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94,
            0x5b, 0x55, 0x5a,
        ];
        assert_eq!(dynamic_truncate(&mac), Some([0x50, 0xef, 0x7f, 0x19]));
    }

    /// RFC 4226 §5.3: the largest offset, 15 (last byte `xF`), takes bytes 15..=18 of a
    /// 20-byte SHA-1 MAC; the top bit of the first one is cleared. Appendix D never
    /// produces this offset, so the vector is constructed: bytes 15..=18 are
    /// `F1 F2 F3 F4`.
    #[test]
    fn dynamic_truncate_largest_offset() {
        let mut mac: Vec<u8> = (0u8..20).collect();
        mac[15..19].copy_from_slice(&[0xF1, 0xF2, 0xF3, 0xF4]);
        mac[19] = 0xAF;
        assert_eq!(dynamic_truncate(&mac), Some([0x71, 0xF2, 0xF3, 0xF4]));
        // Offset 0 with the top bit set (RFC 4226 §5.3 "Snum" is 31 bits).
        let mut mac = [0xFFu8; 32];
        mac[31] = 0x30;
        assert_eq!(dynamic_truncate(&mac), Some([0x7F, 0xFF, 0xFF, 0xFF]));
    }

    #[test]
    fn dynamic_truncate_rejects_short_input() {
        assert_eq!(dynamic_truncate(&[]), None);
        // Offset 0x0f needs 19 bytes.
        assert_eq!(dynamic_truncate(&[0x0f; 10]), None);
    }

    #[test]
    fn challenge_comparison_is_numeric() {
        assert_eq!(compare_challenges(&[0, 0, 1], &[1]), Ordering::Equal);
        assert_eq!(compare_challenges(&[1, 0], &[0xff]), Ordering::Greater);
        assert_eq!(compare_challenges(&[], &[0]), Ordering::Equal);
        assert_eq!(compare_challenges(&[0, 2], &[3]), Ordering::Less);
    }

    /// RFC 2104 §2: keys longer than B are hashed first, so the shortened key gives
    /// the same MAC.
    #[test]
    fn shortening_preserves_the_mac() {
        for alg in [Alg::Sha1, Alg::Sha256, Alg::Sha512] {
            let long = vec![0x5a; alg.block_size() + 1];
            let short = alg.shorten(&long);
            assert_eq!(short.len(), alg.output_len());
            assert_eq!(alg.hmac(&short, b"m"), alg.hmac(&long, b"m"));
            let exact = vec![0x5a; alg.block_size()];
            assert_eq!(alg.shorten(&exact), exact);
        }
    }
}
