//! Deterministic [`Entropy`] sources for reproducible tests.
//!
//! Both sources produce one continuous byte stream: the bytes a caller sees depend only
//! on the seed (and the script) and on how many bytes were drawn before, never on how
//! the draws were split into `fill` calls. `lk_crypto`'s RNG adapter asks for 4- and
//! 8-byte pieces, so this keeps key generation reproducible however a primitive reads
//! its randomness.

use std::collections::VecDeque;

use lk_core::Entropy;

/// Domain-separation label hashed with the seed to form the HMAC key.
const SEED_LABEL: &[u8] = b"lk-testkit/SeededEntropy/v1";

/// A deterministic, seeded pseudo-random byte stream.
///
/// Construction (HMAC-SHA256 in counter mode, after NIST SP 800-108 §4.1):
/// - `key = SHA-256(b"lk-testkit/SeededEntropy/v1" || seed as 8 big-endian bytes)`;
/// - block `i` (from 0) is `HMAC-SHA256(key, i as 8 big-endian bytes)`;
/// - the stream is block 0 || block 1 || ...
///
/// The stream is pinned by a known-answer test. Other crates may embed values derived
/// from it, so the construction must not change. It is for tests only: the seed space is
/// 64 bits and the key is visible through `Debug`.
///
/// # Examples
///
/// ```
/// use lk_core::Entropy;
/// use lk_testkit::SeededEntropy;
///
/// let mut a = SeededEntropy::new(7);
/// let mut b = SeededEntropy::new(7);
///
/// // Draws split differently still see the same stream.
/// let mut whole = [0u8; 12];
/// a.fill(&mut whole);
/// let mut head = [0u8; 5];
/// let mut tail = [0u8; 7];
/// b.fill(&mut head);
/// b.fill(&mut tail);
/// assert_eq!(whole[..5], head);
/// assert_eq!(whole[5..], tail);
///
/// // A different seed gives a different stream.
/// assert_ne!(SeededEntropy::new(8).bytes(12), whole.to_vec());
/// ```
#[derive(Debug, Clone)]
pub struct SeededEntropy {
    key: [u8; 32],
    counter: u64,
    block: [u8; 32],
    /// Bytes of `block` already handed out; `block.len()` means "generate the next block".
    used: usize,
}

impl SeededEntropy {
    /// A stream determined entirely by `seed`.
    pub fn new(seed: u64) -> Self {
        let mut material = Vec::with_capacity(SEED_LABEL.len() + 8);
        material.extend_from_slice(SEED_LABEL);
        material.extend_from_slice(&seed.to_be_bytes());
        let key = lk_crypto::sha256(&material);
        Self { key, counter: 0, block: [0; 32], used: 32 }
    }

    /// The next `len` bytes of the stream as a vector.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        self.fill(&mut out);
        out
    }

    fn refill(&mut self) {
        self.block = lk_crypto::hmac_sha256(&self.key, &self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }
}

impl Entropy for SeededEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        let mut written = 0;
        while written < out.len() {
            if self.used == self.block.len() {
                self.refill();
            }
            let take = (self.block.len() - self.used).min(out.len() - written);
            out[written..written + take].copy_from_slice(&self.block[self.used..self.used + take]);
            self.used += take;
            written += take;
        }
    }
}

/// Entropy that first returns scripted bytes, then continues with a seeded stream.
///
/// The script is one flat queue: every chunk passed to [`ScriptedEntropy::new`] or
/// [`ScriptedEntropy::push`] is appended to it. A `fill` drains bytes from the front of
/// the queue; once the queue is empty the rest of that fill, and every later fill, comes
/// from [`SeededEntropy::new(seed)`](SeededEntropy::new). Scripted bytes do not advance
/// the seeded stream, so its first byte is the first byte after the script.
///
/// Use it to feed a known private scalar, nonce or challenge into code under test, for
/// example to reproduce a published test vector.
///
/// # Examples
///
/// ```
/// use lk_core::Entropy;
/// use lk_testkit::{ScriptedEntropy, SeededEntropy};
///
/// let scalar = [0x11u8; 32];
/// let mut entropy = ScriptedEntropy::new(3, [scalar]);
///
/// // The scripted scalar comes back even when read in smaller pieces...
/// let mut first = [0u8; 20];
/// let mut second = [0u8; 12];
/// entropy.fill(&mut first);
/// entropy.fill(&mut second);
/// assert_eq!([first.as_slice(), second.as_slice()].concat(), scalar);
///
/// // ...and then the seeded stream for seed 3 starts.
/// assert_eq!(entropy.scripted_remaining(), 0);
/// let mut next = [0u8; 4];
/// entropy.fill(&mut next);
/// assert_eq!(next.to_vec(), SeededEntropy::new(3).bytes(4));
/// ```
#[derive(Debug, Clone)]
pub struct ScriptedEntropy {
    script: VecDeque<u8>,
    fallback: SeededEntropy,
}

impl ScriptedEntropy {
    /// Script `chunks` (concatenated in order) ahead of the stream for `seed`.
    pub fn new<I>(seed: u64, chunks: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut entropy = Self { script: VecDeque::new(), fallback: SeededEntropy::new(seed) };
        for chunk in chunks {
            entropy.push(chunk.as_ref());
        }
        entropy
    }

    /// Append `bytes` to the end of the script.
    pub fn push(&mut self, bytes: &[u8]) {
        self.script.extend(bytes.iter().copied());
    }

    /// How many scripted bytes have not been drawn yet.
    pub fn scripted_remaining(&self) -> usize {
        self.script.len()
    }
}

impl Entropy for ScriptedEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        let scripted = self.script.len().min(out.len());
        for (slot, byte) in out.iter_mut().zip(self.script.drain(..scripted)) {
            *slot = byte;
        }
        self.fallback.fill(&mut out[scripted..]);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn draw(entropy: &mut impl Entropy, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        entropy.fill(&mut out);
        out
    }

    /// Known answer for `SeededEntropy::new(0)` and `new(0x0123_4567_89ab_cdef)`, first
    /// 40 bytes (block 0 and the start of block 1). Generated independently with
    /// CPython's standard library (`hashlib`, `hmac`), following the construction in
    /// the `SeededEntropy` doc comment:
    ///
    /// ```text
    /// key = hashlib.sha256(b"lk-testkit/SeededEntropy/v1" + seed.to_bytes(8, "big")).digest()
    /// out = b"".join(hmac.new(key, i.to_bytes(8, "big"), "sha256").digest() for i in range(2))[:40]
    /// ```
    const KAT: &[(u64, &str)] = &[
        (0, "12871c4ffab1d8194c44187c57febe6bf39afd0f5c937bb96bd8996eaa54892acc1d4611c95e4b86"),
        (0x0123_4567_89ab_cdef, "e0d2f5978faf6a3de09303c8c0acde39eab94fba9c33f54f86c3cc004228856b361fb6c3b03eb06c"),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn seeded_stream_matches_known_answer() {
        for &(seed, expected) in KAT {
            assert_eq!(hex(&SeededEntropy::new(seed).bytes(40)), expected, "seed {seed:#x}");
        }
    }

    #[test]
    fn seeded_stream_follows_documented_construction() {
        // Recomputes the doc-comment construction with lk_crypto directly.
        let seed = 42u64;
        let key = lk_crypto::sha256(&[SEED_LABEL, &seed.to_be_bytes()].concat());
        let expected: Vec<u8> = (0u64..3).flat_map(|i| lk_crypto::hmac_sha256(&key, &i.to_be_bytes())).collect();
        assert_eq!(SeededEntropy::new(seed).bytes(96), expected);
    }

    #[test]
    fn seeded_stream_is_independent_of_fill_sizes() {
        let reference = SeededEntropy::new(9).bytes(200);
        // Sizes chosen to cross block boundaries at odd offsets, including empty fills.
        for sizes in [&[1usize, 31, 0, 33, 64, 71][..], &[4, 8, 4, 8, 176], &[200], &[32, 32, 136]] {
            let mut entropy = SeededEntropy::new(9);
            let mut stream = Vec::new();
            for &size in sizes {
                stream.extend(entropy.bytes(size));
            }
            assert_eq!(stream, reference, "sizes {sizes:?}");
        }
    }

    #[test]
    fn different_seeds_give_different_streams() {
        let streams: Vec<Vec<u8>> = (0..8).map(|seed| SeededEntropy::new(seed).bytes(32)).collect();
        for (i, a) in streams.iter().enumerate() {
            for b in &streams[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn clone_continues_the_same_stream() {
        let mut original = SeededEntropy::new(5);
        original.bytes(10);
        let mut copy = original.clone();
        assert_eq!(original.bytes(50), copy.bytes(50));
    }

    #[test]
    fn script_is_served_before_the_seeded_stream() {
        let mut entropy = ScriptedEntropy::new(1, [&[1u8, 2, 3][..], &[4, 5]]);
        assert_eq!(entropy.scripted_remaining(), 5);
        let mut out = [0u8; 8];
        entropy.fill(&mut out);
        // A fill that straddles the end of the script continues with the seeded stream.
        let seeded = SeededEntropy::new(1).bytes(3);
        assert_eq!(out[..5], [1, 2, 3, 4, 5]);
        assert_eq!(out[5..], seeded[..]);
        assert_eq!(entropy.scripted_remaining(), 0);
    }

    #[test]
    fn pushed_bytes_are_served_next() {
        let mut entropy = ScriptedEntropy::new(2, [] as [&[u8]; 0]);
        let first = {
            let mut out = [0u8; 4];
            entropy.fill(&mut out);
            out
        };
        assert_eq!(first.to_vec(), SeededEntropy::new(2).bytes(4));

        entropy.push(&[0xaa, 0xbb]);
        let mut out = [0u8; 3];
        entropy.fill(&mut out);
        let mut seeded = SeededEntropy::new(2);
        seeded.bytes(4);
        assert_eq!(out[..2], [0xaa, 0xbb]);
        assert_eq!(out[2..], seeded.bytes(1)[..]);
    }

    #[test]
    fn empty_fill_consumes_nothing() {
        let mut entropy = ScriptedEntropy::new(4, [[9u8]]);
        entropy.fill(&mut []);
        assert_eq!(entropy.scripted_remaining(), 1);
    }

    #[test]
    fn no_block_repeats_within_or_across_seeds() {
        // HMAC-SHA256 is a PRF (RFC 2104 §6, FIPS 198-1), so a repeated 32-byte block is a
        // ~2^-128 event. A repeat would mean a counter that does not advance, a key that
        // ignores part of the seed, or two seeds sharing a stream. Edge seeds included.
        let seeds = (0u64..48).chain([1 << 32, 1 << 56, 1 << 63, u64::MAX - 1, u64::MAX]);
        let mut seen = BTreeSet::new();
        for seed in seeds {
            for (i, block) in SeededEntropy::new(seed).bytes(32 * 64).chunks(32).enumerate() {
                assert!(seen.insert(block.to_vec()), "seed {seed:#x} block {i} repeats an earlier block");
            }
        }
    }

    #[test]
    fn byte_and_bit_frequencies_look_uniform() {
        // Coarse sanity checks on 64 KiB from a fixed seed, not a randomness proof:
        // - chi-square over the 256 byte values: 255 degrees of freedom, mean 255 and
        //   standard deviation sqrt(510) ~ 22.6, so the bound 400 is > 6 sd;
        // - ones among 524,288 bits: mean 262,144 and sd 362, bound +-2,500 (~7 sd).
        // The stream is fixed, so the outcome is deterministic; the bounds catch gross
        // defects such as a stuck byte, zeroed blocks or one block repeated throughout.
        let data = SeededEntropy::new(0x5eed).bytes(65_536);
        let mut counts = [0u32; 256];
        for &byte in &data {
            counts[usize::from(byte)] += 1;
        }
        let expected = data.len() as f64 / 256.0;
        let chi_square: f64 = counts.iter().map(|&c| (f64::from(c) - expected).powi(2) / expected).sum();
        assert!(chi_square < 400.0, "chi-square {chi_square}");
        let ones: u32 = data.iter().map(|byte| byte.count_ones()).sum();
        assert!(ones.abs_diff(262_144) < 2_500, "ones {ones}");
    }

    #[test]
    fn seeds_one_bit_apart_give_unrelated_streams() {
        // Avalanche through the SHA-256 key derivation: flipping any single seed bit should
        // change about half of the output bits. Over 2,048 bits the mean is 1,024 and the
        // sd is ~22.6; the window +-200 is ~9 sd.
        let base = SeededEntropy::new(0).bytes(256);
        for bit in 0..64 {
            let other = SeededEntropy::new(1 << bit).bytes(256);
            let distance: u32 = base.iter().zip(&other).map(|(a, b)| (a ^ b).count_ones()).sum();
            assert!(distance.abs_diff(1_024) <= 200, "seed bit {bit}: Hamming distance {distance}");
        }
    }

    #[test]
    fn instances_do_not_share_state() {
        // Interleaved draws from two sources equal the draws each makes alone: no global or
        // shared state links them.
        let alone_a = SeededEntropy::new(20).bytes(100);
        let alone_b = SeededEntropy::new(21).bytes(100);
        let mut a = SeededEntropy::new(20);
        let mut b = SeededEntropy::new(21);
        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        for size in [3, 29, 1, 32, 35] {
            got_a.extend(a.bytes(size));
            got_b.extend(b.bytes(size));
        }
        assert_eq!((got_a, got_b), (alone_a, alone_b));
    }

    #[test]
    fn empty_chunks_are_ignored() {
        let mut entropy = ScriptedEntropy::new(6, [&[][..], &[1, 2], &[], &[], &[3], &[]]);
        assert_eq!(entropy.scripted_remaining(), 3);
        assert_eq!(draw(&mut entropy, 5), [&[1u8, 2, 3][..], &SeededEntropy::new(6).bytes(2)].concat());
    }

    #[test]
    fn chunking_and_fill_sizes_do_not_change_the_stream() {
        // The same script split into different chunks, drawn with different fill sizes
        // (including one byte at a time and empty fills), is one stream: script, then seed.
        let script: Vec<u8> = (1..=23).collect();
        let reference = [script.clone(), SeededEntropy::new(10).bytes(41)].concat();
        let chunkings: [Vec<Vec<u8>>; 3] = [
            vec![script.clone()],
            script.chunks(1).map(<[u8]>::to_vec).collect(),
            vec![script[..7].to_vec(), Vec::new(), script[7..12].to_vec(), script[12..].to_vec()],
        ];
        let fill_patterns: [&[usize]; 4] = [&[64], &[1; 64], &[7, 5, 11, 0, 1, 40], &[23, 41]];
        for (c, chunks) in chunkings.iter().enumerate() {
            for sizes in fill_patterns {
                let mut entropy = ScriptedEntropy::new(10, chunks);
                let stream: Vec<u8> = sizes.iter().flat_map(|&size| draw(&mut entropy, size)).collect();
                assert_eq!(stream, reference, "chunking {c}, fills {sizes:?}");
                assert_eq!(entropy.scripted_remaining(), 0);
            }
        }
    }

    #[test]
    fn fill_ending_exactly_at_the_script_end_leaves_the_seed_untouched() {
        let mut entropy = ScriptedEntropy::new(12, [[0xaau8; 12]]);
        assert_eq!(draw(&mut entropy, 12), [0xaa; 12]);
        assert_eq!(entropy.scripted_remaining(), 0);
        assert_eq!(draw(&mut entropy, 40), SeededEntropy::new(12).bytes(40));
    }

    #[test]
    fn pushes_between_draws_keep_the_seeded_position() {
        // The seeded stream resumes where it stopped each time the script runs dry.
        let seeded = SeededEntropy::new(13).bytes(30);
        let mut entropy = ScriptedEntropy::new(13, [] as [&[u8]; 0]);
        let mut got = draw(&mut entropy, 10);
        entropy.push(&[1, 2, 3]);
        got.extend(draw(&mut entropy, 2));
        entropy.push(&[4]);
        assert_eq!(entropy.scripted_remaining(), 2);
        got.extend(draw(&mut entropy, 4));
        got.extend(draw(&mut entropy, 18));
        assert_eq!(got, [&seeded[..10], &[1, 2, 3, 4], &seeded[10..]].concat());
    }

    #[test]
    fn scripted_clones_are_independent() {
        let mut original = ScriptedEntropy::new(14, [[1u8, 2, 3, 4]]);
        assert_eq!(draw(&mut original, 1), [1]);
        let mut copy = original.clone();
        assert_eq!(draw(&mut original, 10), draw(&mut copy, 10));
        copy.push(&[9]);
        assert_eq!((original.scripted_remaining(), copy.scripted_remaining()), (0, 1));
    }
}
