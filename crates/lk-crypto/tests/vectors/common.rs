//! Helpers shared by the vector tests: hex decoding and deterministic entropy sources.
//!
//! `lk-testkit` is being written in parallel, so these are local on purpose.

use std::collections::VecDeque;

use lk_core::Entropy;

/// Decode hex, ignoring ASCII whitespace so vectors can be pasted as printed in the RFCs.
pub fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(digits.len().is_multiple_of(2), "odd number of hex digits");
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

/// A deterministic byte stream: `SHA-256(seed || counter)` blocks, counter big-endian.
///
/// Not a DRBG anyone should ship; it only makes key generation reproducible in tests.
#[derive(Debug)]
pub struct CounterEntropy {
    seed: Vec<u8>,
    counter: u64,
    pending: Vec<u8>,
}

impl CounterEntropy {
    pub fn new(seed: &[u8]) -> Self {
        Self { seed: seed.to_vec(), counter: 0, pending: Vec::new() }
    }
}

impl Entropy for CounterEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            if self.pending.is_empty() {
                let block = lk_crypto::sha256(&[self.seed.as_slice(), &self.counter.to_be_bytes()].concat());
                self.counter += 1;
                // Stored reversed so `pop` yields the block in order.
                self.pending = block.iter().rev().copied().collect();
            }
            *byte = self.pending.pop().unwrap();
        }
    }
}

/// Entropy that returns a fixed script of chunks, one per `fill` call.
///
/// Each request must ask for exactly the next chunk's length; running out of script
/// fails the test, which catches unexpected extra draws.
#[derive(Debug)]
pub struct ScriptedEntropy {
    chunks: VecDeque<Vec<u8>>,
    pub calls: usize,
}

impl ScriptedEntropy {
    pub fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self { chunks: chunks.into(), calls: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.chunks.len()
    }
}

impl Entropy for ScriptedEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        let chunk = self.chunks.pop_front().expect("entropy script exhausted");
        assert_eq!(chunk.len(), out.len(), "entropy request length differs from script");
        out.copy_from_slice(&chunk);
        self.calls += 1;
    }
}

#[test]
fn hex_ignores_whitespace() {
    assert_eq!(hex("0b0b 0b\n  ff"), [0x0b, 0x0b, 0x0b, 0xff]);
}

#[test]
fn counter_entropy_is_deterministic_and_split_independent() {
    let mut a = CounterEntropy::new(b"seed");
    let mut b = CounterEntropy::new(b"seed");
    let mut whole = [0u8; 80];
    a.fill(&mut whole);
    let mut parts = [0u8; 80];
    let (first, rest) = parts.split_at_mut(7);
    b.fill(first);
    b.fill(rest);
    assert_eq!(whole, parts);
    // The first block is SHA-256(seed || 0u64).
    assert_eq!(whole[..32], lk_crypto::sha256(b"seed\0\0\0\0\0\0\0\0"));
}
