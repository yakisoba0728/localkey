//! RSA key generation, import from primes, and the raw RSAEP/RSADP primitives
//! (RFC 8017 §5.1).

use std::sync::OnceLock;

use lk_crypto::{CryptoError, RsaPrivateKey, rsa_public_op};

use crate::common::CounterEntropy;

/// Key generation is slow in debug builds, so the generated key is shared.
fn generated() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::generate(1024, &mut CounterEntropy::new(b"lk-crypto rsa 1024")).unwrap())
}

#[test]
fn textbook_key_from_primes() {
    // Rivest, Shamir and Adleman's small worked example as used in most textbooks
    // (e.g. Stallings, "Cryptography and Network Security"; Wikipedia "RSA" § Example):
    // p = 61, q = 53, e = 17, n = 3233, and 65^17 mod 3233 = 2790.
    let key = RsaPrivateKey::from_primes(&[61], &[53], &[17]).unwrap();
    assert_eq!(key.modulus(), 3233u16.to_be_bytes());
    assert_eq!(key.public_exponent(), [17]);
    assert_eq!(key.size(), 2);
    let ciphertext = 2790u16.to_be_bytes();
    let plaintext = 65u16.to_be_bytes();
    assert_eq!(rsa_public_op(&key.modulus(), &[17], &plaintext).unwrap(), ciphertext);
    let mut entropy = CounterEntropy::new(b"blinding");
    assert_eq!(key.raw_private(&ciphertext, &mut entropy).unwrap(), plaintext);
}

#[test]
fn generate_1024_shape() {
    let key = generated();
    assert_eq!(key.size(), 128);
    let modulus = key.modulus();
    assert_eq!(modulus.len(), 128);
    assert!(modulus[0] & 0x80 != 0, "modulus must have exactly 1024 bits");
    assert!(modulus[127] & 1 == 1, "modulus must be odd");
    assert_eq!(key.public_exponent(), [0x01, 0x00, 0x01]);
    let primes = key.primes();
    assert_eq!(primes.0.len(), 64);
    assert_eq!(primes.1.len(), 64);
    assert_ne!(primes.0, primes.1);
}

#[test]
fn generate_is_deterministic_for_a_given_entropy_stream() {
    // The same seed must give the same key; lk-testkit-driven tests rely on this.
    let again = RsaPrivateKey::generate(1024, &mut CounterEntropy::new(b"lk-crypto rsa 1024")).unwrap();
    assert_eq!(again.modulus(), generated().modulus());
}

#[test]
fn from_primes_reproduces_the_modulus() {
    let key = generated();
    let primes = key.primes();
    let rebuilt = RsaPrivateKey::from_primes(&primes.0, &primes.1, &[0x01, 0x00, 0x01]).unwrap();
    assert_eq!(rebuilt.modulus(), key.modulus());
    assert_eq!(rebuilt.public_exponent(), key.public_exponent());
    // Prime order does not matter for the modulus.
    let swapped = RsaPrivateKey::from_primes(&primes.1, &primes.0, &[0x01, 0x00, 0x01]).unwrap();
    assert_eq!(swapped.modulus(), key.modulus());
}

#[test]
fn from_primes_rejects_equal_primes() {
    let primes = generated().primes();
    assert_eq!(
        RsaPrivateKey::from_primes(&primes.0, &primes.0, &[0x01, 0x00, 0x01]).unwrap_err(),
        CryptoError::InvalidKey
    );
}

/// `n - 1`, the largest valid representative (n is odd, so only the last byte changes).
fn below_modulus(modulus: &[u8]) -> Vec<u8> {
    let mut value = modulus.to_vec();
    let last = value.len() - 1;
    value[last] -= 1;
    value
}

#[test]
fn raw_private_then_public_round_trips() {
    // RSASP1 followed by RSAVP1 (RFC 8017 §5.2) is the identity on [0, n).
    let key = generated();
    let n = key.modulus();
    let e = key.public_exponent();
    let mut entropy = CounterEntropy::new(b"blinding");
    for input in [
        vec![0; 128],
        [vec![0; 127], vec![1]].concat(),
        [vec![0x00], (1..=127).collect()].concat(),
        below_modulus(&n),
    ] {
        let signature = key.raw_private(&input, &mut entropy).unwrap();
        assert_eq!(signature.len(), 128);
        assert_eq!(rsa_public_op(&n, &e, &signature).unwrap(), input);
    }
}

#[test]
fn public_then_raw_private_round_trips() {
    // RSAEP then RSADP (RFC 8017 §5.1).
    let key = generated();
    let n = key.modulus();
    let e = key.public_exponent();
    let message = [vec![0x00, 0x02], vec![0x5a; 126]].concat();
    let ciphertext = rsa_public_op(&n, &e, &message).unwrap();
    assert_ne!(ciphertext, message);
    let mut entropy = CounterEntropy::new(b"blinding");
    assert_eq!(key.raw_private(&ciphertext, &mut entropy).unwrap(), message);
}

#[test]
fn raw_private_is_independent_of_blinding() {
    // Blinding changes the intermediate values only; RSADP output is a function of the input.
    let key = generated();
    let input = [vec![0x00, 0x01], vec![0xff; 100], vec![0x00], vec![0x42; 25]].concat();
    let a = key.raw_private(&input, &mut CounterEntropy::new(b"one")).unwrap();
    let b = key.raw_private(&input, &mut CounterEntropy::new(b"two")).unwrap();
    assert_eq!(a, b);
}

#[test]
fn raw_private_rejects_out_of_range_and_wrong_length() {
    // RFC 8017 §5.1.2 step 1: the representative must be in [0, n - 1].
    let key = generated();
    let n = key.modulus();
    let mut entropy = CounterEntropy::new(b"blinding");
    assert_eq!(key.raw_private(&n, &mut entropy).unwrap_err(), CryptoError::InvalidInput, "input = n");
    assert_eq!(key.raw_private(&[0xff; 128], &mut entropy).unwrap_err(), CryptoError::InvalidInput, "input > n");
    for len in [0, 1, 127, 129, 256] {
        assert_eq!(key.raw_private(&vec![0; len], &mut entropy).unwrap_err(), CryptoError::InvalidInput, "length {len}");
    }
}

#[test]
fn public_op_rejects_wrong_length() {
    let key = generated();
    let n = key.modulus();
    let e = key.public_exponent();
    for len in [0, 127, 129] {
        assert_eq!(rsa_public_op(&n, &e, &vec![0; len]).unwrap_err(), CryptoError::InvalidInput, "length {len}");
    }
}

#[test]
fn generate_rejects_tiny_moduli() {
    // The underlying implementation refuses keys under 1024 bits; the device never
    // generates them (YubiKey 5 PIV/OpenPGP: RSA 1024-4096).
    assert!(RsaPrivateKey::generate(512, &mut CounterEntropy::new(b"small")).is_err());
}

#[test]
fn debug_shows_only_the_size() {
    let text = format!("{:?}", generated());
    assert!(text.contains("1024"), "{text}");
    assert!(!text.contains("prime") && !text.contains("inner"), "{text}");
}

#[test]
fn from_primes_accepts_zero_padded_integers() {
    // Imports often carry DER INTEGER content or fixed-width fields with leading zeros
    // (e.g. OpenPGP card algorithm attributes, PIV key import); the value is what counts.
    let key = generated();
    let primes = key.primes();
    let pad = |value: &[u8]| [vec![0u8], value.to_vec()].concat();
    let rebuilt = RsaPrivateKey::from_primes(&pad(&primes.0), &pad(&primes.1), &[0x00, 0x01, 0x00, 0x01]).unwrap();
    assert_eq!(rebuilt.modulus(), key.modulus());
    assert_eq!(rebuilt.public_exponent(), [0x01, 0x00, 0x01]);
}

#[test]
fn public_op_accepts_a_zero_padded_modulus() {
    // The DER encoding of a modulus has a leading 0x00; its size is still 128 bytes.
    let key = generated();
    let n = key.modulus();
    let padded = [vec![0x00], n.clone()].concat();
    let input = [vec![0x00, 0x02], vec![0x5a; 126]].concat();
    assert_eq!(rsa_public_op(&padded, &[1, 0, 1], &input).unwrap(), rsa_public_op(&n, &[1, 0, 1], &input).unwrap());
}

#[test]
fn public_op_rejects_out_of_range_input() {
    // RFC 8017 §5.1.1 step 1 (RSAEP) and §5.2.2 step 1 (RSAVP1): 0 <= input <= n - 1.
    let key = generated();
    let n = key.modulus();
    let e = key.public_exponent();
    assert_eq!(rsa_public_op(&n, &e, &n).unwrap_err(), CryptoError::InvalidInput, "input = n");
    assert_eq!(rsa_public_op(&n, &e, &[0xff; 128]).unwrap_err(), CryptoError::InvalidInput, "input > n");
    assert_eq!(rsa_public_op(&n, &e, &below_modulus(&n)).unwrap().len(), 128, "input = n - 1");
}

#[test]
fn public_op_rejects_invalid_public_keys() {
    let n = generated().modulus();
    let input = [vec![0x00], vec![0x11; 127]].concat();
    for (modulus, exponent, what) in [
        (n.as_slice(), &[1u8][..], "e = 1"),
        (n.as_slice(), &[0u8][..], "e = 0"),
        (&[][..], &[1, 0, 1][..], "empty modulus"),
    ] {
        assert_eq!(rsa_public_op(modulus, exponent, &input).unwrap_err(), CryptoError::InvalidKey, "{what}");
    }
    // An even modulus cannot be an RSA modulus.
    assert_eq!(rsa_public_op(&[0x10, 0x00], &[3], &[0x00, 0x05]).unwrap_err(), CryptoError::InvalidKey);
}

#[test]
fn from_primes_accepts_primes_of_different_encoded_widths() {
    // An import may zero-pad one prime and not the other. This used to panic inside the
    // rsa crate (operands of different precision).
    let key = generated();
    let primes = key.primes();
    let padded_p = [vec![0u8], primes.0.clone()].concat();
    let rebuilt = RsaPrivateKey::from_primes(&padded_p, &primes.1, &[0x01, 0x00, 0x01]).unwrap();
    assert_eq!(rebuilt.modulus(), key.modulus());

    // Primes of genuinely different sizes: the Mersenne primes 2^61 - 1 (8 bytes) and
    // 2^89 - 1 (12 bytes). 65537 is coprime to both p - 1 and q - 1 (2 has order 32
    // mod 65537, which divides neither 60 nor 88).
    let m61 = (2u128.pow(61) - 1).to_be_bytes();
    let m89 = (2u128.pow(89) - 1).to_be_bytes();
    let key = RsaPrivateKey::from_primes(&m61, &m89, &[0x01, 0x00, 0x01]).unwrap();
    assert_eq!(key.modulus(), crate::common::hex("3ffffffffffffffdffffffe000000000000001"));
    let input = [vec![0x00], vec![0x5a; key.size() - 1]].concat();
    let ciphertext = rsa_public_op(&key.modulus(), &key.public_exponent(), &input).unwrap();
    assert_eq!(key.raw_private(&ciphertext, &mut CounterEntropy::new(b"blinding")).unwrap(), input);
}

#[test]
fn from_primes_rejects_degenerate_parameters() {
    // RFC 8017 §3.2: p and q are distinct odd primes; §3.1: e is odd and at least 3.
    // Zero, one and even values used to panic inside the rsa crate instead of failing.
    let primes = generated().primes();
    let (p, q) = (primes.0.as_slice(), primes.1.as_slice());
    let e = &[0x01, 0x00, 0x01][..];
    let padded_p = [vec![0u8], p.to_vec()].concat();
    for (p, q, e, what) in [
        (&[][..], q, e, "p empty"),
        (&[0][..], q, e, "p = 0"),
        (&[1][..], q, e, "p = 1"),
        (&[2][..], q, e, "p = 2"),
        (&[0x10, 0x00][..], q, e, "p even"),
        (p, &[0, 1][..], e, "q = 1 (padded)"),
        (p, &[0x04][..], e, "q even"),
        (p, q, &[][..], "e empty"),
        (p, q, &[1][..], "e = 1"),
        (p, q, &[2][..], "e = 2"),
        (p, q, &[0x01, 0x00, 0x00][..], "e even"),
        (padded_p.as_slice(), p, e, "p = q, encoded differently"),
    ] {
        assert_eq!(RsaPrivateKey::from_primes(p, q, e).unwrap_err(), CryptoError::InvalidKey, "{what}");
    }
}

#[test]
fn from_primes_rejects_keys_that_fail_the_pairwise_test() {
    // NIST SP 800-56B Rev. 2 §6.4.1.1 pairwise consistency. 65 = 5 * 13 is not prime, so
    // the private exponent derived from "p - 1" is wrong: RSADP(RSAEP(2)) != 2. Without
    // the test the key was accepted and silently produced wrong RSADP output.
    assert_eq!(RsaPrivateKey::from_primes(&[65], &[23], &[3]).unwrap_err(), CryptoError::InvalidKey);
}
