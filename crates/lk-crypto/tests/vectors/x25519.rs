//! X25519, RFC 7748 §5.2 and §6.1.

use lk_crypto::{CryptoError, X25519Key};

use crate::common::{ScriptedEntropy, hex};

fn x25519(scalar: &str, u: &str) -> Vec<u8> {
    X25519Key::from_bytes(&hex(scalar)).unwrap().dh(&hex(u)).unwrap().to_vec()
}

#[test]
fn rfc7748_section_5_2_vectors() {
    // RFC 7748 §5.2, first X25519 vector.
    assert_eq!(
        x25519(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ),
        hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    );
    // RFC 7748 §5.2, second X25519 vector. The u-coordinate has bit 255 set, which
    // §5 says implementations must mask.
    assert_eq!(
        x25519(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        ),
        hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    );
}

#[test]
fn rfc7748_section_5_2_one_iteration() {
    // RFC 7748 §5.2: k = u = 9, after one iteration.
    let nine = "0900000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(x25519(nine, nine), hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
}

#[test]
fn rfc7748_section_6_1_diffie_hellman() {
    // RFC 7748 §6.1 test vector.
    let alice = X25519Key::from_bytes(&hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).unwrap();
    let bob = X25519Key::from_bytes(&hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")).unwrap();
    let alice_public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    assert_eq!(alice.public().to_vec(), alice_public);
    assert_eq!(bob.public().to_vec(), bob_public);
    assert_eq!(alice.dh(&bob_public).unwrap().to_vec(), shared);
    assert_eq!(bob.dh(&alice_public).unwrap().to_vec(), shared);
}

#[test]
fn low_order_points_are_rejected() {
    // RFC 7748 §6.1: the all-zero output of a small-order input must be refused.
    // u = 0 and u = 1 have order 1 and 4; the third has order 8 (curve25519 small-order
    // points as listed by Bernstein, "Curve25519: new Diffie-Hellman speed records" and
    // the cr.yp.to "Will a 32-byte public key be safe?" note).
    let key = X25519Key::from_bytes(&hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).unwrap();
    for point in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ] {
        assert_eq!(key.dh(&hex(point)).unwrap_err(), CryptoError::InvalidInput, "{point}");
    }
}

#[test]
fn remaining_small_order_inputs_are_rejected() {
    // The rest of the curve25519 small-order list in Bernstein's "Which public keys are
    // safe?" (cr.yp.to/ecdh.html): the second order-8 point
    // (39382357235489614581723060781553021112529911719440698176882885853963445705823),
    // then p - 1, p and p + 1. RFC 7748 §5 reduces non-canonical u mod p, so p and p + 1
    // are 0 and 1 again.
    let key = X25519Key::from_bytes(&hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")).unwrap();
    for point in [
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        assert_eq!(key.dh(&hex(point)).unwrap_err(), CryptoError::InvalidInput, "{point}");
    }
}

#[test]
fn bit_255_of_u_is_ignored() {
    // RFC 7748 §5: "implementations of X25519 MUST mask the most significant bit in the
    // final byte". The §6.1 exchange gives the same secret with that bit set.
    let alice = X25519Key::from_bytes(&hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).unwrap();
    let mut bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    bob_public[31] |= 0x80;
    assert_eq!(
        alice.dh(&bob_public).unwrap().to_vec(),
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
}

#[test]
fn debug_does_not_leak_the_secret() {
    let key = X25519Key::from_bytes(&[0x42; 32]).unwrap();
    assert_eq!(format!("{key:?}"), "X25519Key { .. }");
}

#[test]
fn wrong_lengths_are_rejected() {
    for len in [0, 31, 33] {
        assert_eq!(X25519Key::from_bytes(&vec![1; len]).unwrap_err(), CryptoError::InvalidKey, "secret {len}");
    }
    let key = X25519Key::from_bytes(&[1; 32]).unwrap();
    for len in [0, 31, 33] {
        assert_eq!(key.dh(&vec![9; len]).unwrap_err(), CryptoError::InvalidInput, "peer {len}");
    }
}

#[test]
fn generate_uses_entropy_as_the_secret() {
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let mut entropy = ScriptedEntropy::new(vec![alice.clone()]);
    let key = X25519Key::generate(&mut entropy);
    assert_eq!(key.secret().to_vec(), alice);
    assert_eq!(key.public().to_vec(), hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
}
