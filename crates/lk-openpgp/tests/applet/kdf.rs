//! KDF-DO F9 (spec §4.3.2) with iterated-salted S2K (RFC 4880 §3.7.1.3).

use lk_codec::tlv;

use crate::common::Card;

const SALT_PW1: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const SALT_RC: [u8; 8] = [9, 9, 9, 9, 9, 9, 9, 9];
const SALT_PW3: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

/// RFC 4880 §3.7.1.3, written independently of the crate: hash `salt || pin` repeated to
/// `max(count, len)` bytes.
fn s2k256(salt: &[u8], pin: &[u8], count: usize) -> Vec<u8> {
    let block: Vec<u8> = salt.iter().chain(pin.iter()).copied().collect();
    let total = count.max(block.len());
    let input: Vec<u8> = block.iter().copied().cycle().take(total).collect();
    lk_crypto::sha256(&input).to_vec()
}

fn s2k512(salt: &[u8], pin: &[u8], count: usize) -> Vec<u8> {
    let block: Vec<u8> = salt.iter().chain(pin.iter()).copied().collect();
    let total = count.max(block.len());
    let input: Vec<u8> = block.iter().copied().cycle().take(total).collect();
    lk_crypto::sha512(&input).to_vec()
}

/// Build F9 contents (spec §4.3.2 table) the way YubiKit's `KdfIterSaltedS2k` encodes them.
fn kdf_do(hash: u8, count: u32, initial: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    tlv::encode_into(&mut out, 0x81, &[0x03]);
    tlv::encode_into(&mut out, 0x82, &[hash]);
    tlv::encode_into(&mut out, 0x83, &count.to_be_bytes());
    tlv::encode_into(&mut out, 0x84, &SALT_PW1);
    tlv::encode_into(&mut out, 0x85, &SALT_RC);
    tlv::encode_into(&mut out, 0x86, &SALT_PW3);
    if let Some((pw1, pw3)) = initial {
        tlv::encode_into(&mut out, 0x87, pw1);
        tlv::encode_into(&mut out, 0x88, pw3);
    }
    out
}

/// Initial hashes supplied by the host become the PW1/PW3 references; plain PINs no
/// longer verify (catalog: "hash-only PIN state when KDF enabled").
#[test]
fn kdf_with_initial_hashes() {
    let mut card = Card::new();
    card.admin();
    let count = 0x0001_0000;
    let pw1 = s2k256(&SALT_PW1, b"123456", count);
    let pw3 = s2k256(&SALT_PW3, b"12345678", count);
    let f9 = kdf_do(0x08, count as u32, Some((&pw1, &pw3)));
    assert_eq!(card.put(0x00F9, &f9), 0x9000);
    assert_eq!(card.get_ok(0x00F9), f9);
    // Writing F9 dropped the earlier PW3 verification.
    assert_eq!(card.verify(0x83, b""), 0x63C3);
    assert_eq!(card.verify(0x82, b"123456"), 0x63C2);
    assert_eq!(card.verify(0x82, &pw1), 0x9000);
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
    card.reload();
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
}

/// Without 87/88 the card derives the initial hashes itself (SHA-256 and SHA-512).
#[test]
fn kdf_card_derives_initial_hashes() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 100_000, None)), 0x9000);
    assert_eq!(card.verify(0x82, &s2k256(&SALT_PW1, b"123456", 100_000)), 0x9000);
    assert_eq!(card.verify(0x83, &s2k256(&SALT_PW3, b"12345678", 100_000)), 0x9000);
    assert_eq!(card.put(0x00F9, &kdf_do(0x0A, 50_000, None)), 0x9000);
    assert_eq!(card.verify(0x82, &s2k512(&SALT_PW1, b"123456", 50_000)), 0x9000);
    assert_eq!(card.verify(0x83, &s2k512(&SALT_PW3, b"12345678", 50_000)), 0x9000);
}

/// Catalog: "RFC4880 low-count iterated-salted S2K hashes one complete salt-plus-PIN block".
#[test]
fn kdf_low_count_hashes_one_full_block() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 1, None)), 0x9000);
    let mut block = SALT_PW1.to_vec();
    block.extend_from_slice(b"123456");
    let full_block = lk_crypto::sha256(&block).to_vec();
    let truncated = lk_crypto::sha256(&block[..1]).to_vec();
    assert_eq!(card.verify(0x82, &truncated), 0x63C2);
    assert_eq!(card.verify(0x82, &full_block), 0x9000);
}

/// Catalog: "KDF PIN change, retry and reset-code recovery".
#[test]
fn kdf_pin_change_retry_and_reset_code() {
    let mut card = Card::new();
    card.admin();
    let count = 1000;
    let f9 = kdf_do(0x08, count as u32, None);
    assert_eq!(card.put(0x00F9, &f9), 0x9000);
    let pw1 = s2k256(&SALT_PW1, b"123456", count);
    let pw3 = s2k256(&SALT_PW3, b"12345678", count);
    // Change PW1: old hash || new hash.
    let new_pw1 = s2k256(&SALT_PW1, b"654321", count);
    let mut data = pw1.clone();
    data.extend_from_slice(&new_pw1);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, &data, None).1, 0x9000);
    assert_eq!(card.verify(0x82, &new_pw1), 0x9000);
    // A new value that is not a hash of the right length is refused.
    let mut bad = new_pw1.clone();
    bad.extend_from_slice(b"plainpin");
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, &bad, None).1, 0x6A80);
    // Set a resetting code (hash), block PW1, recover.
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
    let rc = s2k256(&SALT_RC, b"resetcode", count);
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x6A80);
    assert_eq!(card.put(0x00D3, &rc), 0x9000);
    for _ in 0..3 {
        card.verify(0x82, &pw1);
    }
    assert_eq!(card.verify(0x82, &new_pw1), 0x6983);
    let recovered = s2k256(&SALT_PW1, b"recovered", count);
    let mut data = rc.clone();
    data.extend_from_slice(&recovered);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, &data, None).1, 0x9000);
    assert_eq!(card.verify(0x82, &recovered), 0x9000);
    // Admin reset with a hash value.
    let admin_set = s2k256(&SALT_PW1, b"adminset", count);
    assert_eq!(card.apdu(0x00, 0x2C, 0x02, 0x81, &admin_set, None).1, 0x9000);
    assert_eq!(card.verify(0x81, &admin_set), 0x9000);
}

/// Writing KDF_NONE restores the default PINs and removes the resetting code.
#[test]
fn kdf_none_restores_default_pins() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"123456abcdef", None).1, 0x9000);
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 64, None)), 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.verify(0x83, &s2k256(&SALT_PW3, b"12345678", 64)), 0x9000);
    assert_eq!(card.put(0x00F9, &[0x81, 0x01, 0x00]), 0x9000);
    assert_eq!(card.get_ok(0x00F9), vec![0x81, 0x01, 0x00]);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.admin();
}

/// F9 needs PW3; malformed contents change nothing (spec §4.3.2).
#[test]
fn kdf_requires_pw3_and_validates() {
    let mut card = Card::new();
    assert_eq!(card.put(0x00F9, &[0x81, 0x01, 0x00]), 0x6982);
    card.admin();
    for bad in [
        vec![],
        vec![0x81, 0x01, 0x02],
        vec![0x81, 0x01, 0x03],
        vec![0x81, 0x01, 0x03, 0x82, 0x01, 0x09],
        kdf_do(0x08, 0, None),
        kdf_do(0x08, 1000, Some((&[0; 31], &[0; 32]))),
        kdf_do(0x0A, 1000, Some((&[0; 32], &[0; 32]))),
    ] {
        assert_eq!(card.put(0x00F9, &bad), 0x6A80, "{bad:02X?}");
    }
    assert_eq!(card.get_ok(0x00F9), vec![0x81, 0x01, 0x00]);
    assert_eq!(card.verify(0x83, b""), 0x9000);
    // The largest count with initial hashes: nothing to derive on the card.
    let f9 = kdf_do(0x08, u32::MAX, Some((&[0x11; 32], &[0x22; 32])));
    assert_eq!(card.put(0x00F9, &f9), 0x9000);
    assert_eq!(card.verify(0x83, &[0x22; 32]), 0x9000);
}

/// The count is the raw byte count of spec §4.3.2, not capped at RFC 4880's largest coded
/// count (65 011 712): one byte more is derived on the card when no initial hashes are
/// given. Expected values: Python hashlib over (salt || PIN) repeated to 65 011 713 bytes.
#[test]
fn kdf_count_above_the_coded_maximum_is_derived() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 65_011_713, None)), 0x9000);
    let pw1 = crate::common::hex("98e240053141b1dc877a8cf265c7632baa74641ce40ae9ee447214d067296a85");
    let pw3 = crate::common::hex("567b07bf21fd002ab326476c1c487a6717126597700432df7175c04d6ceba2e3");
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
    // The plain PIN is no longer the reference (hash-only state) and costs a retry.
    assert_eq!(card.verify(0x82, b"123456"), 0x63C2);
    assert_eq!(card.verify(0x81, &pw1), 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
}

/// Yubico "YubiKey 5.2.3 Enhancements to OpenPGP 3.4", Key Derived Format: "Once a key has
/// been placed on the YubiKey any changes to the KDF settings will be prevented until the
/// OpenPGP application has been reset" ("Conditions of use not satisfied", 6985). The
/// factory attestation key does not count (a fresh card takes F9); a generated or an
/// imported SIG/DEC/AUT key does, and the refusal changes nothing and saves nothing.
/// TERMINATE DF / ACTIVATE FILE lifts the lock.
#[test]
fn kdf_locked_while_a_key_exists() {
    use crate::common::{attr, crt, import_data};
    let mut card = Card::new();
    card.admin();
    // Factory attestation key status 02 (was 01): docs/MEASUREMENT.md, probe openpgp-get-006e.
    assert_eq!(card.key_status(), [0, 0, 0, 2]);
    let pw3 = s2k256(&SALT_PW3, b"12345678", 64);
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 64, None)), 0x9000);
    assert_eq!(card.verify(0x83, &pw3), 0x9000);

    // A generated AUT key locks F9, also against KDF_NONE and malformed values.
    card.set_attributes(0x00C3, attr::ED25519);
    card.generate(crt::AUT);
    let f9 = card.get_ok(0x00F9);
    let persists = card.host.persist_count();
    for value in [kdf_do(0x0A, 64, None), vec![0x81, 0x01, 0x00], vec![0x81, 0x01, 0x07]] {
        assert_eq!(card.put(0x00F9, &value), 0x6985, "{value:02X?}");
    }
    assert_eq!(card.host.persist_count(), persists);
    assert_eq!(card.get_ok(0x00F9), f9);
    // Nothing changed: PW3 still verified, the PINs are still the hashes.
    assert_eq!(card.verify(0x83, b""), 0x9000);
    assert_eq!(card.verify(0x82, &s2k256(&SALT_PW1, b"123456", 64)), 0x9000);
    // Access is still checked first.
    card.select();
    assert_eq!(card.put(0x00F9, &[0x81, 0x01, 0x00]), 0x6982);

    // Removing the key (attribute change, spec §4.4.3.10) lifts the lock.
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
    card.set_attributes(0x00C3, attr::P256_ECDSA);
    // Factory attestation key status 02 (was 01): docs/MEASUREMENT.md, probe openpgp-get-006e.
    assert_eq!(card.key_status(), [0, 0, 0, 2]);
    assert_eq!(card.put(0x00F9, &[0x81, 0x01, 0x00]), 0x9000);

    // An imported DEC key locks it too.
    card.admin();
    card.set_attributes(0x00C2, attr::X25519);
    assert_eq!(card.import(&import_data(crt::DEC, &[(0x92, &[0x42; 32])])), 0x9000);
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 64, None)), 0x6985);
    assert_eq!(card.get_ok(0x00F9), vec![0x81, 0x01, 0x00]);

    // The application reset removes the user keys and unlocks F9.
    for _ in 0..3 {
        card.verify(0x83, b"wrongpin");
    }
    assert_eq!(card.send(&[0x00, 0xE6, 0x00, 0x00]).1, 0x9000);
    assert_eq!(card.send(&[0x00, 0x44, 0x00, 0x00]).1, 0x9000);
    card.select();
    card.admin();
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 64, None)), 0x9000);
}

/// A storage failure while writing F9 keeps the previous KDF and PINs.
#[test]
fn kdf_storage_failure() {
    let mut card = Card::new();
    card.admin();
    card.host.fail_next_saves(1);
    assert_eq!(card.put(0x00F9, &kdf_do(0x08, 64, None)), 0x6581);
    assert_eq!(card.get_ok(0x00F9), vec![0x81, 0x01, 0x00]);
    assert_eq!(card.verify(0x83, b""), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
}
