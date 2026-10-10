//! User interaction flags D6-D9 (Yubico OpenPGP touch policy: 00 off, 01 on, 02 fixed,
//! 03 cached, 04 cached-fixed; the cache lasts 15 seconds) through `Outcome::NeedTouch`
//! and `CardApplet::touch_resolved` (lk-core applet contract).

use lk_core::{CardApplet, Outcome, ResetKind};
use lk_crypto::ed25519_verify;

use crate::common::{Card, Public, attr, cipher_do, crt, hex, import_data, parse_public, rsa_primes, split};

/// A card with Ed25519 SIG/AUT and X25519 DEC keys, both PW1 modes verified, and the given
/// UIF on SIG.
fn card_with_keys(sig_uif: u8) -> (Card, Vec<u8>) {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.set_attributes(0x00C2, attr::X25519);
    card.set_attributes(0x00C3, attr::ED25519);
    let Public::Point(sig) = parse_public(&card.generate(crt::SIG)) else { panic!() };
    card.generate(crt::DEC);
    card.generate(crt::AUT);
    assert_eq!(card.put(0x00D6, &[sig_uif, 0x20]), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    (card, sig)
}

fn sign_apdu(message: &[u8]) -> Vec<u8> {
    Card::ext_bytes(0x2A, 0x9E, 0x9A, message)
}

/// UIF 01: every signature waits for a touch; the signature comes from `touch_resolved`.
#[test]
fn uif_on_requires_touch_for_each_signature() {
    let (mut card, public) = card_with_keys(0x01);
    let (signature, sw) = card.send_touch(&sign_apdu(b"one"), true);
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&public, b"one", &signature));
    assert_eq!(card.signature_counter(), 1);
    let (_, sw) = card.send_touch(&sign_apdu(b"two"), true);
    assert_eq!(sw, 0x9000);
    assert_eq!(card.signature_counter(), 2);
}

/// Without a touch (timeout or cancel) the answer is 6982 and nothing changes: no counter
/// step and no use of the single-signature PW1 verification.
#[test]
fn touch_denied_answers_6982_and_changes_nothing() {
    let (mut card, _) = card_with_keys(0x02);
    card.admin();
    assert_eq!(card.put(0x00C4, &[0x00]), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let persists = card.host.persist_count();
    assert_eq!(card.send_touch(&sign_apdu(b"m"), false), (vec![], 0x6982));
    assert_eq!(card.host.persist_count(), persists);
    assert_eq!(card.signature_counter(), 0);
    assert_eq!(card.send_touch(&sign_apdu(b"m"), true).1, 0x9000);
    assert_eq!(card.signature_counter(), 1);
}

/// UIF 03: a touch is cached for 15 s; at 15 000 ms it must be renewed.
#[test]
fn cached_touch_lasts_15_seconds() {
    let (mut card, _) = card_with_keys(0x03);
    card.host.set_now(1_000);
    assert_eq!(card.send_touch(&sign_apdu(b"a"), true).1, 0x9000);
    card.host.advance(14_999);
    assert_eq!(card.send(&sign_apdu(b"b")).1, 0x9000);
    card.host.advance(1);
    assert_eq!(card.send_touch(&sign_apdu(b"c"), true).1, 0x9000);
    // The cache is per key: AUT with UIF 03 needs its own touch.
    assert_eq!(card.put_admin(0x00D8, &[0x03, 0x20]), 0x9000);
    let auth = Card::ext_bytes(0x88, 0x00, 0x00, b"challenge");
    assert_eq!(card.send_touch(&auth, true).1, 0x9000);
    assert_eq!(card.send(&auth).1, 0x9000);
    // A denied touch does not refresh anything.
    card.host.advance(15_000);
    assert_eq!(card.send_touch(&sign_apdu(b"d"), false).1, 0x6982);
    assert_eq!(card.send_touch(&sign_apdu(b"e"), true).1, 0x9000);
}

/// The cache survives SELECT and card power-off but not a power cycle (model policy).
#[test]
fn cached_touch_cleared_by_power_cycle() {
    let (mut card, _) = card_with_keys(0x04);
    assert_eq!(card.send_touch(&sign_apdu(b"a"), true).1, 0x9000);
    card.app.reset(ResetKind::CardPowerOff);
    card.select();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.send(&sign_apdu(b"b")).1, 0x9000);
    card.app.reset(ResetKind::PowerCycle);
    card.select();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.send_touch(&sign_apdu(b"c"), true).1, 0x9000);
}

/// D7 governs PSO:DECIPHER, D8 INTERNAL AUTHENTICATE and D9 GET ATTESTATION.
#[test]
fn uif_for_decipher_authenticate_and_attest() {
    let (mut card, _) = card_with_keys(0x00);
    for tag in [0x00D7, 0x00D8, 0x00D9] {
        assert_eq!(card.put_admin(tag, &[0x01, 0x20]), 0x9000);
    }
    let peer = lk_crypto::X25519Key::generate(&mut lk_testkit::SeededEntropy::new(3));
    let decipher = Card::ext_bytes(0x2A, 0x80, 0x86, &cipher_do(&peer.public()));
    let (shared, sw) = card.send_touch(&decipher, true);
    assert_eq!((shared.len(), sw), (32, 0x9000));
    let auth = Card::ext_bytes(0x88, 0x00, 0x00, b"challenge");
    assert_eq!(card.send_touch(&auth, true).1, 0x9000);
    // Signing (D6 = 00) needs no touch.
    assert_eq!(card.send(&sign_apdu(b"free")).1, 0x9000);
    let before = card.certificate(2);
    assert_eq!(card.send_touch(&[0x80, 0xFB, 0x01, 0x00], false), (vec![], 0x6982));
    assert_eq!(card.certificate(2), before);
    assert_eq!(card.send_touch(&[0x80, 0xFB, 0x01, 0x00], true), (vec![], 0x9000));
    assert_ne!(card.certificate(2), before);
}

/// The touch is requested only after access and input checks pass: a request that would
/// fail answers at once.
#[test]
fn touch_requested_after_access_and_input_checks() {
    let (mut card, _) = card_with_keys(0x01);
    card.select();
    assert_eq!(card.send(&sign_apdu(b"m")).1, 0x6982);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.send(&sign_apdu(b"")).1, 0x6700);
    assert_eq!(card.send(&hex("00 2A 9E9A 01 55 10")).1, 0x6700);
    assert_eq!(card.send_touch(&sign_apdu(b"m"), true).1, 0x9000);
}

/// A waiting operation is abandoned by any other command or by SELECT; resolving it later
/// answers 6985 and changes nothing.
#[test]
fn pending_touch_abandoned_by_other_commands() {
    let (mut card, _) = card_with_keys(0x01);
    assert!(matches!(card.process(&sign_apdu(b"m")), Outcome::NeedTouch { .. }));
    assert_eq!(card.get(0x5F52).1, 0x9000);
    assert_eq!(split(card.app.touch_resolved(true, &mut card.host)), (vec![], 0x6985));
    assert!(matches!(card.process(&sign_apdu(b"m")), Outcome::NeedTouch { .. }));
    card.select();
    assert_eq!(split(card.app.touch_resolved(true, &mut card.host)), (vec![], 0x6985));
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert!(matches!(card.process(&sign_apdu(b"m")), Outcome::NeedTouch { .. }));
    card.app.deselect();
    assert_eq!(split(card.app.touch_resolved(true, &mut card.host)), (vec![], 0x6985));
    assert_eq!(card.signature_counter(), 0);
}

/// A long result after a touch is served in 61xx chunks of the original command's Ne.
#[test]
fn long_response_after_touch_is_chunked() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::RSA3072);
    let (p, q) = rsa_primes(3072);
    let e: &[u8] = &[1, 0, 1];
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x91, e), (0x92, &p), (0x93, &q)])), 0x9000);
    assert_eq!(card.put(0x00D6, &[0x01, 0x20]), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let mut apdu = hex("00 2A 9E9A 20");
    apdu.extend_from_slice(&[0x5A; 32]);
    apdu.push(0x00);
    let (first, sw) = card.send_touch(&apdu, true);
    assert_eq!((first.len(), sw), (256, 0x6180));
    let (rest, sw) = card.send(&hex("00C0000080"));
    assert_eq!((rest.len(), sw), (128, 0x9000));
}

impl Card {
    fn put_admin(&mut self, tag: u16, value: &[u8]) -> u16 {
        self.admin();
        self.put(tag, value)
    }
}
