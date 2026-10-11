//! Answers measured on a physical YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md): each test
//! replays the APDUs of one probe of `tools/measure/probes.py` and expects the key's
//! answers. Assertions marked "derived" extend a measured rule to a case the read-only
//! probes could not send.

use crate::common::{Card, attr, crt, hex};

/// The PW status bytes C4 of the factory state, as the key returned them.
const PW_STATUS: &str = "017F7F7F030003";

/// Probe `cla-variants-openpgp`: CLA 80 is taken like 00; CLA 10 on GET DATA is a chain
/// part (`9000`, no data); GET RESPONSE during that chain is `6D00`; a SELECT clears it.
#[test]
fn class_variants() {
    let mut card = Card::yubikey();
    assert_eq!(card.send(&hex("80CA00C4")), (hex(PW_STATUS), 0x9000));
    assert_eq!(card.send(&hex("10CA00C4")), (vec![], 0x9000));
    assert_eq!(card.send(&hex("00C0000000")), (vec![], 0x6D00));
    assert_eq!(card.select(), 0x9000);
    assert_eq!(card.send(&hex("00CA00C4")), (hex(PW_STATUS), 0x9000));
    // Derived: the chain was dropped by GET RESPONSE, so the next GET DATA is a plain one.
    assert_eq!(card.send(&hex("10CA00C4")), (vec![], 0x9000));
    assert_eq!(card.send(&hex("00C0000000")), (vec![], 0x6D00));
    assert_eq!(card.send(&hex("00CA00C4")), (hex(PW_STATUS), 0x9000));
    // Derived: a chained GET DATA completed by a plain one answers as usual.
    assert_eq!(card.send(&hex("10CA00C4")), (vec![], 0x9000));
    assert_eq!(card.send(&hex("00CA00C4")), (hex(PW_STATUS), 0x9000));
    // Derived: CLA 80 for other commands (VERIFY status, GET RESPONSE).
    assert_eq!(card.send(&hex("80200081")).1, 0x63C3);
    assert_eq!(card.send(&hex("00CA006E00")).1, 0x613B);
    let (rest, sw) = card.send(&hex("80C0000000"));
    assert_eq!((rest.len(), sw), (59, 0x9000));
    // Unmeasured classes keep 6E00: 90 (80 with the chaining bit), A0.
    assert_eq!(card.send(&hex("90CA00C4")).1, 0x6E00);
    assert_eq!(card.send(&hex("A0CA00C4")).1, 0x6E00);
    // GET ATTESTATION keeps its CLA 80-only rule.
    assert_eq!(card.send(&hex("00FB0100")).1, 0x6E00);
}

/// Probe `get-response-idle-openpgp`: GET RESPONSE with nothing pending is `6D00`.
#[test]
fn get_response_with_nothing_pending_answers_6d00() {
    let mut card = Card::yubikey();
    assert_eq!(card.send(&hex("00C0000000")), (vec![], 0x6D00));
}

/// Probe `chain-61xx`: the 6E response in 61xx pieces of the requested sizes; one more GET
/// RESPONSE after the last piece is `6D00`.
#[test]
fn response_chaining_and_the_end_of_it() {
    let mut card = Card::yubikey();
    let (first, sw) = card.send(&hex("00CA006E00"));
    assert_eq!((first.len(), sw), (256, 0x613B));
    let (part, sw) = card.send(&hex("00C0000010"));
    assert_eq!((part.len(), sw), (16, 0x612B));
    let (last, sw) = card.send(&hex("00C000002B"));
    assert_eq!((last.len(), sw), (43, 0x9000));
    assert_eq!(card.send(&hex("00C0000000")), (vec![], 0x6D00));
    // The tail holds DE with the measured attestation key status (probe chain-61xx).
    assert_eq!(last[6..16], hex("DE08 0100 0200 0300 8102"));
}

/// Probe `openpgp-get-006e`: key information DE reads `01 00 02 00 03 00 81 02`, the
/// factory attestation key reported as imported.
#[test]
fn factory_attestation_key_status_is_imported() {
    for mut card in [Card::yubikey(), Card::new()] {
        assert_eq!(card.get_ok(0x00DE), hex("0100 0200 0300 8102"));
        assert_eq!(card.key_status(), [0, 0, 0, 0x02]);
    }
    // Derived: the issuer's own status does not stop it from attesting a generated key,
    // and it survives a restart.
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01), (vec![], 0x9000));
    assert_eq!(card.key_status(), [0x01, 0, 0, 0x02]);
    card.reload();
    assert_eq!(card.key_status(), [0x01, 0, 0, 0x02]);
}
