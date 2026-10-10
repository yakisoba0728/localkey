//! Host request shapes, byte for byte, of GnuPG's scdaemon (`scd/app-openpgp.c`,
//! `scd/iso7816.c`), OpenSC (`card-openpgp.c`) and yubikit (`yubikit/openpgp.py`), checked
//! against the crate's framing and Le rules. The second independent review added these;
//! each test names the host function whose APDU it reproduces.
//!
//! GnuPG's Le values (`scd/app-openpgp.c`, `scd/iso7816.c`):
//! - GENERATE P1 80 and P1 81 for RSA above 1952 bits (`RSA_SMALL_SIZE_KEY`): extended
//!   APDU, Le = `determine_rsa_response` = 2 + 3 + 4 + n/8 + 2 + ceil(e_bits/8), with
//!   e_bits from the card's attributes (17 here, so 3 bytes): 270, 398 and 526 for RSA
//!   2048/3072/4096. That is exactly the length of 7F49, so the crate's Le guard
//!   (operations.rs) must accept Le equal to the result.
//! - PSO:CDS and INTERNAL AUTHENTICATE for RSA above 2048 bits (`RSA_SMALL_SIZE_OP`):
//!   extended, Le = n/8 exactly; otherwise short with Le 00 (256).
//! - SELECT DATA: `00 A5 <occurrence> 04 06 60 04 5C 02 7F 21` with Le 00
//!   (`iso7816_select_data`).

use lk_crypto::RsaPrivateKey;

use crate::common::{Card, Public, crt, digest_info_sha256, hex, import_data, parse_public, rsa_primes, rsa_verify};

const E: &[u8] = &[0x01, 0x00, 0x01];

/// GnuPG `determine_rsa_response`: header 2 + 3, modulus 4 + n/8, exponent 2 + e/8.
fn gnupg_rsa_response(bits: usize, e_bits: usize) -> usize {
    2 + 3 + 4 + bits.div_ceil(8) + 2 + e_bits.div_ceil(8)
}

/// An extended-length APDU with an explicit Le (ISO 7816-4 §5.1).
fn extended(ins: u8, p1: u8, p2: u8, data: &[u8], le: u32) -> Vec<u8> {
    let mut cmd = lk_codec::apdu::Command::new(0x00, ins, p1, p2).with_data(data.to_vec());
    cmd.le = Some(le);
    cmd.extended = true;
    cmd.to_bytes()
}

/// GnuPG `do_genkey` / `get_public_key` for RSA 2048: GENERATE with extended Le 270, the
/// exact length of the public key DO; one byte less is refused before the key changes
/// (catalog "GENERATE ... Le mutation guards").
#[test]
fn gnupg_generate_rsa2048_with_exact_le() {
    let mut card = Card::new();
    card.admin();
    let le = gnupg_rsa_response(2048, 17);
    assert_eq!(le, 270);
    let crt_sig: &[u8] = &[0xB6, 0x00];
    let (short, sw) = card.send(&extended(0x47, 0x80, 0x00, crt_sig, (le - 1) as u32));
    assert_eq!((short, sw), (vec![], 0x6700));
    assert_eq!(card.key_status()[0], 0x00);
    let (template, sw) = card.send(&extended(0x47, 0x80, 0x00, crt_sig, le as u32));
    assert_eq!((template.len(), sw), (le, 0x9000));
    // Reading it back the way GnuPG's get_public_key does.
    assert_eq!(card.send(&extended(0x47, 0x81, 0x00, crt_sig, le as u32)), (template, 0x9000));
}

/// GnuPG's Le for RSA 3072 and 4096 equals the crate's 7F49 length too (so GENERATE P1 80
/// with that Le passes the guard); and GnuPG `do_sign` / `do_auth` with extended Le = n/8
/// get the whole signature.
#[test]
fn gnupg_rsa3072_and_4096_le_values() {
    for (bits, signature_slot) in [(3072usize, crt::SIG), (4096, crt::AUT)] {
        let mut card = Card::new();
        card.admin();
        let (tag, attributes) = if bits == 3072 { (0x00C1, "01 0C00 0011 00") } else { (0x00C3, "01 1000 0011 00") };
        card.set_attributes(tag, attributes);
        let (p, q) = rsa_primes(bits);
        let import = import_data(signature_slot, &[(0x91, E), (0x92, &p), (0x93, &q)]);
        assert_eq!(card.import(&import), 0x9000, "{bits}");
        let le = gnupg_rsa_response(bits, 17);
        let (template, sw) = card.send(&extended(0x47, 0x81, 0x00, signature_slot, le as u32));
        assert_eq!((template.len(), sw), (le, 0x9000), "{bits}");

        let key = RsaPrivateKey::from_primes(&p, &q, E).unwrap();
        let input = digest_info_sha256(b"gnupg");
        let apdu = if bits == 3072 {
            assert_eq!(card.verify(0x81, b"123456"), 0x9000);
            extended(0x2A, 0x9E, 0x9A, &input, (bits / 8) as u32)
        } else {
            assert_eq!(card.verify(0x82, b"123456"), 0x9000);
            extended(0x88, 0x00, 0x00, &input, (bits / 8) as u32)
        };
        let (signature, sw) = card.send(&apdu);
        assert_eq!((signature.len(), sw), (bits / 8, 0x9000), "{bits}");
        assert!(rsa_verify(&key.modulus(), &key.public_exponent(), &input, &signature), "{bits}");
    }
}

/// GnuPG `iso7816_select_data` and OpenSC `pgp_select_data` send the standard tag list
/// `60 04 5C 02 7F 21` (GnuPG with Le 00); yubikit adds a leading length byte only for
/// firmware up to 5.4.3, which this 5.7.4 card does not need to accept.
#[test]
fn gnupg_and_opensc_select_data_forms() {
    let mut card = Card::new();
    card.admin();
    for (occurrence, value) in [(0u8, &b"aut"[..]), (1, b"dec"), (2, b"sig")] {
        let mut apdu = hex("00A5 0004 06 6004 5C02 7F21 00");
        apdu[2] = occurrence;
        assert_eq!(card.send(&apdu).1, 0x9000);
        assert_eq!(card.put(0x7F21, value), 0x9000);
    }
    for (occurrence, value) in [(0u8, &b"aut"[..]), (1, b"dec"), (2, b"sig")] {
        let mut apdu = hex("00A5 0004 06 6004 5C02 7F21");
        apdu[2] = occurrence;
        assert_eq!(card.send(&apdu).1, 0x9000);
        assert_eq!(card.get_ok(0x7F21), value);
    }
    // The pre-5.4.4 yubikit form (leading 06) is not a tag list.
    assert_eq!(card.send(&hex("00A5 0204 07 06 6004 5C02 7F21")).1, 0x6A80);
}

/// GnuPG `change_rsa_keyattr` keeps the card's exponent length when it changes an RSA
/// size (`01 1000 0011 00`) but writes `00 20` (32 bits) when it switches a slot from ECC
/// back to RSA, and OpenSC `pgp_update_new_algo_attr` always writes
/// `SC_OPENPGP_MAX_EXP_BITS` = `00 20`. The crate accepts exponent lengths of 17 to 32 bits
/// for every advertised RSA size and stores the value as written (model policy,
/// `objects::RSA_E_BITS`; a physical 5.7.4's answer is unmeasured). GnuPG then sizes Le
/// and the imported e from the 32 bits it reads back (`determine_rsa_response`,
/// `build_privkey_template`): GENERATE with that Le gets 7F49 with e = 65537, and an
/// import with e right-justified in 4 bytes signs verifiably.
#[test]
fn rsa_attributes_with_32_bit_exponent_length_are_accepted() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, "16 2b06010401da470f01");
    card.generate(crt::SIG);
    assert_eq!(card.put(0x00C1, &hex("01 0800 0020 00")), 0x9000);
    assert_eq!(card.get_ok(0x00C1), hex("01 0800 0020 00"));
    assert_eq!(card.key_status()[0], 0x00, "the Ed25519 key left with its algorithm");
    let le = gnupg_rsa_response(2048, 32);
    let (template, sw) = card.send(&extended(0x47, 0x80, 0x00, &[0xB6, 0x00], le as u32));
    assert_eq!(sw, 0x9000);
    let Public::Rsa { n, e } = parse_public(&template) else { panic!("RSA public key expected") };
    assert_eq!((n.len(), e.as_slice()), (256, E));
    let (p, q) = rsa_primes(2048);
    let four_byte_e: &[u8] = &[0x00, 0x01, 0x00, 0x01];
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x91, four_byte_e), (0x92, &p), (0x93, &q)])), 0x9000);
    let key = RsaPrivateKey::from_primes(&p, &q, E).unwrap();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let input = digest_info_sha256(b"m");
    let (signature, sw) = card.sign(&input);
    assert_eq!(sw, 0x9000);
    assert!(rsa_verify(&key.modulus(), E, &input, &signature));
    // Below e = 65537's 17 bits or above 32 bits is still refused and changes nothing.
    for attributes in ["01 0800 0010 00", "01 0800 0021 00"] {
        assert_eq!(card.put(0x00C1, &hex(attributes)), 0x6A80, "{attributes}");
    }
    assert_eq!(card.get_ok(0x00C1), hex("01 0800 0020 00"));
    assert_eq!(card.key_status()[0], 0x02, "the imported key stays");
    card.reload();
    assert_eq!(card.get_ok(0x00C1), hex("01 0800 0020 00"), "kept across a restart");
    assert_eq!(card.key_status()[0], 0x02);
}
