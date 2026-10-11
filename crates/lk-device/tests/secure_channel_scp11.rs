//! SCP11a and SCP11c (GlobalPlatform Card Specification v2.3.1 Amendment F, "Amd F")
//! through the device's CCID interface with PIV behind the channel: the OCE
//! certificate chain is presented with PERFORM SECURITY OPERATION, MUTUAL AUTHENTICATE
//! opens the channel while PIV stays selected, and PIV is then driven with wrapped
//! commands while further PSO commands travel inside the channel (catalog
//! SecurityDomain_incremental_pso: "protected PSO preserves ongoing secure messaging
//! and PIV verified PIN; plaintext in an established channel rejects before dispatch
//! and revokes all local authorization", "PIV signatures independently verified after
//! valid/failed protected PSO and complete protected PSO; no real key or manufacturer
//! identity used").
//!
//! The off-card entity here is written from Amd F and Yubico's SDK wire format
//! (yubikit `scp.py`, `securitydomain.py`), like the one in lk-sd's
//! `tests/common/scp11.rs`, and shares no code with `lk-sd`:
//! - provisioning under the factory SCP03 keys (Yubico yk5-apps-scp): PUT KEY of the
//!   OCE CA public key `KVN, B0 41 <point>, F0 01 00, 00` at KID `10` KVN `03`, and of
//!   the SCP11 private keys `KVN, B1 20 <scalar AES-CBC under the DEK>, F0 01 00, 00`
//!   at KID `11` (SCP11a) and `15` (SCP11c), KVN `01`;
//! - PSO `80 2A <CA KVN> <CA KID | 80 while more certificates follow> <certificate>`;
//! - MUTUAL AUTHENTICATE `80 82 <KVN> <KID>` with `A6 { 90 02 11 <i>, 95 01 3C, 80 01
//!   88, 81 01 10 } 5F49 41 <ePK.OCE>` (Amd F §7.6.2.3; `i` = `01` SCP11a, `03`
//!   SCP11c), answered `5F49 41 <ePK.SD or PK.SD> 86 10 <receipt>`;
//! - ShSee = ECDH(eSK.OCE, card point), ShSes = ECDH(SK.OCE, PK.SD); X9.63 KDF with
//!   SHA-256 (BSI TR-03111 §4.3.3) over ShSee || ShSes with SharedInfo `3C 88 10` gives
//!   the receipt key, S-ENC, S-MAC, S-RMAC and S-DEK (Amd F §3.1.2, §6.5.2.3); the
//!   receipt is AES-CMAC(receipt key, request data || card `5F49` object) and the first
//!   MAC chaining value of the session.
//!
//! Every key is a fixed test scalar; nothing is a real key or a manufacturer identity.
//! PIV signatures are checked with `ecdsa_verify_prehash` against the public point that
//! GENERATE returned.

#![allow(clippy::unwrap_used)]

mod common;

use common::iso::{command, find_tlv, piv, tlv};
use common::*;
use lk_codec::x509::{self, Extension, Name, PublicKey, SignatureAlgorithm, TbsCertificate, Validity, key_usage};
use lk_crypto::{Curve, EcPrivateKey, HashAlg, ecdsa_verify_prehash, sha256};

/// The OCE CA public key reference (KID `10`, KVN `03`).
const CA_KID: u8 = 0x10;
const CA_KVN: u8 = 0x03;
/// Key version of the SCP11 private keys.
const SCP11_KVN: u8 = 0x01;

/// The two SCP11 variants that need an OCE certificate (Amd F §2.2: SCP11a and SCP11c
/// authenticate the OCE; yubikit `ScpKid.SCP11a = 0x11`, `SCP11c = 0x15`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    A,
    C,
}

impl Variant {
    const ALL: [Variant; 2] = [Variant::A, Variant::C];

    fn kid(self) -> u8 {
        match self {
            Variant::A => 0x11,
            Variant::C => 0x15,
        }
    }

    /// The `i` parameter of the control reference template (yubikit `scp.py`).
    fn parameter(self) -> u8 {
        match self {
            Variant::A => 0x01,
            Variant::C => 0x03,
        }
    }
}

/// A P-256 key from 32 consecutive byte values starting at `start` (far below the
/// group order for every start used here).
fn key_from(start: u8) -> EcPrivateKey {
    let scalar: Vec<u8> = (0..32u8).map(|i| start.wrapping_add(i)).collect();
    EcPrivateKey::from_scalar(Curve::P256, &scalar).unwrap()
}

/// ANSI X9.63 KDF with SHA-256 (BSI TR-03111 §4.3.3).
fn x963(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < len {
        let block = [z, &counter.to_be_bytes(), shared_info].concat();
        out.extend_from_slice(&sha256(&block));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// The OCE's PKI: a root CA (its public key is stored on the card as the CA key), an
/// intermediate CA, the OCE leaf (key agreement), and an intermediate certificate whose
/// signature does not verify.
struct Oce {
    ca: EcPrivateKey,
    leaf: EcPrivateKey,
    chain: Vec<Vec<u8>>,
    forged_intermediate: Vec<u8>,
}

/// A certificate (RFC 5280 §4.1) for `subject_key`, signed with `issuer_key` using
/// ecdsa-with-SHA256: critical basicConstraints and keyUsage (keyCertSign for a CA,
/// keyAgreement for the leaf, as Amd F requires of the OCE certificate), SKI and AKI.
#[allow(clippy::too_many_arguments)]
fn certificate(serial: &[u8], issuer: &str, subject: &str, ca: Option<u32>, ski: Option<&[u8]>, aki: &[u8], subject_key: &EcPrivateKey, issuer_key: &EcPrivateKey) -> Vec<u8> {
    let mut extensions = vec![
        Extension::basic_constraints(ca.is_some(), ca),
        Extension::key_usage(if ca.is_some() { key_usage::KEY_CERT_SIGN } else { key_usage::KEY_AGREEMENT }),
    ];
    if let Some(ski) = ski {
        extensions.push(Extension::subject_key_identifier(ski));
    }
    extensions.push(Extension::authority_key_identifier(aki));
    let tbs = TbsCertificate {
        serial: serial.to_vec(),
        signature: SignatureAlgorithm::EcdsaWithSha256,
        issuer: Name::new().common_name(issuer),
        validity: Validity::rfc5280("20250101000000Z", "20450101000000Z").unwrap(),
        subject: Name::new().common_name(subject),
        public_key: PublicKey::EcP256(subject_key.public_uncompressed()),
        extensions,
    }
    .to_der();
    let signature = issuer_key.sign_message(HashAlg::Sha256, &tbs).unwrap().to_der();
    x509::assemble(&tbs, SignatureAlgorithm::EcdsaWithSha256, &signature)
}

fn oce() -> Oce {
    let ca = key_from(0xC1);
    let intermediate = key_from(0x11);
    let leaf = key_from(0x81);
    let (root_ski, inter_ski) = ([0xAA, 1, 1, 1], [0xBB, 2, 2, 2]);
    let root = certificate(&[0x80, 0, 0, 1], "OCE Root", "OCE Root", Some(1), Some(&root_ski), &root_ski, &ca, &ca);
    let inter = certificate(&[0x80, 0, 0, 2], "OCE Root", "OCE Intermediate", Some(0), Some(&inter_ski), &root_ski, &intermediate, &ca);
    let leaf_cert = certificate(&[3, 0, 3], "OCE Intermediate", "OCE", None, None, &inter_ski, &leaf, &intermediate);
    // Claims the root as issuer but is signed by an unrelated key.
    let forged_intermediate = certificate(&[0x80, 0, 0, 9], "OCE Root", "OCE Intermediate", Some(0), Some(&inter_ski), &root_ski, &intermediate, &key_from(0x31));
    Oce { ca, leaf, chain: vec![root, inter, leaf_cert], forged_intermediate }
}

/// Provision the Security Domain under an SCP03 session with the factory keys: the
/// OCE CA key and one SCP11 key (scalar `61..80`) for each variant. Returns PK.SD.
fn provision(rig: &mut Rig, oce: &Oce) -> Vec<u8> {
    assert_eq!(sw(&rig.select(AID_SD)), 0x9000);
    let mut admin = Scp03::open(rig);
    let ca_data = [vec![CA_KVN], tlv(0xB0, &oce.ca.public_uncompressed()), vec![0xF0, 0x01, 0x00, 0x00]].concat();
    let put = admin.wrap(0x80, 0xD8, 0x00, CA_KID, &ca_data, Some(0));
    assert_eq!(admin.unwrap(&rig.apdu(&put)), (vec![CA_KVN], 0x9000), "PUT KEY OCE CA");
    let sd_key = key_from(0x61);
    let encrypted = lk_crypto::aes_cbc_encrypt(&admin.dek, &[0; 16], sd_key.scalar()).unwrap();
    let key_data = [vec![SCP11_KVN], tlv(0xB1, &encrypted), vec![0xF0, 0x01, 0x00, 0x00]].concat();
    for variant in Variant::ALL {
        let put = admin.wrap(0x80, 0xD8, 0x00, variant.kid(), &key_data, Some(0));
        assert_eq!(admin.unwrap(&rig.apdu(&put)), (vec![SCP11_KVN], 0x9000), "PUT KEY {variant:?}");
    }
    sd_key.public_uncompressed()
}

/// The PSO commands for a chain (yubikit `scp.py`): P2 carries `80` on every
/// certificate but the last.
fn pso(certificate: &[u8], last: bool) -> (u8, u8, u8, u8, &[u8]) {
    (0x80, 0x2A, CA_KVN, CA_KID | if last { 0x00 } else { 0x80 }, certificate)
}

/// A prepared MUTUAL AUTHENTICATE: its data field and the OCE ephemeral key.
struct Request {
    data: Vec<u8>,
    esk: EcPrivateKey,
}

fn request(variant: Variant, esk_start: u8) -> Request {
    let esk = key_from(esk_start);
    let mut data = vec![0xA6, 0x0D, 0x90, 0x02, 0x11, variant.parameter(), 0x95, 0x01, 0x3C, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10];
    data.extend_from_slice(&[0x5F, 0x49, 0x41]);
    data.extend_from_slice(&esk.public_uncompressed());
    Request { data, esk }
}

impl Request {
    /// Check the card's answer (`data || 9000`) with the receipt and derive the session.
    fn finish(&self, response: &[u8], pk_sd: &[u8], sk_oce: &EcPrivateKey) -> Scp03 {
        assert_eq!(response.len(), 86 + 2, "{response:02X?}");
        assert_eq!(&response[86..], &[0x90, 0x00]);
        assert_eq!(&response[..3], &[0x5F, 0x49, 0x41]);
        assert_eq!(&response[68..70], &[0x86, 0x10]);
        let card_point = &response[3..68];
        let sh_see = self.esk.ecdh(card_point).unwrap();
        let sh_ses = sk_oce.ecdh(pk_sd).unwrap();
        let keys = x963(&[sh_see.as_slice(), sh_ses.as_slice()].concat(), &[0x3C, 0x88, 0x10], 80);
        let key = |i: usize| -> [u8; 16] { keys[i * 16..(i + 1) * 16].try_into().unwrap() };
        let receipt: [u8; 16] = response[70..86].try_into().unwrap();
        let input = [self.data.as_slice(), &response[..68]].concat();
        assert_eq!(lk_crypto::aes_cmac(&key(0), &input).unwrap(), receipt, "receipt");
        Scp03::from_scp11(key(1), key(2), key(3), receipt, key(4))
    }
}

/// The scenario's starting point: the Security Domain provisioned, PIV selected with a
/// P-256 key generated in slot `9A` (PIN policy "once"), the OCE chain presented in
/// plaintext, an SCP11 session opened with PIV still selected, and the PIV PIN
/// verified inside it.
struct Setup {
    rig: Rig,
    session: Scp03,
    oce: Oce,
    pk_sd: Vec<u8>,
    point: Vec<u8>,
}

fn setup(variant: Variant) -> Setup {
    let mut rig = Rig::new();
    rig.power_on();
    let oce = oce();
    let pk_sd = provision(&mut rig, &oce);
    // The plaintext SELECT ends the SCP03 session.
    assert_eq!(sw(&rig.select(AID_PIV)), 0x9000);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let point = rig.piv_generate_p256(piv::SLOT_AUTH, None);
    let last = oce.chain.len() - 1;
    for (i, cert) in oce.chain.iter().enumerate() {
        let (cla, ins, p1, p2, data) = pso(cert, i == last);
        assert_eq!(rig.apdu(&command(cla, ins, p1, p2, data, None)), vec![0x90, 0x00], "plaintext PSO {i}");
    }
    let req = request(variant, 0x41);
    let response = rig.apdu(&command(0x80, 0x82, SCP11_KVN, variant.kid(), &req.data, None));
    let mut session = req.finish(&response, &pk_sd, &oce.leaf);
    let verify = session.wrap(0x00, 0x20, 0x00, piv::PIN, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000), "{variant:?}: VERIFY inside the channel");
    Setup { rig, session, oce, pk_sd, point }
}

impl Setup {
    /// A protected PSO; its status after the R-MAC check (error statuses come bare,
    /// Amd D §6.2.5).
    fn protected_pso(&mut self, certificate: &[u8], last: bool) -> u16 {
        let (cla, ins, p1, p2, data) = pso(certificate, last);
        let wrapped = self.session.wrap_extended(cla, ins, p1, p2, data, None);
        let (data, status) = self.session.unwrap(&self.rig.apdu(&wrapped));
        assert!(data.is_empty());
        status
    }

    /// Present the whole chain inside the channel.
    fn protected_chain(&mut self) {
        let chain = self.oce.chain.clone();
        let last = chain.len() - 1;
        for (i, cert) in chain.iter().enumerate() {
            assert_eq!(self.protected_pso(cert, i == last), 0x9000, "protected PSO {i}");
        }
    }

    /// The wrapped PIV VERIFY status query (SP 800-73-4 Part 2 §3.2.1: no data field):
    /// `9000` while the PIN is verified; the response's R-MAC shows the channel is still
    /// in step.
    fn pin_status(&mut self) -> u16 {
        let query = self.session.wrap(0x00, 0x20, 0x00, piv::PIN, &[], None);
        let (data, status) = self.session.unwrap(&self.rig.apdu(&query));
        assert!(data.is_empty());
        status
    }

    /// A wrapped GENERAL AUTHENTICATE signature with the slot `9A` key (Part 2 §3.2.4,
    /// Appendix A.4: `7C { 82 00, 81 digest }`), verified against the generated point.
    fn sign_and_verify(&mut self, message: &[u8]) {
        let digest = sha256(message);
        let inner = [tlv(0x82, &[]), tlv(0x81, &digest)].concat();
        let sign = self.session.wrap(0x00, 0x87, piv::ALG_ECCP256, piv::SLOT_AUTH, &tlv(0x7C, &inner), Some(0));
        let (data, status) = self.session.unwrap(&self.rig.apdu(&sign));
        assert_eq!(status, 0x9000, "signature after {:?}", String::from_utf8_lossy(message));
        let signature = find_tlv(&find_tlv(&data, 0x7C).unwrap(), 0x82).unwrap();
        assert!(ecdsa_verify_prehash(Curve::P256, &self.point, &digest, &signature), "signature verifies");
    }

    /// A protected MUTUAL AUTHENTICATE (catalog SecurityDomain_handoff): answered under
    /// the current session, after which the new session replaces it.
    fn protected_handoff(&mut self, variant: Variant) {
        let req = request(variant, 0x51);
        let wrapped = self.session.wrap(0x80, 0x82, SCP11_KVN, variant.kid(), &req.data, None);
        let (data, status) = self.session.unwrap(&self.rig.apdu(&wrapped));
        assert_eq!(status, 0x9000, "{variant:?}: protected MUTUAL AUTHENTICATE");
        let response = [data, vec![0x90, 0x00]].concat();
        self.session = req.finish(&response, &self.pk_sd, &self.oce.leaf);
    }
}

/// Catalog SecurityDomain_incremental_pso: "protected PSO preserves ongoing secure
/// messaging and PIV verified PIN; plaintext in an established channel rejects before
/// dispatch and revokes all local authorization". For SCP11a and SCP11c: the PIN
/// verified inside the channel stays verified, and every later wrapped exchange passes
/// its R-MAC check, after a valid protected PSO, after one whose certificate fails its
/// signature check (`6982`, returned bare: Amd D §6.2.5), after the complete chain
/// inside the channel and after the protected MUTUAL AUTHENTICATE that uses it. Then a
/// plaintext VERIFY with a wrong PIN is refused by the channel (`6982`) without
/// reaching PIV (the retry counter stays at 3), the channel is gone (a wrapped command
/// reaches PIV with its secure-messaging bits, `6882`), and so is the PIN verification
/// (Yubico yk5-apps-scp: "Sending a command in plain text will not be accepted and
/// immediately ends the session").
#[test]
fn protected_pso_keeps_secure_messaging_and_the_piv_pin_until_plaintext_ends_the_channel() {
    for variant in Variant::ALL {
        let mut s = setup(variant);
        assert_eq!(s.pin_status(), 0x9000, "{variant:?}: verified");

        let root = s.oce.chain[0].clone();
        assert_eq!(s.protected_pso(&root, false), 0x9000, "{variant:?}: valid protected PSO");
        assert_eq!(s.pin_status(), 0x9000, "{variant:?}: after a valid protected PSO");

        let forged = s.oce.forged_intermediate.clone();
        assert_eq!(s.protected_pso(&forged, false), 0x6982, "{variant:?}: failed protected PSO");
        assert_eq!(s.pin_status(), 0x9000, "{variant:?}: after a failed protected PSO");

        s.protected_chain();
        assert_eq!(s.pin_status(), 0x9000, "{variant:?}: after a complete protected PSO");

        s.protected_handoff(variant);
        assert_eq!(s.pin_status(), 0x9000, "{variant:?}: after the protected handoff");

        let wrong = command(0x00, 0x20, 0x00, piv::PIN, &piv::pin_block("000000"), None);
        assert_eq!(s.rig.apdu(&wrong), vec![0x69, 0x82], "{variant:?}: plaintext refused by the channel");
        let query = s.session.wrap(0x00, 0x20, 0x00, piv::PIN, &[], None);
        assert_eq!(s.rig.apdu(&query), vec![0x68, 0x82], "{variant:?}: no channel unwraps it any more");
        assert_eq!(
            s.rig.apdu(&[0x00, 0x20, 0x00, piv::PIN]),
            vec![0x63, 0xC3],
            "{variant:?}: PIN no longer verified, and the refused VERIFY used no try"
        );
    }
}

/// Catalog SecurityDomain_incremental_pso: "PIV signatures independently verified
/// after valid/failed protected PSO and complete protected PSO; no real key or
/// manufacturer identity used". For SCP11a and SCP11c, a wrapped GENERAL AUTHENTICATE
/// with the slot `9A` key verifies against the GENERATE point right after the channel
/// opens, after a valid protected PSO, after a failed one, after the complete chain
/// inside the channel and under the session that the protected MUTUAL AUTHENTICATE
/// opened. Ending the channel with a plaintext command revokes the PIN, so a plaintext
/// signature request is then refused (`6982`, SP 800-73-4 Part 2 §3.2.4: the key
/// needs the PIN) until the PIN is verified again.
#[test]
fn piv_signatures_verify_after_valid_failed_and_complete_protected_pso() {
    for variant in Variant::ALL {
        let mut s = setup(variant);
        s.sign_and_verify(b"right after MUTUAL AUTHENTICATE");

        let root = s.oce.chain[0].clone();
        assert_eq!(s.protected_pso(&root, false), 0x9000);
        s.sign_and_verify(b"after a valid protected PSO");

        let forged = s.oce.forged_intermediate.clone();
        assert_eq!(s.protected_pso(&forged, false), 0x6982);
        s.sign_and_verify(b"after a failed protected PSO");

        s.protected_chain();
        s.sign_and_verify(b"after a complete protected PSO");

        s.protected_handoff(variant);
        s.sign_and_verify(b"under the handed-off session");

        assert_eq!(s.rig.apdu(&[0x00, 0xCB, 0x3F, 0xFF]), vec![0x69, 0x82], "{variant:?}: plaintext ends the channel");
        let request = Rig::piv_sign_request(piv::SLOT_AUTH, &sha256(b"in plaintext"));
        assert_eq!(sw(&s.rig.apdu(&request)), 0x6982, "{variant:?}: the PIN went with the channel");
        assert_eq!(s.rig.piv_verify("123456"), 0x9000);
        let signature = Rig::piv_signature(&s.rig.apdu(&request));
        assert!(ecdsa_verify_prehash(Curve::P256, &s.point, &sha256(b"in plaintext"), &signature));
    }
}
