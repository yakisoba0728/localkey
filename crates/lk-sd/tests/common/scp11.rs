//! An independent SCP11 off-card entity (OCE) for the integration tests.
//!
//! Written from GlobalPlatform Card Specification v2.3.1 Amendment F (SCP11) and the
//! wire format of Yubico's SDK (yubikit `scp.py`), without using any `lk-sd` code:
//! - request: `A6 { 90 02 11 <i>, 95 01 3C, 80 01 88, 81 01 10 } 5F49 41 <ePK.OCE>`,
//!   `i` = `01` (a), `00` (b), `03` (c); INTERNAL AUTHENTICATE `80 88` for b, MUTUAL
//!   AUTHENTICATE `80 82` for a/c, P1 = KVN, P2 = KID;
//! - host key agreement: ShSee = ECDH(eSK.OCE, ePK.SD), ShSes = ECDH(SK.OCE, PK.SD)
//!   (SK.OCE = eSK.OCE for b); X9.63 KDF with SHA-256 over ShSee || ShSes, SharedInfo
//!   `3C 88 10`, 80 bytes = receipt key, S-ENC, S-MAC, S-RMAC, S-DEK;
//! - receipt = AES-CMAC(receipt key, request data || card `5F49` object), checked; it is
//!   the first MAC chaining value of the session (then SCP03 secure messaging).
//!
//! Only `lk_crypto` primitives are shared with the card. Certificates for the OCE
//! chains are built with `lk_codec::x509` (a builder the card does not use for parsing)
//! and read back here with a small DER walker of this file.

#![allow(dead_code, clippy::unwrap_used)]

use lk_codec::der;
use lk_codec::x509::{self, Extension, Name, PublicKey, SignatureAlgorithm, TbsCertificate, Validity, key_usage};
use lk_crypto::{Curve, EcPrivateKey, HashAlg};

use super::{HostSession, cmac, encode_apdu};

/// A P-256 key from 32 consecutive byte values starting at `start` (valid for every
/// start used here: the value is far below the group order).
pub fn key_from(start: u8) -> EcPrivateKey {
    let scalar: Vec<u8> = (0..32u8).map(|i| start.wrapping_add(i)).collect();
    EcPrivateKey::from_scalar(Curve::P256, &scalar).unwrap()
}

/// ANSI X9.63 KDF, SHA-256 (BSI TR-03111 §4.3.3).
pub fn x963(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < len {
        let mut block = z.to_vec();
        block.extend_from_slice(&counter.to_be_bytes());
        block.extend_from_slice(shared_info);
        out.extend_from_slice(&lk_crypto::sha256(&block));
        counter += 1;
    }
    out.truncate(len);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    A,
    B,
    C,
}

impl Variant {
    pub fn kid(self) -> u8 {
        match self {
            Variant::A => 0x11,
            Variant::B => 0x13,
            Variant::C => 0x15,
        }
    }
    fn parameter(self) -> u8 {
        match self {
            Variant::A => 0x01,
            Variant::B => 0x00,
            Variant::C => 0x03,
        }
    }
    fn ins(self) -> u8 {
        if self == Variant::B { 0x88 } else { 0x82 }
    }
}

/// A prepared MUTUAL/INTERNAL AUTHENTICATE.
pub struct Request {
    pub variant: Variant,
    pub data: Vec<u8>,
    pub apdu: Vec<u8>,
    esk: EcPrivateKey,
}

/// The request data, encoded by hand.
pub fn request_data(variant: Variant, epk: &[u8]) -> Vec<u8> {
    let mut data = vec![0xA6, 0x0D, 0x90, 0x02, 0x11, variant.parameter(), 0x95, 0x01, 0x3C, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10];
    data.extend_from_slice(&[0x5F, 0x49, epk.len() as u8]);
    data.extend_from_slice(epk);
    data
}

pub fn request(variant: Variant, kvn: u8, esk: EcPrivateKey) -> Request {
    let data = request_data(variant, &esk.public_uncompressed());
    let apdu = encode_apdu(0x80, variant.ins(), kvn, variant.kid(), &data, None, false);
    Request { variant, data, apdu, esk }
}

/// What the host learnt from a successful handshake.
pub struct Established {
    pub session: HostSession,
    pub card_point: Vec<u8>,
    pub receipt: [u8; 16],
}

impl Request {
    /// Check the card's answer and derive the host session. `pk_sd` is the card's static
    /// SCP11 key; `sk_oce` the OCE's static key (a/c).
    pub fn finish(&self, resp: &[u8], pk_sd: &[u8], sk_oce: Option<&EcPrivateKey>) -> Result<Established, String> {
        if resp.len() != 86 + 2 || resp[86..] != [0x90, 0x00] {
            return Err(format!("unexpected response {resp:02X?}"));
        }
        if resp[..3] != [0x5F, 0x49, 0x41] || resp[68..70] != [0x86, 0x10] {
            return Err("response layout".into());
        }
        let card_point = resp[3..68].to_vec();
        let receipt: [u8; 16] = resp[70..86].try_into().unwrap();
        let sh_see = self.esk.ecdh(&card_point).map_err(|_| "card point".to_string())?;
        let static_key = sk_oce.unwrap_or(&self.esk);
        let sh_ses = static_key.ecdh(pk_sd).map_err(|_| "card static key".to_string())?;
        let z = [sh_see.as_slice(), sh_ses.as_slice()].concat();
        let keys = x963(&z, &[0x3C, 0x88, 0x10], 80);
        let key = |i: usize| -> [u8; 16] { keys[i * 16..(i + 1) * 16].try_into().unwrap() };
        let mut input = self.data.clone();
        input.extend_from_slice(&resp[..68]);
        if cmac(&key(0), &input) != receipt {
            return Err("receipt does not verify".into());
        }
        Ok(Established {
            session: HostSession {
                s_enc: key(1),
                s_mac: key(2),
                s_rmac: key(3),
                mcv: receipt,
                counter: 1,
                level: 0x33,
                pad_empty: true,
                dek: key(4),
            },
            card_point,
            receipt,
        })
    }
}

/// PERFORM SECURITY OPERATION APDUs for a chain (yubikit `scp.py`): P1 = CA KVN, P2 = CA
/// KID with `80` on every certificate but the last; extended length for long ones.
pub fn pso_apdus(kid: u8, kvn: u8, chain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let last = chain.len().saturating_sub(1);
    chain
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let p2 = kid | if i < last { 0x80 } else { 0x00 };
            encode_apdu(0x80, 0x2A, kvn, p2, cert, None, cert.len() > 255)
        })
        .collect()
}

// ---------------------------------------------------------------------------------
// Command data (yubikit `securitydomain.py` layouts), encoded by hand
// ---------------------------------------------------------------------------------

/// BER-TLV with a one- or two-byte tag (ISO/IEC 7816-4 §5.2.2), by hand.
pub fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    match value.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

/// PUT KEY data for an OCE CA public key (yubikit `put_key`): KVN, `B0 41 <point>`,
/// `F0 01 00`, empty KCV.
pub fn ca_key_data(kvn: u8, point: &[u8]) -> Vec<u8> {
    [vec![kvn], tlv(&[0xB0], point), vec![0xF0, 0x01, 0x00, 0x00]].concat()
}

/// PUT KEY data for an SCP11 private key: KVN, `B1 20 <scalar, AES-CBC under the DEK>`,
/// `F0 01 00`, empty KCV.
pub fn private_key_data(dek: &[u8; 16], kvn: u8, scalar: &[u8]) -> Vec<u8> {
    let encrypted = lk_crypto::aes_cbc_encrypt(dek, &[0; 16], scalar).unwrap();
    [vec![kvn], tlv(&[0xB1], &encrypted), vec![0xF0, 0x01, 0x00, 0x00]].concat()
}

/// STORE DATA allowlist (yubikit `store_allowlist`, serials with an ASN.1 sign byte when
/// the top bit is set), with an SCP11c counter in `A6` if given.
pub fn allowlist_data(kid: u8, kvn: u8, serials: &[&[u8]], counter: Option<u16>) -> Vec<u8> {
    let mut crt = tlv(&[0x83], &[kid, kvn]);
    if let Some(c) = counter {
        crt.extend(tlv(&[0x92], &c.to_be_bytes()));
    }
    let mut list = Vec::new();
    for s in serials {
        let mut v = s.to_vec();
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        list.extend(tlv(&[0x93], &v));
    }
    [tlv(&[0xA6], &crt), tlv(&[0x70], &list)].concat()
}

/// STORE DATA CA issuer (yubikit `store_ca_issuer`: `80` = `01` for KLCC, `00` KLOC).
pub fn ca_issuer_data(kid: u8, kvn: u8, ski: &[u8]) -> Vec<u8> {
    let klcc = matches!(kid, 0x11 | 0x13 | 0x15);
    tlv(&[0xA6], &[tlv(&[0x80], &[u8::from(klcc)]), tlv(&[0x42], ski), tlv(&[0x83], &[kid, kvn])].concat())
}

/// STORE DATA certificate store (yubikit `store_certificate_bundle`).
pub fn cert_store_data(kid: u8, kvn: u8, certs: &[Vec<u8>]) -> Vec<u8> {
    [tlv(&[0xA6], &tlv(&[0x83], &[kid, kvn])), tlv(&[0xBF, 0x21], &certs.concat())].concat()
}

// ---------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------

/// What a test certificate contains.
#[derive(Clone, Debug)]
pub struct CertSpec {
    pub serial: Vec<u8>,
    pub issuer: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    /// `Some((ca, path_len))` adds a critical basicConstraints.
    pub basic: Option<(bool, Option<u32>)>,
    pub usage: Option<u16>,
    pub ski: Option<Vec<u8>>,
    pub aki: Option<Vec<u8>>,
    pub extra: Vec<Extension>,
    pub algorithm: SignatureAlgorithm,
}

impl CertSpec {
    pub fn ca(serial: &[u8], issuer: &str, subject: &str, path_len: Option<u32>) -> Self {
        CertSpec {
            serial: serial.to_vec(),
            issuer: issuer.into(),
            subject: subject.into(),
            not_before: "20250101000000Z".into(),
            not_after: "20450101000000Z".into(),
            basic: Some((true, path_len)),
            usage: Some(key_usage::KEY_CERT_SIGN),
            ski: None,
            aki: None,
            extra: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
        }
    }

    pub fn leaf(serial: &[u8], issuer: &str, subject: &str) -> Self {
        CertSpec {
            basic: Some((false, None)),
            usage: Some(key_usage::KEY_AGREEMENT),
            ..CertSpec::ca(serial, issuer, subject, None)
        }
    }

    /// Build and sign the certificate for `subject_key` (P-256 point) with `issuer`.
    pub fn build(&self, subject_key: PublicKey, issuer: &EcPrivateKey) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some((ca, path_len)) = self.basic {
            extensions.push(Extension::basic_constraints(ca, path_len));
        }
        if let Some(bits) = self.usage {
            extensions.push(Extension::key_usage(bits));
        }
        if let Some(ski) = &self.ski {
            extensions.push(Extension::subject_key_identifier(ski));
        }
        if let Some(aki) = &self.aki {
            extensions.push(Extension::authority_key_identifier(aki));
        }
        extensions.extend(self.extra.iter().cloned());
        let tbs = TbsCertificate {
            serial: self.serial.clone(),
            signature: self.algorithm,
            issuer: Name::new().common_name(&self.issuer),
            validity: Validity::generalized(&self.not_before, &self.not_after),
            subject: Name::new().common_name(&self.subject),
            public_key: subject_key,
            extensions,
        }
        .to_der();
        let hash = if self.algorithm == SignatureAlgorithm::EcdsaWithSha384 { HashAlg::Sha384 } else { HashAlg::Sha256 };
        let signature = issuer.sign_message(hash, &tbs).unwrap().to_der();
        x509::assemble(&tbs, self.algorithm, &signature)
    }

    pub fn build_for(&self, subject: &EcPrivateKey, issuer: &EcPrivateKey) -> Vec<u8> {
        self.build(PublicKey::EcP256(subject.public_uncompressed()), issuer)
    }
}

/// A three-level OCE PKI: root CA (whose public key the card stores as CA-KLOC), an
/// intermediate CA and the OCE leaf (key agreement). Serials `01..`, `02..`, `03..`;
/// the root and intermediate serials start with `80` so that their DER encoding carries
/// a sign byte.
pub struct Pki {
    pub ca: EcPrivateKey,
    pub inter: EcPrivateKey,
    pub leaf: EcPrivateKey,
    pub root_cert: Vec<u8>,
    pub inter_cert: Vec<u8>,
    pub leaf_cert: Vec<u8>,
    /// A leaf signed directly by the root CA.
    pub direct_leaf_cert: Vec<u8>,
    pub root_serial: Vec<u8>,
    pub inter_serial: Vec<u8>,
    pub leaf_serial: Vec<u8>,
    pub direct_serial: Vec<u8>,
    pub root_ski: Vec<u8>,
    pub inter_ski: Vec<u8>,
}

/// The OCE static key of the known-answer vectors (scalar `81..A0`).
pub const OCE_LEAF_KEY_START: u8 = 0x81;

pub fn pki(seed: u8) -> Pki {
    let ca = key_from(0xC1u8.wrapping_add(seed));
    let inter = key_from(0x11u8.wrapping_add(seed));
    let leaf = key_from(OCE_LEAF_KEY_START.wrapping_add(seed));
    let root_serial = vec![0x80, 0x00, seed, 0x01];
    let inter_serial = vec![0x80, 0x00, seed, 0x02];
    let leaf_serial = vec![0x03, seed, 0x03];
    let direct_serial = vec![0x04, seed, 0x04];
    let root_ski = vec![0xAA, seed, 1, 1];
    let inter_ski = vec![0xBB, seed, 2, 2];
    let root_cert = CertSpec { ski: Some(root_ski.clone()), aki: Some(root_ski.clone()), ..CertSpec::ca(&root_serial, "OCE Root", "OCE Root", Some(1)) }
        .build_for(&ca, &ca);
    let inter_cert = CertSpec { ski: Some(inter_ski.clone()), aki: Some(root_ski.clone()), ..CertSpec::ca(&inter_serial, "OCE Root", "OCE Intermediate", Some(0)) }
        .build_for(&inter, &ca);
    let leaf_cert = CertSpec { aki: Some(inter_ski.clone()), ..CertSpec::leaf(&leaf_serial, "OCE Intermediate", "OCE") }.build_for(&leaf, &inter);
    let direct_leaf_cert = CertSpec { aki: Some(root_ski.clone()), ..CertSpec::leaf(&direct_serial, "OCE Root", "OCE direct") }.build_for(&leaf, &ca);
    Pki {
        ca,
        inter,
        leaf,
        root_cert,
        inter_cert,
        leaf_cert,
        direct_leaf_cert,
        root_serial,
        inter_serial,
        leaf_serial,
        direct_serial,
        root_ski,
        inter_ski,
    }
}

impl Pki {
    pub fn full_chain(&self) -> Vec<Vec<u8>> {
        vec![self.root_cert.clone(), self.inter_cert.clone(), self.leaf_cert.clone()]
    }
}

// ---------------------------------------------------------------------------------
// A small DER walker (X.690), independent of the card's reader.
// ---------------------------------------------------------------------------------

/// One element: (tag, value, whole element, rest).
pub fn der_next(input: &[u8]) -> (u8, &[u8], &[u8], &[u8]) {
    let tag = input[0];
    let (len, header) = match input[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 => (input[2] as usize, 3),
        0x82 => (((input[2] as usize) << 8) | input[3] as usize, 4),
        _ => panic!("length form"),
    };
    (tag, &input[header..header + len], &input[..header + len], &input[header + len..])
}

/// Split concatenated DER elements.
pub fn der_split_all(mut input: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (_, _, element, rest) = der_next(input);
        out.push(element.to_vec());
        input = rest;
    }
    out
}

/// The subject public key (point) of a certificate and whether the certificate's
/// signature verifies with `issuer_point` (RFC 5280 §4.1).
pub fn cert_key_and_check(cert: &[u8], issuer_point: Option<&[u8]>) -> (Vec<u8>, bool) {
    let (_, body, _, _) = der_next(cert);
    let (_, tbs_body, tbs, rest) = der_next(body);
    let (_, _, _, rest) = der_next(rest); // signatureAlgorithm
    let (_, sig_bits, _, _) = der_next(rest);
    // TBS: [0] version, serial, signature, issuer, validity, subject, spki, ...
    let mut items = tbs_body;
    let mut fields = Vec::new();
    while !items.is_empty() {
        let (tag, value, _, rest) = der_next(items);
        fields.push((tag, value));
        items = rest;
    }
    let (_, spki) = fields[6];
    let (_, _, _, rest) = der_next(spki);
    let (_, bits, _, _) = der_next(rest);
    let point = bits[1..].to_vec();
    let check_key = issuer_point.unwrap_or(&point);
    let ok = lk_crypto::ecdsa_verify_prehash(Curve::P256, check_key, &lk_crypto::sha256(tbs), &sig_bits[1..]);
    (point, ok)
}

/// Whether a certificate carries an extension with this DER OID value and whether it is
/// critical; and the extension's value.
pub fn cert_extension(cert: &[u8], oid: &[u64]) -> Option<(bool, Vec<u8>)> {
    let wanted = der::oid(oid);
    let (_, body, _, _) = der_next(cert);
    let (_, tbs_body, _, _) = der_next(body);
    let mut items = tbs_body;
    while !items.is_empty() {
        let (tag, value, _, rest) = der_next(items);
        if tag == 0xA3 {
            let (_, list, _, _) = der_next(value);
            let mut exts = list;
            while !exts.is_empty() {
                let (_, ext, _, rest) = der_next(exts);
                let (_, _, oid_el, after) = der_next(ext);
                if oid_el == wanted.as_slice() {
                    let (tag, v, _, after2) = der_next(after);
                    return Some(if tag == 0x01 {
                        let (_, ov, _, _) = der_next(after2);
                        (v == [0xFF], ov.to_vec())
                    } else {
                        (false, v.to_vec())
                    });
                }
                exts = rest;
            }
        }
        items = rest;
    }
    None
}
