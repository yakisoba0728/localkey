//! A minimal DER reader for the host side (ITU-T X.690 §8.1, §10): enough to walk an
//! X.509 certificate (RFC 5280 §4.1) to its subject public key.

#![allow(dead_code)]

/// Header of the DER element at the start of `bytes`: (tag, header length, content length).
pub fn header(bytes: &[u8]) -> (u8, usize, usize) {
    let tag = bytes[0];
    assert_ne!(tag & 0x1F, 0x1F, "multi-byte tags are not used here");
    let first = bytes[1];
    if first < 0x80 {
        return (tag, 2, usize::from(first));
    }
    let n = usize::from(first & 0x7F);
    assert!((1..=3).contains(&n), "definite long form (X.690 §8.1.3.5)");
    let len = bytes[2..2 + n].iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    (tag, 2 + n, len)
}

/// Total length (header and content) of the element at the start of `bytes`.
pub fn element_len(bytes: &[u8]) -> usize {
    let (_, h, l) = header(bytes);
    h + l
}

/// The content of the element at the start of `bytes`, checking its tag, and the rest.
pub fn take(bytes: &[u8], tag: u8) -> (&[u8], &[u8]) {
    let (t, h, l) = header(bytes);
    assert_eq!(t, tag, "DER tag");
    (&bytes[h..h + l], &bytes[h + l..])
}

/// Skip one element.
pub fn skip(bytes: &[u8]) -> &[u8] {
    &bytes[element_len(bytes)..]
}

/// The uncompressed EC point in a certificate's SubjectPublicKeyInfo (RFC 5280 §4.1.2.7,
/// RFC 5480 §2.2).
pub fn certificate_ec_public_key(cert: &[u8]) -> Vec<u8> {
    let (certificate, _) = take(cert, 0x30);
    let (tbs, _) = take(certificate, 0x30);
    let mut fields = tbs;
    if fields[0] == 0xA0 {
        fields = skip(fields); // [0] EXPLICIT version
    }
    for _ in 0..5 {
        fields = skip(fields); // serial, signature, issuer, validity, subject
    }
    let (spki, _) = take(fields, 0x30);
    let rest = skip(spki); // algorithm
    let (bits, _) = take(rest, 0x03);
    assert_eq!(bits[0], 0, "no unused bits");
    bits[1..].to_vec()
}
