use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Hash algorithms used by the protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    Sha384::digest(data).into()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

pub fn digest(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => sha1(data).to_vec(),
        HashAlg::Sha256 => sha256(data).to_vec(),
        HashAlg::Sha384 => sha384(data).to_vec(),
        HashAlg::Sha512 => sha512(data).to_vec(),
    }
}
