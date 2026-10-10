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

/// An incremental hash: [`Hasher::new`], any number of [`Hasher::update`] calls, then
/// [`Hasher::finalize`]. The result equals [`digest`] of the concatenated input, so a
/// long input (an RFC 4880 iterated-salted S2K, say) never has to be held in memory.
#[derive(Clone)]
pub struct Hasher {
    state: HasherState,
}

#[derive(Clone)]
enum HasherState {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(alg: HashAlg) -> Self {
        let state = match alg {
            HashAlg::Sha1 => HasherState::Sha1(Sha1::new()),
            HashAlg::Sha256 => HasherState::Sha256(Sha256::new()),
            HashAlg::Sha384 => HasherState::Sha384(Sha384::new()),
            HashAlg::Sha512 => HasherState::Sha512(Sha512::new()),
        };
        Self { state }
    }

    pub fn alg(&self) -> HashAlg {
        match self.state {
            HasherState::Sha1(_) => HashAlg::Sha1,
            HasherState::Sha256(_) => HashAlg::Sha256,
            HasherState::Sha384(_) => HashAlg::Sha384,
            HasherState::Sha512(_) => HashAlg::Sha512,
        }
    }

    /// Feed more input.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            HasherState::Sha1(h) => h.update(data),
            HasherState::Sha256(h) => h.update(data),
            HasherState::Sha384(h) => h.update(data),
            HasherState::Sha512(h) => h.update(data),
        }
    }

    /// The digest of everything fed so far ([`HashAlg::output_len`] bytes).
    pub fn finalize(self) -> Vec<u8> {
        match self.state {
            HasherState::Sha1(h) => h.finalize().to_vec(),
            HasherState::Sha256(h) => h.finalize().to_vec(),
            HasherState::Sha384(h) => h.finalize().to_vec(),
            HasherState::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hasher").field("alg", &self.alg()).finish_non_exhaustive()
    }
}
