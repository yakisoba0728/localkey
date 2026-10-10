//! A byte buffer for secrets that is wiped when dropped.
//!
//! Protocol crates may not depend on `zeroize` (docs/DESIGN.md §8), so this crate owns the
//! type they use to hold shared secrets, session keys and similar material.

use core::fmt;
use core::ops::{Deref, DerefMut};

use zeroize::Zeroizing;

use crate::ct_eq;

/// Secret bytes, zeroed on drop (`zeroize`), with a redacted `Debug` and a constant-time
/// `PartialEq`.
///
/// It dereferences to `[u8]`, so slice methods (`len`, `to_vec`, indexing) and `&[u8]`
/// coercion work as on a plain buffer. Copies made with `to_vec` are ordinary `Vec`s and
/// are not wiped.
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Take ownership of `bytes`; the buffer is wiped when the value is dropped.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copy `bytes` into a new secret buffer.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// `len` zero bytes, to be filled in place through `DerefMut`.
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0; len])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl PartialEq for SecretBytes {
    /// Constant time in the contents ([`ct_eq`]); the lengths are not secret.
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes, <redacted>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaves_like_a_slice() {
        let mut secret = SecretBytes::from_slice(&[1, 2, 3]);
        assert_eq!(secret.len(), 3);
        assert_eq!(secret.as_slice(), &[1, 2, 3]);
        assert_eq!(secret.to_vec(), vec![1, 2, 3]);
        assert_eq!(&secret[1..], &[2, 3]);
        secret[0] = 9;
        assert_eq!(secret.as_ref(), &[9, 2, 3]);
        let coerced: &[u8] = &secret;
        assert_eq!(coerced, &[9, 2, 3]);
        let mut filled = SecretBytes::zeroed(2);
        filled.as_mut_slice().copy_from_slice(&[7, 8]);
        assert_eq!(filled, SecretBytes::from(vec![7, 8]));
    }

    #[test]
    fn equality_and_debug() {
        assert_eq!(SecretBytes::new(vec![5; 4]), SecretBytes::new(vec![5; 4]));
        assert_ne!(SecretBytes::new(vec![5; 4]), SecretBytes::new(vec![5, 5, 5, 6]));
        assert_ne!(SecretBytes::new(vec![5; 4]), SecretBytes::new(vec![5; 3]));
        let text = format!("{:?}", SecretBytes::new(vec![0xAB; 4]));
        assert_eq!(text, "SecretBytes(4 bytes, <redacted>)");
        assert!(!text.contains("171"));
    }
}
