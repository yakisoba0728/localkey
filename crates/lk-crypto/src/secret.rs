//! A byte buffer for secrets that is wiped when dropped.
//!
//! Protocol crates may not depend on `zeroize` (docs/DESIGN.md §8), so this crate owns the
//! type they use to hold shared secrets, session keys and similar material.

use core::fmt;
use core::ops::{Deref, DerefMut};

use zeroize::{Zeroize, Zeroizing};

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

/// Overwrite `bytes` with zeros through `zeroize` (volatile writes plus a compiler
/// fence, so the stores are not optimised away even though the buffer is about to be
/// released). For secrets that live in fixed-size arrays or borrowed buffers, where
/// [`SecretBytes`] does not fit; protocol crates may not call `zeroize` themselves
/// (docs/DESIGN.md §8).
pub fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Overwrite every byte of `buf`'s allocation with zeros, the spare capacity beyond its
/// length included, and leave it empty (length 0, capacity kept). `zeroize`'s `Vec`
/// implementation does exactly this. Use it before a buffer that held a secret is
/// dropped, cleared or reused.
pub fn wipe_vec(buf: &mut Vec<u8>) {
    buf.zeroize();
}

/// Append bytes, wiping the old allocation if the buffer has to grow.
pub fn extend_secret(buf: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() > buf.capacity() - buf.len() {
        let old = SecretBytes::new(core::mem::take(buf));
        *buf = Vec::with_capacity(old.len().saturating_add(bytes.len()).max(old.len().saturating_mul(2)));
        buf.extend_from_slice(&old);
    }
    buf.extend_from_slice(bytes);
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

    #[test]
    fn wipe_zeroes_a_slice_in_place() {
        let mut key = [0xA5u8; 24];
        wipe(&mut key[4..]);
        assert_eq!(&key[..4], &[0xA5; 4]);
        assert!(key[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn wipe_vec_empties_the_buffer_and_keeps_its_allocation() {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0x5Au8; 40]);
        buf.truncate(10);
        let capacity = buf.capacity();
        wipe_vec(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), capacity, "the allocation is kept for reuse");
    }

    #[test]
    fn extending_a_secret_preserves_bytes_across_growth_and_reuses_room() {
        let mut buf = Vec::with_capacity(4);
        extend_secret(&mut buf, &[1, 2]);
        let pointer = buf.as_ptr();
        extend_secret(&mut buf, &[3, 4]);
        assert_eq!(buf.as_ptr(), pointer, "room is reused");
        extend_secret(&mut buf, &[5, 6, 7, 8, 9]);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        wipe_vec(&mut buf);
    }
}
