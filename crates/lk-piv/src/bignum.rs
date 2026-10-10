//! Minimal unsigned multi-precision arithmetic to check imported RSA CRT components
//! (RFC 8017 §3.2: `e * dP ≡ 1 (mod p-1)`, `e * dQ ≡ 1 (mod q-1)`, `q * qInv ≡ 1 (mod p)`).
//!
//! This is validation of public relations between values the host supplied, not a
//! cryptographic primitive: the private operations themselves use `lk_crypto`. Numbers are
//! little-endian `u32` limbs; nothing here is constant time, which is acceptable because
//! the check runs once per import on values the host already knows.

use std::cmp::Ordering;

type Limbs = Vec<u32>;

/// Big-endian bytes to limbs, without leading zero limbs.
fn from_be(bytes: &[u8]) -> Limbs {
    let mut out: Limbs = bytes
        .rchunks(4)
        .map(|chunk| chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
        .collect();
    trim(&mut out);
    out
}

fn trim(v: &mut Limbs) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

fn cmp(a: &[u32], b: &[u32]) -> Ordering {
    // Both trimmed: the longer one is larger.
    a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

/// `a -= b` for `a >= b` (both trimmed); `a` stays trimmed.
fn sub_assign(a: &mut Limbs, b: &[u32]) {
    let mut borrow = 0u64;
    for (i, limb) in a.iter_mut().enumerate() {
        let rhs = u64::from(b.get(i).copied().unwrap_or(0)) + borrow;
        let lhs = u64::from(*limb);
        if lhs >= rhs {
            *limb = (lhs - rhs) as u32;
            borrow = 0;
        } else {
            *limb = ((1u64 << 32) + lhs - rhs) as u32;
            borrow = 1;
        }
    }
    trim(a);
}

fn mul(a: &[u32], b: &[u32]) -> Limbs {
    let mut out = vec![0u32; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &y) in b.iter().enumerate() {
            if let Some(slot) = out.get_mut(i + j) {
                let t = u64::from(x) * u64::from(y) + u64::from(*slot) + carry;
                *slot = t as u32;
                carry = t >> 32;
            }
        }
        if let Some(slot) = out.get_mut(i + b.len()) {
            *slot = carry as u32;
        }
    }
    trim(&mut out);
    out
}

/// `r = 2r + bit`.
fn shl1_add(r: &mut Limbs, bit: bool) {
    let mut carry = u32::from(bit);
    for limb in r.iter_mut() {
        let next = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        r.push(carry);
    }
}

/// `a mod m` by binary long division; `None` for `m = 0`.
fn rem(a: &[u32], m: &[u32]) -> Option<Limbs> {
    if m.is_empty() {
        return None;
    }
    let mut r: Limbs = Vec::with_capacity(m.len() + 1);
    for limb in a.iter().rev() {
        for bit in (0..32).rev() {
            shl1_add(&mut r, (limb >> bit) & 1 == 1);
            if cmp(&r, m) != Ordering::Less {
                sub_assign(&mut r, m);
            }
        }
    }
    Some(r)
}

fn is_one(v: &[u32]) -> bool {
    v == [1]
}

/// `x - 1` for `x >= 1`.
fn minus_one(x: &[u32]) -> Limbs {
    let mut out = x.to_vec();
    sub_assign(&mut out, &[1]);
    out
}

/// Whether `(a * b) mod m == 1`.
fn product_is_one_mod(a: &[u32], b: &[u32], m: &[u32]) -> bool {
    rem(&mul(a, b), m).is_some_and(|r| is_one(&r))
}

/// Whether the CRT components `dP`, `dQ` and `qInv` belong to the primes `p`, `q` and the
/// public exponent `e` (RFC 8017 §3.2, second representation). All values are unsigned
/// big-endian.
pub(crate) fn crt_consistent(p: &[u8], q: &[u8], e: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]) -> bool {
    let (p, q, e) = (from_be(p), from_be(q), from_be(e));
    if p.is_empty() || q.is_empty() {
        return false;
    }
    let (p1, q1) = (minus_one(&p), minus_one(&q));
    product_is_one_mod(&e, &from_be(dp), &p1)
        && product_is_one_mod(&e, &from_be(dq), &q1)
        && product_is_one_mod(&q, &from_be(qinv), &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(v: u128) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    #[test]
    fn arithmetic_matches_native_integers() {
        let values: [u128; 6] = [1, 2, 0xFFFF_FFFF, 0x1_0000_0000, 0xDEAD_BEEF_0123_4567, 0xFFFF_FFFF_FFFF_FFFF];
        for &a in &values {
            for &b in &values {
                assert_eq!(mul(&from_be(&be(a)), &from_be(&be(b))), from_be(&be(a * b)), "{a} * {b}");
                let r = rem(&from_be(&be(a * b + 5)), &from_be(&be(b))).unwrap_or_default();
                assert_eq!(r, from_be(&be((a * b + 5) % b)), "({a} * {b} + 5) mod {b}");
            }
        }
        assert_eq!(rem(&[5], &[]), None);
    }

    #[test]
    fn textbook_rsa_crt_components() {
        // RFC 8017 §3.2 relations on the classic toy key p = 61, q = 53, e = 17:
        // d = 2753, dP = d mod 60 = 53, dQ = d mod 52 = 49, qInv = 53^-1 mod 61 = 38.
        assert!(crt_consistent(&[61], &[53], &[17], &[53], &[49], &[38]));
        assert!(crt_consistent(&[0, 61], &[53], &[17], &[0, 0, 53], &[49], &[38]), "leading zeros");
        assert!(!crt_consistent(&[61], &[53], &[17], &[52], &[49], &[38]), "wrong dP");
        assert!(!crt_consistent(&[61], &[53], &[17], &[53], &[48], &[38]), "wrong dQ");
        assert!(!crt_consistent(&[61], &[53], &[17], &[53], &[49], &[37]), "wrong qInv");
        assert!(!crt_consistent(&[61], &[53], &[3], &[53], &[49], &[38]), "other exponent");
        assert!(!crt_consistent(&[], &[53], &[17], &[53], &[49], &[38]));
    }
}
