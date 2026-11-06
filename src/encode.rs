//! Bit unpacking, hints and w1 packing (FIPS 204 sections 7.1 and 7.4).

use crate::GAMMA1;
use crate::ntt::{Poly, Q, caddq};

/// Maximum number of 1s in the hint (omega).
pub const OMEGA: usize = 55;
/// (q - 1) / 32.
const GAMMA2: i32 = (Q - 1) / 32;

/// SimpleBitUnpack (Algorithm 18) of coefficients with `bits` bits each, for `bits` that divides
/// 40.
pub fn unpack(bytes: &[u8], bits: u32) -> impl Iterator<Item = i32> {
    let mask = (1 << bits) - 1;
    bytes.chunks_exact(5).flat_map(move |chunk| {
        let v = chunk.iter().rev().fold(0, |v, &b| v << 8 | u64::from(b));
        (0..40 / bits).map(move |i| (v >> (i * bits) & mask) as i32)
    })
}

/// Unpacks a z polynomial (BitUnpack with a = gamma1 - 1, b = gamma1, Algorithm 19).
pub fn unpack_z(bytes: &[u8]) -> impl Iterator<Item = i32> {
    unpack(bytes, 20).map(|v| GAMMA1 - v)
}

/// Checks the hint encoding as HintBitUnpack (Algorithm 21) does, for `y` of omega + k bytes.
pub fn hints_valid(y: &[u8]) -> bool {
    let (indices, limits) = y.split_at(OMEGA);
    let mut start = 0;
    for &end in limits {
        let end = usize::from(end);
        if end < start || end > OMEGA || indices[start..end].windows(2).any(|w| w[0] >= w[1]) {
            return false;
        }
        start = end;
    }
    indices[start..].iter().all(|&b| b == 0)
}

/// UseHint (Algorithm 40) with Decompose (Algorithm 36), for `r` in (-q, q).
fn use_hint(hint: bool, r: i32) -> u8 {
    let r = caddq(r);
    let mut r0 = r % (2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    let (r1, r0) = if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * GAMMA2), r0)
    };
    let r1 = match (hint, r0 > 0) {
        (false, _) => r1,
        (true, true) => r1 + 1,
        (true, false) => r1 - 1,
    };
    (r1 & 15) as u8
}

/// Applies the hints at the sorted coefficient `indices` to `w` and returns w1Encode (Algorithm
/// 28) of the result.
pub fn use_hints_encode(w: &Poly, indices: &[u8]) -> [u8; 128] {
    let mut hints = indices.iter().map(|&i| usize::from(i)).peekable();
    let mut out = [0; 128];
    for (n, &r) in w.iter().enumerate() {
        let w1 = use_hint(hints.next_if_eq(&n).is_some(), r);
        out[n / 2] |= w1 << (4 * (n % 2));
    }
    out
}
