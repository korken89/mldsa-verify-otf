//! Bit unpacking, hints and w1 packing (FIPS 204 sections 7.1 and 7.4).

use core::marker::PhantomData;

use crate::ntt::{Poly, Q, caddq};
use crate::params::Params;

/// SimpleBitUnpack (Algorithm 18) of coefficients with `bits` bits each, for `bits` up to 24.
pub fn unpack(bytes: &[u8], bits: u32) -> impl Iterator<Item = i32> {
    let mut bytes = bytes.iter();
    let (mut acc, mut acc_bits) = (0u32, 0);
    core::iter::from_fn(move || {
        while acc_bits < bits {
            acc |= u32::from(*bytes.next()?) << acc_bits;
            acc_bits += 8;
        }
        let v = acc & ((1 << bits) - 1);
        acc >>= bits;
        acc_bits -= bits;
        Some(v as i32)
    })
}

/// Unpacks a z polynomial (BitUnpack with a = gamma1 - 1, b = gamma1, Algorithm 19).
pub fn unpack_z<P: Params>(bytes: &[u8]) -> impl Iterator<Item = i32> {
    unpack(bytes, P::Z_BITS).map(|v| P::GAMMA1 - v)
}

/// A hint encoding of omega + k bytes that passed [`hints_valid`].
pub struct ValidHints<'a, P>(&'a [u8], PhantomData<P>);

/// Checks the hint encoding as HintBitUnpack (Algorithm 21) does, for `y` of omega + k bytes.
pub fn hints_valid<P: Params>(y: &[u8]) -> Option<ValidHints<'_, P>> {
    let (indices, limits) = y.split_at(P::OMEGA);
    let mut start = 0;
    for &end in limits {
        let end = usize::from(end);
        if end < start || end > P::OMEGA || indices[start..end].windows(2).any(|w| w[0] >= w[1]) {
            return None;
        }
        start = end;
    }
    indices[start..]
        .iter()
        .all(|&b| b == 0)
        .then_some(ValidHints(y, PhantomData))
}

/// UseHint (Algorithm 40) with Decompose (Algorithm 36), for `r` in (-q, q).
fn use_hint<P: Params>(hint: bool, r: i32) -> u32 {
    let r = caddq(r);
    let mut r0 = r % (2 * P::GAMMA2);
    if r0 > P::GAMMA2 {
        r0 -= 2 * P::GAMMA2;
    }
    let (r1, r0) = if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * P::GAMMA2), r0)
    };
    let r1 = match (hint, r0 > 0) {
        (false, _) => r1,
        (true, true) => (r1 + 1) % P::W1_MOD,
        (true, false) => (r1 + P::W1_MOD - 1) % P::W1_MOD,
    };
    r1 as u32
}

/// Applies the hints of `row` to `w` and returns w1Encode (Algorithm 28) of the result in the
/// first `P::W1_POLY_LEN` bytes.
pub fn use_hints_encode<P: Params>(w: &Poly, hints: &ValidHints<P>, row: u8) -> [u8; 192] {
    let (indices, limits) = hints.0.split_at(P::OMEGA);
    let row = usize::from(row);
    let start = row.checked_sub(1).map_or(0, |r| usize::from(limits[r]));
    let indices = &indices[start..usize::from(limits[row])];
    let mut hints = indices.iter().map(|&i| usize::from(i)).peekable();
    let mut out = [0; 192];
    let (mut acc, mut acc_bits, mut i) = (0u32, 0, 0);
    for (n, &r) in w.iter().enumerate() {
        acc |= use_hint::<P>(hints.next_if_eq(&n).is_some(), r) << acc_bits;
        acc_bits += P::W1_BITS;
        while acc_bits >= 8 {
            out[i] = acc as u8;
            acc >>= 8;
            acc_bits -= 8;
            i += 1;
        }
    }
    out
}
