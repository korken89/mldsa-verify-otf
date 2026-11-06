//! Sampling from SHAKE (FIPS 204 section 7.3).

use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};

use crate::ntt::{Poly, Q};

/// Number of nonzero coefficients in the challenge polynomial c.
const TAU: usize = 49;

/// The challenge polynomial c, with coefficients in {-1, 0, 1}.
pub type Challenge = [i8; 256];

/// RejNTTPoly (Algorithm 30) for the matrix entry `A[row][col]` (Algorithm 32), passing each
/// coefficient to `f` in order instead of storing the polynomial.
#[inline(never)]
pub fn rej_ntt_poly(rho: &[u8], row: u8, col: u8, mut f: impl FnMut(usize, i32)) {
    let mut xof = Shake128::default()
        .chain(rho)
        .chain([col, row])
        .finalize_xof();
    let mut n = 0;
    while n < 256 {
        let mut b = [0; 3];
        xof.read(&mut b);
        let a = i32::from(b[0]) | i32::from(b[1]) << 8 | i32::from(b[2] & 0x7f) << 16;
        if a < Q {
            f(n, a);
            n += 1;
        }
    }
}

/// SampleInBall (Algorithm 29).
#[inline(never)]
pub fn sample_in_ball(c_tilde: &[u8]) -> Challenge {
    let mut xof = Shake256::default().chain(c_tilde).finalize_xof();
    let mut signs = [0; 8];
    xof.read(&mut signs);
    let mut signs = u64::from_le_bytes(signs);
    let mut c = [0; 256];
    for i in 256 - TAU..256 {
        let j = loop {
            let mut j = [0];
            xof.read(&mut j);
            let j = usize::from(j[0]);
            if j <= i {
                break j;
            }
        };
        c[i] = c[j];
        c[j] = 1 - 2 * (signs & 1) as i8;
        signs >>= 1;
    }
    c
}

/// Subtracts `c * t` from `w` in Z[X]/(X^256 + 1), using that c is sparse.
pub fn sub_challenge_product(w: &mut Poly, c: &Challenge, t: &Poly) {
    for (pos, &sign) in c.iter().enumerate().filter(|(_, c)| **c != 0) {
        let sign = i32::from(sign);
        // X^pos * t wraps the top `pos` coefficients around with a sign change.
        let (w_low, w_high) = w.split_at_mut(pos);
        let (t_low, t_high) = t.split_at(256 - pos);
        for (w, t) in w_high.iter_mut().zip(t_low) {
            *w -= sign * t;
        }
        for (w, t) in w_low.iter_mut().zip(t_high) {
            *w += sign * t;
        }
    }
}
