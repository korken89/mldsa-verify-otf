//! Arithmetic mod q and the NTT, as in the Dilithium reference implementation.

/// The ML-DSA modulus q.
pub const Q: i32 = 8_380_417;
/// q^-1 mod 2^32.
const QINV: i32 = 58_728_449;
/// 2^32 mod q.
const MONT: i64 = 4_193_792;

const fn pow_mod(base: i64, mut exp: i64) -> i64 {
    let (mut acc, mut b) = (1, base);
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * b % Q as i64;
        }
        b = b * b % Q as i64;
        exp >>= 1;
    }
    acc
}

/// `MONT * 1753^brv8(k) mod q`, where 1753 is the 512th root of unity (FIPS 204 Appendix B).
const ZETAS: [i32; 256] = {
    let mut zetas = [0; 256];
    let mut k = 1;
    while k < 256 {
        zetas[k] = (MONT * pow_mod(1753, (k as u8).reverse_bits() as i64) % Q as i64) as i32;
        k += 1;
    }
    zetas
};

/// `MONT^2 / 256 mod q`, which undoes the 1/256 of the inverse NTT and returns to Montgomery form.
const INV_NTT_F: i32 = (MONT * MONT % Q as i64 * pow_mod(256, Q as i64 - 2) % Q as i64) as i32;

/// A polynomial in Z_q[X]/(X^256 + 1), with coefficients not necessarily reduced.
pub type Poly = [i32; 256];

/// Returns `a * 2^-32 mod q` in (-q, q) for |a| < 2^31 * q.
fn mont_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - i64::from(t) * i64::from(Q)) >> 32) as i32
}

/// Returns `a * b * 2^-32 mod q` in (-q, q).
pub fn mont_mul(a: i32, b: i32) -> i32 {
    mont_reduce(i64::from(a) * i64::from(b))
}

/// Returns a value congruent to `a` mod q with |result| < q, for `a < 2^31 - 2^22`.
pub fn reduce32(a: i32) -> i32 {
    a - ((a + (1 << 22)) >> 23) * Q
}

/// Maps `a` in (-q, q) to [0, q).
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// Forward NTT. Coefficients grow by at most 8q in absolute value.
pub fn ntt(a: &mut Poly) {
    let mut k = 0;
    let mut len = 128;
    while len > 0 {
        for block in a.chunks_exact_mut(2 * len) {
            k += 1;
            let zeta = ZETAS[k];
            let (lo, hi) = block.split_at_mut(len);
            for (x, y) in lo.iter_mut().zip(hi) {
                let t = mont_mul(zeta, *y);
                *y = *x - t;
                *x += t;
            }
        }
        len >>= 1;
    }
}

/// Inverse NTT, multiplied by 2^32. Input and output are less than q in absolute value.
pub fn inv_ntt_to_mont(a: &mut Poly) {
    let mut k = 256;
    let mut len = 1;
    while len < 256 {
        for block in a.chunks_exact_mut(2 * len) {
            k -= 1;
            let zeta = -ZETAS[k];
            let (lo, hi) = block.split_at_mut(len);
            for (x, y) in lo.iter_mut().zip(hi) {
                let t = *x;
                *x = t + *y;
                *y = mont_mul(zeta, t - *y);
            }
        }
        len <<= 1;
    }
    for x in a {
        *x = mont_mul(INV_NTT_F, *x);
    }
}
