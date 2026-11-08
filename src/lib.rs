//! ML-DSA-65 signature verification (FIPS 204) with a small stack.
//!
//! Neither the matrix A nor NTT(z) is stored. Each row of w is computed on its own, sampling
//! each entry of A as it is used and recomputing NTT(z) for it, so the working set is two
//! polynomials. The helpers that hold SHAKE state are not inlined, which keeps their frames out
//! of the caller's.
//!
//! Verification handles only public data, so the code is not constant time.
#![cfg_attr(not(test), no_std)]

mod encode;
mod ntt;
mod sample;
#[cfg(test)]
mod tests;

use shake::{ExtendableOutput, Shake256, Update};

use crate::encode::OMEGA;
use crate::ntt::{Poly, inv_ntt_to_mont, mont_mul, ntt, reduce32};

/// Length of an encoded ML-DSA-65 public key.
pub const PUBLIC_KEY_LEN: usize = 1952;
/// Length of an encoded ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = 3309;

/// Rows of A (k).
const K: usize = 6;
/// Columns of A (l).
const L: usize = 5;
/// Length of the commitment hash c~ (lambda / 4).
const C_TILDE_LEN: usize = 48;
/// Bytes of one packed t1 polynomial (10 bits per coefficient).
const T1_POLY_LEN: usize = 320;
/// Bytes of one packed z polynomial (20 bits per coefficient).
const Z_POLY_LEN: usize = 640;
/// Dropped bits of t (d).
const D: u32 = 13;
/// Coefficient range of y (gamma1).
const GAMMA1: i32 = 1 << 19;
/// tau * eta.
const BETA: i32 = 196;

/// A rejected verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// The signature is not valid for this key and message.
    InvalidSignature,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ContextTooLong => "context string is longer than 255 bytes",
            Self::InvalidSignature => "invalid signature",
        })
    }
}

impl core::error::Error for Error {}

/// Verifies `sig` over `message` with an empty context string.
pub fn verify(
    pk: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    verify_with_context(pk, &[], &[message], sig)
}

/// Verifies `sig` over the concatenation of `message` with the context string `context`
/// (ML-DSA.Verify, FIPS 204 Algorithm 3).
pub fn verify_with_context(
    pk: &[u8; PUBLIC_KEY_LEN],
    context: &[u8],
    message: &[&[u8]],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    let context_len = u8::try_from(context.len()).map_err(|_| Error::ContextTooLong)?;
    let prefix = [&[0, context_len][..], context];
    let mu = mu(pk, prefix.into_iter().chain(message.iter().copied()));
    if verify_mu(pk, &mu, sig) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `mu = H(H(pk, 64) || M', 64)` with M' given in parts.
#[inline(never)]
fn mu<'a>(pk: &[u8; PUBLIC_KEY_LEN], message: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    let mut tr = [0; 64];
    Shake256::default().chain(pk).finalize_xof_into(&mut tr);
    let mut h = Shake256::default().chain(tr);
    for part in message {
        h.update(part);
    }
    let mut mu = [0; 64];
    h.finalize_xof_into(&mut mu);
    mu
}

/// ML-DSA.Verify_internal (Algorithm 8) from mu.
fn verify_mu(pk: &[u8; PUBLIC_KEY_LEN], mu: &[u8; 64], sig: &[u8; SIGNATURE_LEN]) -> bool {
    let (c_tilde, rest) = sig.split_at(C_TILDE_LEN);
    let (z, hints) = rest.split_at(L * Z_POLY_LEN);
    if !encode::hints_valid(hints) || encode::unpack_z(z).any(|z| z.abs() >= GAMMA1 - BETA) {
        return false;
    }
    let c = sample::sample_in_ball(c_tilde);
    let mut h = Shake256::default().chain(mu);
    let (rho, t1) = pk.split_at(32);
    let matrix = sample::ExpandA(rho);
    let (hint_indices, hint_limits) = hints.split_at(OMEGA);
    let mut hint_start = 0;
    for ((row, t1), &hint_end) in (0..).zip(t1.chunks_exact(T1_POLY_LEN)).zip(hint_limits) {
        let hint_end = usize::from(hint_end);
        let w1 = w1_row(&matrix, row, z, &c, t1, &hint_indices[hint_start..hint_end]);
        h.update(&w1);
        hint_start = hint_end;
    }
    let mut c_tilde_prime = [0; C_TILDE_LEN];
    h.finalize_xof_into(&mut c_tilde_prime);
    c_tilde == c_tilde_prime
}

/// Returns w1Encode(UseHint(h, A[row] * z - c * t1 * 2^d)) for one row.
#[inline(never)]
fn w1_row(
    matrix: &impl sample::Matrix,
    row: u8,
    z: &[u8],
    c: &sample::Challenge,
    t1: &[u8],
    hints: &[u8],
) -> [u8; 128] {
    let mut w: Poly = [0; 256];
    let mut z_hat: Poly = [0; 256];
    for (col, z) in (0..).zip(z.chunks_exact(Z_POLY_LEN)) {
        for (out, z) in z_hat.iter_mut().zip(encode::unpack_z(z)) {
            *out = z;
        }
        ntt(&mut z_hat);
        matrix.entry(row, col, |n, a| {
            w[n] += mont_mul(a, z_hat[n]);
        });
    }
    for x in w.iter_mut() {
        *x = reduce32(*x);
    }
    inv_ntt_to_mont(&mut w);
    // The sparse c is applied outside the NTT domain, with z_hat reused for t1 * 2^d.
    for (t, t1) in z_hat.iter_mut().zip(encode::unpack(t1, 10)) {
        *t = t1 << D;
    }
    sample::sub_challenge_product(&mut w, c, &z_hat);
    for x in w.iter_mut() {
        *x = reduce32(*x);
    }
    encode::use_hints_encode(&w, hints)
}

const _: () = assert!(PUBLIC_KEY_LEN == 32 + K * T1_POLY_LEN);
const _: () = assert!(SIGNATURE_LEN == C_TILDE_LEN + L * Z_POLY_LEN + OMEGA + K);
