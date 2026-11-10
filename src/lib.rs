//! ML-DSA signature verification (FIPS 204) with a small stack.
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
mod params;
mod sample;
#[cfg(test)]
mod tests;

use shake::{ExtendableOutput, Shake256, Update};

use crate::ntt::{Poly, inv_ntt_to_mont, mont_mul, ntt, reduce32};
pub use crate::params::{MlDsa44, MlDsa65, MlDsa87, ParameterSet};
use crate::params::{Params, T1_POLY_LEN};

/// Dropped bits of t (d).
const D: u32 = 13;

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
pub fn verify<P: ParameterSet>(
    pk: &P::PublicKey,
    message: &[u8],
    sig: &P::Signature,
) -> Result<(), Error> {
    verify_with_context::<P>(pk, &[], &[message], sig)
}

/// Verifies `sig` over the concatenation of `message` with the context string `context`
/// (ML-DSA.Verify, FIPS 204 Algorithm 3).
pub fn verify_with_context<P: ParameterSet>(
    pk: &P::PublicKey,
    context: &[u8],
    message: &[&[u8]],
    sig: &P::Signature,
) -> Result<(), Error> {
    let context_len = u8::try_from(context.len()).map_err(|_| Error::ContextTooLong)?;
    let prefix = [&[0, context_len][..], context];
    let mu = mu(
        pk.as_ref(),
        prefix.into_iter().chain(message.iter().copied()),
    );
    if verify_mu::<P>(pk.as_ref(), &mu, sig.as_ref()) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `mu = H(H(pk, 64) || M', 64)` with M' given in parts.
#[inline(never)]
fn mu<'a>(pk: &[u8], message: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
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

/// ML-DSA.Verify_internal (Algorithm 8) from mu, for `pk` and `sig` of the lengths of `P`.
fn verify_mu<P: Params>(pk: &[u8], mu: &[u8; 64], sig: &[u8]) -> bool {
    let (c_tilde, rest) = sig.split_at(P::C_TILDE_LEN);
    let (z, hints) = rest.split_at(P::L * P::Z_POLY_LEN);
    let Some(hints) = encode::hints_valid::<P>(hints) else {
        return false;
    };
    if encode::unpack_z::<P>(z).any(|z| z.abs() >= P::GAMMA1 - P::BETA) {
        return false;
    }
    let c = sample::sample_in_ball::<P>(c_tilde);
    let mut h = Shake256::default().chain(mu);
    let (rho, t1) = pk.split_at(32);
    let matrix = sample::ExpandA(rho);
    for (row, t1) in (0..).zip(t1.chunks_exact(T1_POLY_LEN)) {
        let w1 = w1_row::<P>(&matrix, row, z, &c, t1, &hints);
        h.update(&w1[..P::W1_POLY_LEN]);
    }
    // A longer XOF output starts with the shorter one.
    let mut c_tilde_prime = [0; 64];
    h.finalize_xof_into(&mut c_tilde_prime);
    c_tilde == &c_tilde_prime[..P::C_TILDE_LEN]
}

/// Returns w1Encode(UseHint(h, A[row] * z - c * t1 * 2^d)) for one row, in the first
/// `P::W1_POLY_LEN` bytes.
#[inline(never)]
fn w1_row<P: Params>(
    matrix: &impl sample::Matrix,
    row: u8,
    z: &[u8],
    c: &sample::Challenge,
    t1: &[u8],
    hints: &encode::ValidHints<P>,
) -> [u8; 192] {
    let mut w: Poly = [0; 256];
    let mut z_hat: Poly = [0; 256];
    for (col, z) in (0..).zip(z.chunks_exact(P::Z_POLY_LEN)) {
        for (out, z) in z_hat.iter_mut().zip(encode::unpack_z::<P>(z)) {
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
    encode::use_hints_encode::<P>(&w, hints, row)
}
