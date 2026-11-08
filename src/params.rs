//! The ML-DSA parameter sets (FIPS 204 section 4).

use core::array::TryFromSliceError;

use crate::ntt::Q;

/// Bytes of one packed t1 polynomial (10 bits per coefficient).
pub const T1_POLY_LEN: usize = 320;

/// An ML-DSA parameter set, used as `verify::<MlDsa65>(..)`.
pub trait ParameterSet: Params {
    /// An encoded public key.
    type PublicKey: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = TryFromSliceError> + 'static;
    /// An encoded signature.
    type Signature: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = TryFromSliceError> + 'static;
}

/// The constants of a parameter set. The trait is public in a private module, so it seals
/// `ParameterSet` and keeps the constants out of the public API.
pub trait Params {
    /// Rows of A (k).
    const K: usize;
    /// Columns of A (l).
    const L: usize;
    /// Nonzero coefficients of c (tau).
    const TAU: usize;
    /// tau * eta.
    const BETA: i32;
    /// log2 of gamma1.
    const GAMMA1_BITS: u32;
    /// Low-order rounding range (gamma2).
    const GAMMA2: i32;
    /// Maximum number of 1s in the hint (omega).
    const OMEGA: usize;
    /// Length of the commitment hash c~ (lambda / 4).
    const C_TILDE_LEN: usize;

    /// Coefficient range of y (gamma1).
    const GAMMA1: i32 = 1 << Self::GAMMA1_BITS;
    /// Bits of one packed z coefficient.
    const Z_BITS: u32 = Self::GAMMA1_BITS + 1;
    /// Bytes of one packed z polynomial.
    const Z_POLY_LEN: usize = 32 * Self::Z_BITS as usize;
    /// Number of values of w1, (q - 1) / (2 * gamma2).
    const W1_MOD: i32 = (Q - 1) / (2 * Self::GAMMA2);
    /// Bits of one packed w1 coefficient.
    const W1_BITS: u32 = i32::BITS - (Self::W1_MOD - 1).leading_zeros();
    /// Bytes of one packed w1 polynomial.
    const W1_POLY_LEN: usize = 32 * Self::W1_BITS as usize;
}

const fn public_key_len<P: Params>() -> usize {
    32 + P::K * T1_POLY_LEN
}

const fn signature_len<P: Params>() -> usize {
    P::C_TILDE_LEN + P::L * P::Z_POLY_LEN + P::OMEGA + P::K
}

/// ML-DSA-44, security category 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsa44;

impl Params for MlDsa44 {
    const K: usize = 4;
    const L: usize = 4;
    const TAU: usize = 39;
    const BETA: i32 = 78;
    const GAMMA1_BITS: u32 = 17;
    const GAMMA2: i32 = (Q - 1) / 88;
    const OMEGA: usize = 80;
    const C_TILDE_LEN: usize = 32;
}

impl ParameterSet for MlDsa44 {
    type PublicKey = [u8; public_key_len::<Self>()];
    type Signature = [u8; signature_len::<Self>()];
}

/// ML-DSA-65, security category 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsa65;

impl Params for MlDsa65 {
    const K: usize = 6;
    const L: usize = 5;
    const TAU: usize = 49;
    const BETA: i32 = 196;
    const GAMMA1_BITS: u32 = 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const OMEGA: usize = 55;
    const C_TILDE_LEN: usize = 48;
}

impl ParameterSet for MlDsa65 {
    type PublicKey = [u8; public_key_len::<Self>()];
    type Signature = [u8; signature_len::<Self>()];
}

/// ML-DSA-87, security category 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsa87;

impl Params for MlDsa87 {
    const K: usize = 8;
    const L: usize = 7;
    const TAU: usize = 60;
    const BETA: i32 = 120;
    const GAMMA1_BITS: u32 = 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const OMEGA: usize = 75;
    const C_TILDE_LEN: usize = 64;
}

impl ParameterSet for MlDsa87 {
    type PublicKey = [u8; public_key_len::<Self>()];
    type Signature = [u8; signature_len::<Self>()];
}

// The sizes in FIPS 204 Table 2.
const _: () = assert!(public_key_len::<MlDsa44>() == 1312 && signature_len::<MlDsa44>() == 2420);
const _: () = assert!(public_key_len::<MlDsa65>() == 1952 && signature_len::<MlDsa65>() == 3309);
const _: () = assert!(public_key_len::<MlDsa87>() == 2592 && signature_len::<MlDsa87>() == 4627);
