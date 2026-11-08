//! NTT checks and the NIST ACVP sigVer vectors for ML-DSA.Verify_internal.

use serde::Deserialize;

use super::*;
use crate::ntt::{Q, caddq};

#[test]
fn ntt_product_matches_schoolbook() {
    let a: Poly = core::array::from_fn(|i| (i as i32 * 7919) % Q);
    let b: Poly = core::array::from_fn(|i| (i as i32 * 104_729 + 3) % 1000);
    let mut want = [0i64; 256];
    for i in 0..256 {
        for j in 0..256 {
            let p = i64::from(a[i]) * i64::from(b[j]);
            // X^256 = -1
            if i + j < 256 {
                want[i + j] += p;
            } else {
                want[i + j - 256] -= p;
            }
        }
    }
    let (mut a_hat, mut b_hat) = (a, b);
    ntt(&mut a_hat);
    ntt(&mut b_hat);
    let mut c: Poly = core::array::from_fn(|i| reduce32(mont_mul(a_hat[i], b_hat[i])));
    inv_ntt_to_mont(&mut c);
    for (c, want) in c.iter().zip(want) {
        assert_eq!(i64::from(caddq(*c)), want.rem_euclid(i64::from(Q)));
    }
}

/// Every coefficient of every entry of A is the same.
struct ConstMatrix(i32);

impl sample::Matrix for ConstMatrix {
    fn entry(&self, _: u8, _: u8, mut f: impl FnMut(usize, i32)) {
        for n in 0..256 {
            f(n, self.0);
        }
    }
}

fn w1_row_largest_sums<P: Params>() {
    // A constant in the NTT domain is a constant polynomial, so with z = z0 in every column
    // A * z = l * a * z0. The largest a and z0 give the largest sums in the inverse NTT. An
    // overflow there moves w only a little, so t1 moves w over all of its HighBits values.
    let (a, z0) = (Q - 1, P::GAMMA1 - P::BETA - 1);
    let bits = P::Z_BITS as usize;
    let mut z = vec![0; P::L * P::Z_POLY_LEN];
    for col in z.chunks_exact_mut(P::Z_POLY_LEN) {
        for n in 0..256 {
            let v = P::GAMMA1 - if n == 0 { z0 } else { 0 };
            for bit in 0..bits {
                col[(bits * n + bit) / 8] |= ((v >> bit) as u8 & 1) << ((bits * n + bit) % 8);
            }
        }
    }
    let mut c = [0; 256];
    c[0] = 1;
    for t1 in 0..1024 {
        let mut t1_packed = [0; T1_POLY_LEN];
        t1_packed[..2].copy_from_slice(&u16::to_le_bytes(t1));
        let mut want = [0; 256];
        let w = P::L as i64 * i64::from(a) * i64::from(z0) - (i64::from(t1) << D);
        want[0] = w.rem_euclid(i64::from(Q)) as i32;
        let got = w1_row::<P>(&ConstMatrix(a), 0, &z, &c, &t1_packed, &[]);
        assert_eq!(got, encode::use_hints_encode::<P>(&want, &[]), "t1 = {t1}");
    }
}

#[test]
fn w1_row_largest_sums_44() {
    w1_row_largest_sums::<MlDsa44>();
}

#[test]
fn w1_row_largest_sums_65() {
    w1_row_largest_sums::<MlDsa65>();
}

#[test]
fn w1_row_largest_sums_87() {
    w1_row_largest_sums::<MlDsa87>();
}

#[test]
fn repeated_hint_index_rejected() {
    let mut hints = [0; MlDsa65::OMEGA + MlDsa65::K];
    hints[..2].copy_from_slice(&[5, 6]);
    hints[MlDsa65::OMEGA..].fill(2);
    assert!(encode::hints_valid::<MlDsa65>(&hints));
    hints[1] = 5;
    assert!(!encode::hints_valid::<MlDsa65>(&hints));
}

#[test]
fn backwards_hint_limit_rejected() {
    let mut hints = [0; MlDsa65::OMEGA + MlDsa65::K];
    hints[..2].copy_from_slice(&[5, 6]);
    hints[MlDsa65::OMEGA..].copy_from_slice(&[1, 2, 2, 2, 2, 2]);
    assert!(encode::hints_valid::<MlDsa65>(&hints));
    hints[MlDsa65::OMEGA + 2] = 1;
    assert!(!encode::hints_valid::<MlDsa65>(&hints));
}

#[derive(Deserialize)]
struct Case {
    id: u32,
    valid: bool,
    #[serde(with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    sig: Vec<u8>,
    #[serde(default, with = "hex")]
    msg: Vec<u8>,
    #[serde(default, with = "hex")]
    mu: Vec<u8>,
}

fn run<P: ParameterSet>(json: &str, mu_of: impl Fn(&[u8], &Case) -> [u8; 64]) -> (usize, usize) {
    let cases: Vec<Case> = serde_json::from_str(json).unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for case in &cases {
        let pk = P::PublicKey::try_from(&case.pk).unwrap();
        let sig = P::Signature::try_from(&case.sig).unwrap();
        let mu = mu_of(pk.as_ref(), case);
        let ok = verify_mu::<P>(pk.as_ref(), &mu, sig.as_ref());
        assert_eq!(ok, case.valid, "tcId {}", case.id);
        if case.valid {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    (valid, invalid)
}

fn acvp_internal_message<P: ParameterSet>(json: &str) {
    let counts = run::<P>(json, |pk, case| mu(pk, [case.msg.as_slice()]));
    assert_eq!(counts, (3, 12));
}

fn acvp_internal_mu<P: ParameterSet>(json: &str) {
    let counts = run::<P>(json, |_, case| case.mu.as_slice().try_into().unwrap());
    assert_eq!(counts, (3, 12));
}

#[test]
fn acvp_internal_message_44() {
    acvp_internal_message::<MlDsa44>(include_str!(
        "../tests/data/acvp_mldsa_44_sigver_internal.json"
    ));
}

#[test]
fn acvp_internal_message_65() {
    acvp_internal_message::<MlDsa65>(include_str!(
        "../tests/data/acvp_mldsa_65_sigver_internal.json"
    ));
}

#[test]
fn acvp_internal_message_87() {
    acvp_internal_message::<MlDsa87>(include_str!(
        "../tests/data/acvp_mldsa_87_sigver_internal.json"
    ));
}

#[test]
fn acvp_internal_mu_44() {
    acvp_internal_mu::<MlDsa44>(include_str!(
        "../tests/data/acvp_mldsa_44_sigver_internal_mu.json"
    ));
}

#[test]
fn acvp_internal_mu_65() {
    acvp_internal_mu::<MlDsa65>(include_str!(
        "../tests/data/acvp_mldsa_65_sigver_internal_mu.json"
    ));
}

#[test]
fn acvp_internal_mu_87() {
    acvp_internal_mu::<MlDsa87>(include_str!(
        "../tests/data/acvp_mldsa_87_sigver_internal_mu.json"
    ));
}
