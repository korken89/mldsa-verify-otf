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

fn run(json: &str, mu_of: impl Fn(&[u8; PUBLIC_KEY_LEN], &Case) -> [u8; 64]) -> (usize, usize) {
    let cases: Vec<Case> = serde_json::from_str(json).unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for case in &cases {
        let pk = case.pk.as_slice().try_into().unwrap();
        let sig = case.sig.as_slice().try_into().unwrap();
        let mu = mu_of(pk, case);
        assert_eq!(verify_mu(pk, &mu, sig), case.valid, "tcId {}", case.id);
        if case.valid {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    (valid, invalid)
}

#[test]
fn acvp_internal_message() {
    let json = include_str!("../tests/data/acvp_mldsa_65_sigver_internal.json");
    let counts = run(json, |pk, case| mu(pk, [case.msg.as_slice()]));
    assert_eq!(counts, (3, 12));
}

#[test]
fn acvp_internal_mu() {
    let json = include_str!("../tests/data/acvp_mldsa_65_sigver_internal_mu.json");
    let counts = run(json, |_, case| case.mu.as_slice().try_into().unwrap());
    assert_eq!(counts, (3, 12));
}
