//! Wycheproof and NIST ACVP vectors through the public API.
//!
//! `data/` holds the cases, trimmed to the fields used here, from C2SP/wycheproof
//! `testvectors_v1/mldsa_{44,65,87}_verify_test.json` (20b256949ea8) and usnistgov/ACVP-Server
//! `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json` (a7f283cdc87d), the test
//! groups that are external and pure, internal with external mu, and internal.

use mldsa_verify_otf::{Error, MlDsa44, MlDsa65, MlDsa87, ParameterSet, verify_with_context};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    id: u32,
    comment: String,
    valid: bool,
    #[serde(default, with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    ctx: Vec<u8>,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
    sig: Vec<u8>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(with = "hex")]
    pk: Vec<u8>,
    tests: Vec<Case>,
}

/// Runs one case and returns whether it verified. Wrong lengths cannot reach the API.
fn check<P: ParameterSet>(pk: &[u8], case: &Case) -> bool {
    let (Ok(pk), Ok(sig)) = (
        P::PublicKey::try_from(pk),
        P::Signature::try_from(&case.sig),
    ) else {
        return false;
    };
    let (pk, sig) = (&pk, &sig);
    let result = verify_with_context::<P>(pk, &case.ctx, &[&case.msg], sig);
    if case.ctx.len() > 255 {
        assert_eq!(result, Err(Error::ContextTooLong));
    }
    // The same message split into parts gives the same result.
    let (a, b) = case.msg.split_at(case.msg.len() / 2);
    assert_eq!(
        verify_with_context::<P>(pk, &case.ctx, &[a, &[], b], sig),
        result
    );
    result.is_ok()
}

fn tally(counts: &mut (usize, usize), case: &Case, ok: bool) {
    assert_eq!(ok, case.valid, "tcId {} ({})", case.id, case.comment);
    if case.valid {
        counts.0 += 1;
    } else {
        counts.1 += 1;
    }
}

fn wycheproof<P: ParameterSet>(json: &str) -> (usize, usize) {
    let groups: Vec<Group> = serde_json::from_str(json).unwrap();
    let mut counts = (0, 0);
    for group in &groups {
        for case in &group.tests {
            tally(&mut counts, case, check::<P>(&group.pk, case));
        }
    }
    counts
}

fn acvp_external_pure<P: ParameterSet>(json: &str) -> (usize, usize) {
    let cases: Vec<Case> = serde_json::from_str(json).unwrap();
    let mut counts = (0, 0);
    for case in &cases {
        tally(&mut counts, case, check::<P>(&case.pk, case));
    }
    counts
}

#[test]
fn wycheproof_44() {
    let json = include_str!("data/wycheproof_mldsa_44_verify.json");
    assert_eq!(wycheproof::<MlDsa44>(json), (77, 103));
}

#[test]
fn wycheproof_65() {
    let json = include_str!("data/wycheproof_mldsa_65_verify.json");
    assert_eq!(wycheproof::<MlDsa65>(json), (79, 131));
}

#[test]
fn wycheproof_87() {
    let json = include_str!("data/wycheproof_mldsa_87_verify.json");
    assert_eq!(wycheproof::<MlDsa87>(json), (71, 170));
}

#[test]
fn acvp_external_pure_44() {
    let json = include_str!("data/acvp_mldsa_44_sigver_external.json");
    assert_eq!(acvp_external_pure::<MlDsa44>(json), (3, 12));
}

#[test]
fn acvp_external_pure_65() {
    let json = include_str!("data/acvp_mldsa_65_sigver_external.json");
    assert_eq!(acvp_external_pure::<MlDsa65>(json), (3, 12));
}

#[test]
fn acvp_external_pure_87() {
    let json = include_str!("data/acvp_mldsa_87_sigver_external.json");
    assert_eq!(acvp_external_pure::<MlDsa87>(json), (3, 12));
}
