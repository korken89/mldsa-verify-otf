//! Wycheproof and NIST ACVP vectors through the public API.
//!
//! `data/` holds the ML-DSA-65 cases, trimmed to the fields used here, from
//! C2SP/wycheproof `testvectors_v1/mldsa_65_verify_test.json` (20b256949ea8) and
//! usnistgov/ACVP-Server `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`
//! (a7f283cdc87d), test groups 3 (external, pure), 9 (internal, external mu) and 10 (internal).

use mldsa_verify_otf::{Error, PUBLIC_KEY_LEN, SIGNATURE_LEN, verify_with_context};
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
fn check(pk: &[u8], case: &Case) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <&[u8; PUBLIC_KEY_LEN]>::try_from(pk),
        <&[u8; SIGNATURE_LEN]>::try_from(case.sig.as_slice()),
    ) else {
        return false;
    };
    let result = verify_with_context(pk, &case.ctx, &[&case.msg], sig);
    if case.ctx.len() > 255 {
        assert_eq!(result, Err(Error::ContextTooLong));
    }
    // The same message split into parts gives the same result.
    let (a, b) = case.msg.split_at(case.msg.len() / 2);
    assert_eq!(
        verify_with_context(pk, &case.ctx, &[a, &[], b], sig),
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

#[test]
fn wycheproof() {
    let groups: Vec<Group> =
        serde_json::from_str(include_str!("data/wycheproof_mldsa_65_verify.json")).unwrap();
    let mut counts = (0, 0);
    for group in &groups {
        for case in &group.tests {
            tally(&mut counts, case, check(&group.pk, case));
        }
    }
    assert_eq!(counts, (79, 131));
}

#[test]
fn acvp_external_pure() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("data/acvp_mldsa_65_sigver_external.json")).unwrap();
    let mut counts = (0, 0);
    for case in &cases {
        tally(&mut counts, case, check(&case.pk, case));
    }
    assert_eq!(counts, (3, 12));
}
