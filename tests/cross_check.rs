//! Signatures made by the `ml-dsa` crate verify here, and tampered inputs are rejected.

use ml_dsa::{Keypair, MlDsaParams, SigningKey};
use mldsa_verify_otf::{
    Error, MlDsa44, MlDsa65, MlDsa87, ParameterSet, verify, verify_with_context,
};
use shake::{ExtendableOutput, Shake128, Update, XofReader};

/// Cross checks the parameter set `P` here against `M` in `ml-dsa`.
fn ml_dsa_signatures<P: ParameterSet, M: MlDsaParams>() {
    let mut rng = Shake128::default().chain(b"cross check").finalize_xof();
    let mut seed = [0; 32];
    let mut len = [0; 2];
    for i in 0..100 {
        rng.read(&mut seed);
        rng.read(&mut len);
        let mut msg = vec![0; usize::from(u16::from_le_bytes(len)) % 3000];
        rng.read(&mut msg);
        let ctx: &[u8] = if i % 4 == 0 { b"some context" } else { &[] };

        let key = SigningKey::<M>::from_seed(&seed.into());
        let pk_bytes = key.verifying_key().encode();
        let pk = P::PublicKey::try_from(&pk_bytes).unwrap();
        let mut sig_bytes = key
            .expanded_key()
            .sign_deterministic(&msg, ctx)
            .unwrap()
            .encode();
        let sig = P::Signature::try_from(&sig_bytes).unwrap();

        assert_eq!(verify_with_context::<P>(&pk, ctx, &[&msg], &sig), Ok(()));
        if ctx.is_empty() {
            assert_eq!(verify::<P>(&pk, &msg, &sig), Ok(()));
        } else {
            assert_eq!(verify::<P>(&pk, &msg, &sig), Err(Error::InvalidSignature));
        }
        let (a, b) = msg.split_at(msg.len() / 3);
        assert_eq!(verify_with_context::<P>(&pk, ctx, &[a, b], &sig), Ok(()));
        assert_eq!(
            verify_with_context::<P>(&pk, b"other", &[&msg], &sig),
            Err(Error::InvalidSignature)
        );

        let mut bit = [0; 4];
        rng.read(&mut bit);
        let bit = u32::from_le_bytes(bit) as usize;

        let mut bad_msg = msg.clone();
        bad_msg.push(0);
        assert!(verify_with_context::<P>(&pk, ctx, &[&bad_msg], &sig).is_err());
        if !msg.is_empty() {
            bad_msg = msg.clone();
            bad_msg[bit % msg.len()] ^= 1 << (bit % 8);
            assert!(verify_with_context::<P>(&pk, ctx, &[&bad_msg], &sig).is_err());
        }

        let mut bad_pk = pk_bytes.clone();
        let j = bit % bad_pk.len();
        bad_pk[j] ^= 1 << (bit % 8);
        let bad_pk = P::PublicKey::try_from(&bad_pk).unwrap();
        assert!(verify_with_context::<P>(&bad_pk, ctx, &[&msg], &sig).is_err());

        let i = bit % sig_bytes.len();
        sig_bytes[i] ^= 1 << (bit % 8);
        let sig = P::Signature::try_from(&sig_bytes).unwrap();
        // ml-dsa decodes the signature and verifies, so both must agree on the tampered one.
        let theirs = ml_dsa::Signature::<M>::decode(&sig_bytes)
            .is_some_and(|s| key.verifying_key().verify_with_context(&msg, ctx, &s));
        let ours = verify_with_context::<P>(&pk, ctx, &[&msg], &sig).is_ok();
        assert_eq!(ours, theirs, "bit flip at byte {i}");
        assert!(!ours, "bit flip at byte {i} accepted");
    }
}

#[test]
fn ml_dsa_44_signatures() {
    ml_dsa_signatures::<MlDsa44, ml_dsa::MlDsa44>();
}

#[test]
fn ml_dsa_65_signatures() {
    ml_dsa_signatures::<MlDsa65, ml_dsa::MlDsa65>();
}

#[test]
fn ml_dsa_87_signatures() {
    ml_dsa_signatures::<MlDsa87, ml_dsa::MlDsa87>();
}
