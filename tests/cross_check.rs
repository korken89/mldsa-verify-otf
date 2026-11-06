//! Signatures made by the `ml-dsa` crate verify here, and tampered inputs are rejected.

use ml_dsa::{Keypair, MlDsa65, SigningKey};
use mldsa_verify_otf::{Error, PUBLIC_KEY_LEN, SIGNATURE_LEN, verify, verify_with_context};
use shake::{ExtendableOutput, Shake128, Update, XofReader};

#[test]
fn ml_dsa_signatures() {
    let mut rng = Shake128::default().chain(b"cross check").finalize_xof();
    let mut seed = [0; 32];
    let mut len = [0; 2];
    for i in 0..100 {
        rng.read(&mut seed);
        rng.read(&mut len);
        let mut msg = vec![0; usize::from(u16::from_le_bytes(len)) % 3000];
        rng.read(&mut msg);
        let ctx: &[u8] = if i % 4 == 0 { b"some context" } else { &[] };

        let key = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let pk: [u8; PUBLIC_KEY_LEN] = key.verifying_key().encode().as_slice().try_into().unwrap();
        let sig = key.expanded_key().sign_deterministic(&msg, ctx).unwrap();
        let mut sig: [u8; SIGNATURE_LEN] = sig.encode().as_slice().try_into().unwrap();

        assert_eq!(verify_with_context(&pk, ctx, &[&msg], &sig), Ok(()));
        if ctx.is_empty() {
            assert_eq!(verify(&pk, &msg, &sig), Ok(()));
        } else {
            assert_eq!(verify(&pk, &msg, &sig), Err(Error::InvalidSignature));
        }
        let (a, b) = msg.split_at(msg.len() / 3);
        assert_eq!(verify_with_context(&pk, ctx, &[a, b], &sig), Ok(()));
        assert_eq!(
            verify_with_context(&pk, b"other", &[&msg], &sig),
            Err(Error::InvalidSignature)
        );

        let mut bit = [0; 4];
        rng.read(&mut bit);
        let bit = u32::from_le_bytes(bit) as usize;

        let mut bad_msg = msg.clone();
        bad_msg.push(0);
        assert!(verify_with_context(&pk, ctx, &[&bad_msg], &sig).is_err());
        if !msg.is_empty() {
            bad_msg = msg.clone();
            bad_msg[bit % msg.len()] ^= 1 << (bit % 8);
            assert!(verify_with_context(&pk, ctx, &[&bad_msg], &sig).is_err());
        }

        let mut bad_pk = pk;
        bad_pk[bit % PUBLIC_KEY_LEN] ^= 1 << (bit % 8);
        assert!(verify_with_context(&bad_pk, ctx, &[&msg], &sig).is_err());

        let i = bit % SIGNATURE_LEN;
        sig[i] ^= 1 << (bit % 8);
        // ml-dsa decodes the signature and verifies, so both must agree on the tampered one.
        let theirs = ml_dsa::Signature::<MlDsa65>::decode(&sig.into())
            .is_some_and(|s| key.verifying_key().verify_with_context(&msg, ctx, &s));
        let ours = verify_with_context(&pk, ctx, &[&msg], &sig).is_ok();
        assert_eq!(ours, theirs, "bit flip at byte {i}");
        assert!(!ours, "bit flip at byte {i} accepted");
    }
}
