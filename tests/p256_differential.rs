//! TLS P-256 agreement against the existing independent AWS-LC dev oracle.
use aws_lc_rs::agreement::{ECDH_P256, PrivateKey, UnparsedPublicKey, agree};
use rust_reality::crypto::EphemeralP256Key;

#[test]
fn tls_p256_secrets_match_independent_provider() {
    for round in 1_u32..=128 {
        let mut scalar = [0_u8; 32];
        scalar[28..].copy_from_slice(&round.to_be_bytes());
        let oracle = PrivateKey::from_private_key(&ECDH_P256, &scalar).unwrap();
        let oracle_public = oracle.compute_public_key().unwrap();
        let key = EphemeralP256Key::generate().unwrap();
        let public = key.public_key();
        let expected = agree(
            &oracle,
            UnparsedPublicKey::new(&ECDH_P256, public),
            (),
            |secret| <[u8; 32]>::try_from(secret).map_err(drop),
        )
        .unwrap();
        let actual = key.agree(oracle_public.as_ref()).unwrap();
        assert_eq!(*actual, expected, "P-256 differential round {round}");
    }
}
