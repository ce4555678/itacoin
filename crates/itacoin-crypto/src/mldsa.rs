//! The only module that touches the ML-DSA implementation.
//!
//! RustCrypto `ml-dsa` 0.1.2 has not had an independent audit. Every call into
//! it is confined to this file and works on plain byte encodings, so replacing
//! or cross-checking the implementation means rewriting only these functions.
//! A replacement must keep the FIPS 204 encodings and pass the module tests in
//! `lib.rs`, including the NIST ACVP vectors.
//!
//! Callers in `lib.rs` check every length before calling in here.

use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, SigningKey,
    VerifyingKey, common::getrandom::SysRng,
};
use zeroize::Zeroizing;

use crate::{ML_DSA_65_PRIVATE_KEY_SEED_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES};

pub(crate) type Seed = [u8; ML_DSA_65_PRIVATE_KEY_SEED_BYTES];

/// Failure reported by the backend. Callers map it to a precise `CryptoError`.
#[derive(Debug)]
pub(crate) struct BackendError;

/// Generates a fresh seed from the operating-system CSPRNG.
pub(crate) fn generate_seed() -> Result<Zeroizing<Seed>, BackendError> {
    let signing_key = SigningKey::<MlDsa65>::try_generate().map_err(|_| BackendError)?;
    let mut seed = Zeroizing::new([0_u8; ML_DSA_65_PRIVATE_KEY_SEED_BYTES]);
    seed.copy_from_slice(signing_key.to_bytes().as_ref());
    Ok(seed)
}

/// Checks that a seed expands to a signing key.
pub(crate) fn check_seed(seed: &Seed) -> Result<(), BackendError> {
    signing_key(seed).map(drop)
}

/// Derives the encoded public key for a seed (FIPS 204 `ML-DSA.KeyGen_internal`).
pub(crate) fn public_key(seed: &Seed) -> Result<Vec<u8>, BackendError> {
    let encoded = signing_key(seed)?.verifying_key().to_bytes();
    debug_assert_eq!(encoded.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    Ok(encoded.to_vec())
}

/// Checks that bytes decode as a public key.
pub(crate) fn check_public_key(encoded: &[u8]) -> Result<(), BackendError> {
    verifying_key(encoded).map(drop)
}

/// Checks that bytes decode as a canonical signature.
pub(crate) fn check_signature(encoded: &[u8]) -> Result<(), BackendError> {
    Signature::<MlDsa65>::try_from(encoded)
        .map(drop)
        .map_err(|_| BackendError)
}

/// Hedged `ML-DSA.Sign` with a FIPS 204 context string.
pub(crate) fn sign(seed: &Seed, context: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError> {
    let signature = signing_key(seed)?
        .expanded_key()
        .sign_randomized(message, context, &mut SysRng)
        .map_err(|_| BackendError)?;
    Ok(signature.to_bytes().to_vec())
}

/// `ML-DSA.Verify` with a FIPS 204 context string.
pub(crate) fn verify(
    public_key: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, BackendError> {
    let key = verifying_key(public_key)?;
    let signature = Signature::<MlDsa65>::try_from(signature).map_err(|_| BackendError)?;
    Ok(key.verify_with_context(message, context, &signature))
}

fn signing_key(seed: &Seed) -> Result<SigningKey<MlDsa65>, BackendError> {
    SigningKey::<MlDsa65>::new_from_slice(seed).map_err(|_| BackendError)
}

fn verifying_key(encoded: &[u8]) -> Result<VerifyingKey<MlDsa65>, BackendError> {
    VerifyingKey::<MlDsa65>::new_from_slice(encoded).map_err(|_| BackendError)
}

#[cfg(test)]
mod tests {
    //! NIST ACVP vectors for the backend, run against the exact FIPS 204
    //! interface ITACOIN uses: ML-DSA-65, external, pure, with a context.

    use ml_dsa::{B32, ExpandedSigningKey, ExpandedSigningKeyBytes};

    use super::*;

    const SIGGEN: &str = include_str!("../vectors/acvp-mldsa65-siggen.txt");
    const SIGVER: &str = include_str!("../vectors/acvp-mldsa65-sigver.txt");

    fn hex(field: &str) -> Vec<u8> {
        if field == "-" {
            return Vec::new();
        }
        assert_eq!(field.len() % 2, 0, "odd hex length");
        (0..field.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&field[index..index + 2], 16).unwrap())
            .collect()
    }

    fn records(file: &str) -> impl Iterator<Item = Vec<&str>> {
        file.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split(' ').collect())
    }

    #[test]
    fn nist_acvp_mldsa65_signature_generation() {
        let mut count = 0;
        for fields in records(SIGGEN) {
            let [tc_id, rnd, sk, context, message, expected] = fields[..] else {
                panic!("malformed record");
            };
            let rnd = hex(rnd);
            let rnd = if rnd.is_empty() { vec![0; 32] } else { rnd };
            let rnd = B32::try_from(&rnd[..]).unwrap();
            let sk = ExpandedSigningKeyBytes::<MlDsa65>::try_from(&hex(sk)[..]).unwrap();
            // ACVP supplies the expanded `sk`, which ITACOIN never stores. The
            // deprecated decoder is acceptable here because the input is trusted.
            #[allow(deprecated)]
            let key = ExpandedSigningKey::<MlDsa65>::from_expanded(&sk);
            let context = hex(context);
            let context_length = [0, u8::try_from(context.len()).unwrap()];
            // FIPS 204 Algorithm 2: M' = 0 || |ctx| || ctx || M.
            let signature = key.sign_internal(&[&context_length, &context, &hex(message)], &rnd);
            assert_eq!(
                signature.to_bytes().as_slice(),
                hex(expected),
                "tcId {tc_id}"
            );
            count += 1;
        }
        assert_eq!(count, 30);
    }

    #[test]
    fn nist_acvp_mldsa65_signature_verification() {
        let (mut accepted, mut rejected) = (0, 0);
        for fields in records(SIGVER) {
            let [tc_id, passed, pk, context, message, signature] = fields[..] else {
                panic!("malformed record");
            };
            let expected = passed == "1";
            // A decoding failure is a rejection, exactly as in `crate::verify`.
            let valid =
                verify(&hex(pk), &hex(context), &hex(message), &hex(signature)).unwrap_or(false);
            assert_eq!(valid, expected, "tcId {tc_id}");
            if expected {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert_eq!((accepted, rejected), (3, 12));
    }

    #[test]
    fn hedged_signing_matches_the_acvp_construction() {
        // `sign` must be FIPS 204 external/pure signing, so that the vectors
        // above validate the code path ITACOIN actually calls.
        let seed = generate_seed().unwrap();
        let public_key = public_key(&seed).unwrap();
        let signature = sign(&seed, b"ctx", b"message").unwrap();
        assert!(verify(&public_key, b"ctx", b"message", &signature).unwrap());
        assert!(!verify(&public_key, b"ctx2", b"message", &signature).unwrap());
    }
}
