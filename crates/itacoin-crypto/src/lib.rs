//! Cryptographic building blocks for ITACOIN.
//!
//! The hash functions use BLAKE3-256 with distinct, fixed derive-key contexts.
//! The signature API implements pure, hedged ML-DSA-65. Every signature is
//! bound to a [`SigningDomain`] through the FIPS 204 context string, so a
//! signature produced for one purpose never verifies for another.
//! This crate deliberately exposes raw, fixed-format encodings for protocol use.
//! They are versioned by the surrounding protocol, not self-describing formats.

use core::fmt;

use itacoin_primitives::{BlockId, Hash256, TransactionId, WalletId};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod mldsa;

/// Encoded ML-DSA-65 public-key length, defined by FIPS 204.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
/// Encoded ML-DSA-65 signature length, defined by FIPS 204.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
/// The serialized ML-DSA-65 private-key seed length.
pub const ML_DSA_65_PRIVATE_KEY_SEED_BYTES: usize = 32;

const BLOCK_HASH_CONTEXT: &str = "itacoin:block:v1";
const TRANSACTION_HASH_CONTEXT: &str = "itacoin:transaction:v1";
// v2: RFC 6962 tree shape. v1 duplicated the last node of odd levels, which
// made `[a, b, c]` and `[a, b, c, c]` share a root (audit finding V-01).
const MERKLE_EMPTY_CONTEXT: &str = "itacoin:merkle:empty:v2";
const MERKLE_LEAF_CONTEXT: &str = "itacoin:merkle:leaf:v2";
const MERKLE_NODE_CONTEXT: &str = "itacoin:merkle:node:v2";
const WALLET_ID_CONTEXT: &str = "itacoin:wallet-id:v1";
const INTERNAL_HASH_CONTEXT: &str = "itacoin:internal:v1";
const WITNESS_HASH_CONTEXT: &str = "itacoin:witness:v1";
const SPENT_OUTPUTS_CONTEXT: &str = "itacoin:spent-outputs:v1";
const SIGHASH_CONTEXT: &str = "itacoin:sighash:v1";

/// Upper bound on the number of leaves [`merkle_root`] accepts.
///
/// This is an API safety bound that keeps memory use predictable, not a
/// consensus rule. Consensus must enforce its own, smaller block limits before
/// building a tree from untrusted data.
pub const MAX_MERKLE_LEAVES: usize = 1 << 20;

/// Hashes a canonical block-header encoding.
///
/// The caller is responsible for canonical encoding and for enforcing size
/// limits on untrusted input before hashing.
#[must_use]
pub fn block_hash(header: &[u8]) -> BlockId {
    BlockId::new(hash_parts(BLOCK_HASH_CONTEXT, &[header]))
}

/// Hashes a canonical transaction encoding.
#[must_use]
pub fn transaction_hash(transaction: &[u8]) -> TransactionId {
    TransactionId::new(hash_parts(TRANSACTION_HASH_CONTEXT, &[transaction]))
}

/// Hashes the canonical encoding of a transaction's witness section.
///
/// Witnesses are excluded from the transaction id, so this hash is what lets a
/// block commit to them through its witness root.
#[must_use]
pub fn witness_hash(witnesses: &[u8]) -> Hash256 {
    hash_parts(WITNESS_HASH_CONTEXT, &[witnesses])
}

/// Hashes the canonical encodings of the outputs a transaction spends, in
/// input order.
#[must_use]
pub fn spent_outputs_hash(outputs: &[u8]) -> Hash256 {
    hash_parts(SPENT_OUTPUTS_CONTEXT, &[outputs])
}

/// Computes the message every witness of a transaction signs.
///
/// It binds the signature to one chain (`chain_id`, the genesis block id), to
/// the witness-free transaction id, and to the values and owners of the spent
/// outputs, so an offline signer cannot be misled about the amounts it spends.
#[must_use]
pub fn sighash(chain_id: &Hash256, txid: &TransactionId, spent_outputs: &Hash256) -> Hash256 {
    hash_parts(
        SIGHASH_CONTEXT,
        &[
            chain_id.as_bytes(),
            txid.as_bytes(),
            spent_outputs.as_bytes(),
        ],
    )
}

/// Derives a stable wallet identifier from a parsed ML-DSA-65 public key.
///
/// Taking a [`PublicKey`] rather than raw bytes guarantees the identifier was
/// derived from a correctly sized key encoding.
#[must_use]
pub fn wallet_id(public_key: &PublicKey) -> WalletId {
    WalletId::new(hash_parts(WALLET_ID_CONTEXT, &[public_key.as_bytes()]))
}

/// Hashes internal protocol data under a separately framed label.
///
/// The label lets callers separate independent internal uses without sharing a
/// hash domain. It is length-prefixed before the data.
#[must_use]
pub fn internal_hash(label: &[u8], data: &[u8]) -> Hash256 {
    hash_parts(INTERNAL_HASH_CONTEXT, &[label, data])
}

/// Computes a domain-separated binary Merkle root with the RFC 6962 shape.
///
/// Leaves are hashed under a leaf domain and interior nodes under a separate
/// node domain. An odd node at the end of a level is promoted unchanged to the
/// next level instead of being duplicated, so lists of different lengths never
/// share a root unless BLAKE3 collides. The result is identical to RFC 6962's
/// recursive definition, which splits at the largest power of two below `n`.
/// Empty trees have a fixed domain-separated root.
pub fn merkle_root(leaves: &[Hash256]) -> Result<Hash256, CryptoError> {
    if leaves.len() > MAX_MERKLE_LEAVES {
        return Err(CryptoError::TooManyMerkleLeaves {
            maximum: MAX_MERKLE_LEAVES,
            actual: leaves.len(),
        });
    }
    if leaves.is_empty() {
        return Ok(hash_parts(MERKLE_EMPTY_CONTEXT, &[]));
    }

    let mut level: Vec<Hash256> = leaves
        .iter()
        .map(|leaf| hash_parts(MERKLE_LEAF_CONTEXT, &[leaf.as_bytes()]))
        .collect();
    let mut width = level.len();
    while width > 1 {
        let mut next = 0;
        let mut index = 0;
        while index + 1 < width {
            level[next] = merkle_node(&level[index], &level[index + 1]);
            next += 1;
            index += 2;
        }
        if index < width {
            level[next] = level[index];
            next += 1;
        }
        width = next;
    }

    Ok(level[0])
}

fn merkle_node(left: &Hash256, right: &Hash256) -> Hash256 {
    hash_parts(MERKLE_NODE_CONTEXT, &[left.as_bytes(), right.as_bytes()])
}

fn hash_parts(context: &str, parts: &[&[u8]]) -> Hash256 {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        let length = u64::try_from(part.len()).expect("slice length fits in u64");
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    Hash256::new(*hasher.finalize().as_bytes())
}

/// A serializable ML-DSA-65 public key.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Parses and validates a canonical ML-DSA-65 public-key encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        validate_length(
            "ML-DSA-65 public key",
            ML_DSA_65_PUBLIC_KEY_BYTES,
            bytes.len(),
        )?;
        mldsa::check_public_key(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the canonical FIPS 204 public-key encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the deterministic ITACOIN wallet identifier for this key.
    #[must_use]
    pub fn wallet_id(&self) -> WalletId {
        wallet_id(self)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicKey")
            .field("bytes", &self.0.len())
            .field("wallet_id", &self.wallet_id())
            .finish()
    }
}

/// A serializable ML-DSA-65 signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Parses and validates an ML-DSA-65 signature encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        validate_length(
            "ML-DSA-65 signature",
            ML_DSA_65_SIGNATURE_BYTES,
            bytes.len(),
        )?;
        mldsa::check_signature(bytes).map_err(|_| CryptoError::MalformedSignature)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the canonical FIPS 204 signature encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Signature")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// An ML-DSA-65 signing key represented as its 32-byte FIPS 204 seed.
///
/// The seed is sufficient to regenerate the signing key. It is zeroized when
/// dropped and is intentionally never printable or serializable by `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    seed: [u8; ML_DSA_65_PRIVATE_KEY_SEED_BYTES],
}

impl PrivateKey {
    /// Parses a serialized 32-byte ML-DSA-65 signing-key seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        validate_length(
            "ML-DSA-65 private-key seed",
            ML_DSA_65_PRIVATE_KEY_SEED_BYTES,
            seed.len(),
        )?;
        let mut bytes = [0_u8; ML_DSA_65_PRIVATE_KEY_SEED_BYTES];
        bytes.copy_from_slice(seed);
        let key = Self { seed: bytes };
        bytes.zeroize();
        mldsa::check_seed(&key.seed).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(key)
    }

    /// Returns the private-key seed for protected local storage only.
    ///
    /// The copy is wrapped in [`Zeroizing`] so it is wiped when dropped.
    /// Callers must encrypt it immediately and must not copy it elsewhere.
    #[must_use]
    pub fn to_seed(&self) -> Zeroizing<[u8; ML_DSA_65_PRIVATE_KEY_SEED_BYTES]> {
        Zeroizing::new(self.seed)
    }

    /// Derives this private key's public key.
    pub fn public_key(&self) -> Result<PublicKey, CryptoError> {
        mldsa::public_key(&self.seed)
            .map(PublicKey)
            .map_err(|_| CryptoError::InvalidPrivateKey)
    }

    /// Creates a hedged ML-DSA-65 signature over `message` in `domain`.
    ///
    /// The domain is the FIPS 204 context string, so the signature verifies
    /// only under the same domain. Signing is hedged: fresh randomness from
    /// the operating system is mixed with the key, so signing the same message
    /// twice yields different signatures. This hardens against fault-injection
    /// attacks on deterministic signing (audit finding V-03).
    pub fn sign(&self, domain: SigningDomain, message: &[u8]) -> Result<Signature, CryptoError> {
        mldsa::sign(&self.seed, domain.context(), message)
            .map(Signature)
            .map_err(|_| CryptoError::SigningFailed)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateKey(REDACTED)")
    }
}

/// A matching ML-DSA-65 keypair.
#[derive(Debug)]
pub struct KeyPair {
    /// The private signing material.
    pub private_key: PrivateKey,
    /// The corresponding public verification key.
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generates a keypair using the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = mldsa::generate_seed().map_err(|_| CryptoError::KeyGenerationFailed)?;
        let private_key = PrivateKey { seed: *seed };
        let public_key = private_key.public_key()?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

/// The purpose a signature authorizes.
///
/// Each domain maps to a distinct FIPS 204 context string. A signature made in
/// one domain never verifies in another, which prevents an off-chain signed
/// message from being replayed as a transaction authorization (audit finding
/// V-02). Adding a domain is a protocol change; never reuse a context string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SigningDomain {
    /// Authorization of an on-chain transaction.
    Transaction,
    /// An off-chain message, such as a proof of address ownership.
    Message,
}

impl SigningDomain {
    /// Returns the FIPS 204 context string bound into signatures.
    #[must_use]
    pub const fn context(self) -> &'static [u8] {
        match self {
            Self::Transaction => b"ITACOIN:transaction:v1",
            Self::Message => b"ITACOIN:message:v1",
        }
    }
}

/// Verifies an ML-DSA-65 signature over `message` in `domain`.
pub fn verify(
    public_key: &PublicKey,
    domain: SigningDomain,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    // Both encodings were validated when the values were constructed.
    let valid = mldsa::verify(
        public_key.as_bytes(),
        domain.context(),
        message,
        signature.as_bytes(),
    )
    .map_err(|_| CryptoError::MalformedSignature)?;
    if valid {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

fn validate_length(
    component: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), CryptoError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CryptoError::InvalidLength {
            component,
            expected,
            actual,
        })
    }
}

/// Errors generated by the ITACOIN cryptographic interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// A fixed-format key or signature had the wrong number of bytes.
    InvalidLength {
        /// Human-readable component name.
        component: &'static str,
        /// Required byte length.
        expected: usize,
        /// Provided byte length.
        actual: usize,
    },
    /// The ML-DSA implementation could not access secure randomness.
    KeyGenerationFailed,
    /// The public key did not decode as ML-DSA-65.
    InvalidPublicKey,
    /// The private-key seed did not decode as ML-DSA-65.
    InvalidPrivateKey,
    /// The signature was not a canonical ML-DSA-65 encoding.
    MalformedSignature,
    /// Signing failed, typically because secure randomness was unavailable.
    SigningFailed,
    /// [`merkle_root`] received more leaves than [`MAX_MERKLE_LEAVES`].
    TooManyMerkleLeaves {
        /// Maximum accepted leaf count.
        maximum: usize,
        /// Provided leaf count.
        actual: usize,
    },
    /// The signature did not authenticate the supplied message and public key.
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                component,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "invalid {component} length: expected {expected}, got {actual}"
                )
            }
            Self::KeyGenerationFailed => formatter.write_str("ML-DSA key generation failed"),
            Self::InvalidPublicKey => formatter.write_str("invalid ML-DSA public key"),
            Self::InvalidPrivateKey => formatter.write_str("invalid ML-DSA private-key seed"),
            Self::MalformedSignature => formatter.write_str("malformed ML-DSA signature"),
            Self::SigningFailed => formatter.write_str("ML-DSA signing failed"),
            Self::TooManyMerkleLeaves { maximum, actual } => write!(
                formatter,
                "too many Merkle leaves: maximum {maximum}, got {actual}"
            ),
            Self::VerificationFailed => formatter.write_str("ML-DSA signature verification failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_deterministic_and_domain_separated() {
        let bytes = b"canonical bytes";
        assert_eq!(block_hash(bytes), block_hash(bytes));
        assert_ne!(
            block_hash(bytes).as_bytes(),
            transaction_hash(bytes).as_bytes()
        );
        assert_ne!(internal_hash(b"a", b"bc"), internal_hash(b"ab", b"c"));
    }

    #[test]
    fn every_hash_context_is_distinct() {
        let contexts = [
            BLOCK_HASH_CONTEXT,
            TRANSACTION_HASH_CONTEXT,
            MERKLE_EMPTY_CONTEXT,
            MERKLE_LEAF_CONTEXT,
            MERKLE_NODE_CONTEXT,
            WALLET_ID_CONTEXT,
            INTERNAL_HASH_CONTEXT,
            WITNESS_HASH_CONTEXT,
            SPENT_OUTPUTS_CONTEXT,
            SIGHASH_CONTEXT,
        ];
        let mut hashes: Vec<Hash256> = contexts
            .iter()
            .map(|context| hash_parts(context, &[b"same input"]))
            .collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), contexts.len());
        assert_eq!(
            witness_hash(b"x"),
            hash_parts(WITNESS_HASH_CONTEXT, &[b"x"])
        );
        assert_ne!(witness_hash(b"x"), spent_outputs_hash(b"x"));
    }

    fn leaves(count: usize) -> Vec<Hash256> {
        (0..count)
            .map(|index| {
                let mut bytes = [0_u8; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                Hash256::new(bytes)
            })
            .collect()
    }

    /// RFC 6962 section 2.1 recursive definition, used as an oracle.
    fn reference_root(leaves: &[Hash256]) -> Hash256 {
        match leaves.len() {
            0 => hash_parts(MERKLE_EMPTY_CONTEXT, &[]),
            1 => hash_parts(MERKLE_LEAF_CONTEXT, &[leaves[0].as_bytes()]),
            n => {
                let split = 1 << (usize::BITS - 1 - (n - 1).leading_zeros());
                merkle_node(
                    &reference_root(&leaves[..split]),
                    &reference_root(&leaves[split..]),
                )
            }
        }
    }

    #[test]
    fn merkle_root_matches_rfc6962_definition() {
        for count in 0..=70 {
            let leaves = leaves(count);
            assert_eq!(
                merkle_root(&leaves).unwrap(),
                reference_root(&leaves),
                "{count}"
            );
        }
    }

    #[test]
    fn merkle_root_has_no_duplicate_last_leaf_ambiguity() {
        // Regression test for audit finding V-01 (CVE-2012-2459 analogue).
        for count in 1..=64 {
            let original = leaves(count);
            let mut extended = original.clone();
            extended.push(*original.last().unwrap());
            assert_ne!(
                merkle_root(&original).unwrap(),
                merkle_root(&extended).unwrap(),
                "{count}"
            );
        }
        let mut roots: Vec<Hash256> = (0..=64)
            .map(|count| merkle_root(&leaves(count)).unwrap())
            .collect();
        roots.sort();
        roots.dedup();
        assert_eq!(roots.len(), 65);
    }

    #[test]
    fn merkle_root_distinguishes_leaf_from_node() {
        let pair = leaves(2);
        let node = merkle_root(&pair).unwrap();
        assert_ne!(merkle_root(&[node]).unwrap(), node);
    }

    #[test]
    fn merkle_root_rejects_oversized_input() {
        let oversized = vec![Hash256::new([0; 32]); MAX_MERKLE_LEAVES + 1];
        assert_eq!(
            merkle_root(&oversized),
            Err(CryptoError::TooManyMerkleLeaves {
                maximum: MAX_MERKLE_LEAVES,
                actual: MAX_MERKLE_LEAVES + 1,
            })
        );
    }

    #[test]
    fn key_generation_signing_and_serialization_round_trip() {
        let pair = KeyPair::generate().unwrap();
        let message = b"ITACOIN ML-DSA-65 test";
        let signature = pair
            .private_key
            .sign(SigningDomain::Transaction, message)
            .unwrap();
        verify(
            &pair.public_key,
            SigningDomain::Transaction,
            message,
            &signature,
        )
        .unwrap();

        let public_key = PublicKey::from_bytes(pair.public_key.as_bytes()).unwrap();
        let signature = Signature::from_bytes(signature.as_bytes()).unwrap();
        let private_key = PrivateKey::from_seed(&*pair.private_key.to_seed()).unwrap();
        assert_eq!(private_key.public_key().unwrap(), public_key);
        verify(&public_key, SigningDomain::Transaction, message, &signature).unwrap();
    }

    #[test]
    fn signatures_are_bound_to_their_domain() {
        // Regression test for audit finding V-02.
        let pair = KeyPair::generate().unwrap();
        let message = b"same bytes, different purpose";
        let as_message = pair
            .private_key
            .sign(SigningDomain::Message, message)
            .unwrap();
        let as_transaction = pair
            .private_key
            .sign(SigningDomain::Transaction, message)
            .unwrap();
        assert_eq!(
            verify(
                &pair.public_key,
                SigningDomain::Transaction,
                message,
                &as_message
            ),
            Err(CryptoError::VerificationFailed)
        );
        assert_eq!(
            verify(
                &pair.public_key,
                SigningDomain::Message,
                message,
                &as_transaction
            ),
            Err(CryptoError::VerificationFailed)
        );
        assert_ne!(
            SigningDomain::Message.context(),
            SigningDomain::Transaction.context()
        );
    }

    #[test]
    fn signing_is_hedged() {
        // Regression test for audit finding V-03.
        let pair = KeyPair::generate().unwrap();
        let first = pair.private_key.sign(SigningDomain::Message, b"m").unwrap();
        let second = pair.private_key.sign(SigningDomain::Message, b"m").unwrap();
        assert_ne!(first, second);
        for signature in [&first, &second] {
            verify(&pair.public_key, SigningDomain::Message, b"m", signature).unwrap();
        }
    }

    #[test]
    fn rejects_invalid_signature_message_and_public_key() {
        let pair = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let domain = SigningDomain::Transaction;
        let signature = pair.private_key.sign(domain, b"original").unwrap();
        assert_eq!(
            verify(&pair.public_key, domain, b"altered", &signature),
            Err(CryptoError::VerificationFailed)
        );
        assert_eq!(
            verify(&other.public_key, domain, b"original", &signature),
            Err(CryptoError::VerificationFailed)
        );
        assert!(matches!(
            Signature::from_bytes(&[0; ML_DSA_65_SIGNATURE_BYTES - 1]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            PublicKey::from_bytes(&[0; ML_DSA_65_PUBLIC_KEY_BYTES - 1]),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn rejects_malformed_signature_encoding() {
        // A correct length alone must not make a signature a valid encoding.
        assert_eq!(
            Signature::from_bytes(&[0; ML_DSA_65_SIGNATURE_BYTES]),
            Err(CryptoError::MalformedSignature)
        );
    }

    #[test]
    fn ml_dsa_is_confined_to_the_backend_module() {
        // Only `mldsa.rs` may call the unaudited implementation, so that it can
        // be replaced or cross-checked in one place.
        let forbidden = concat!("ml", "_dsa::");
        assert!(!include_str!("lib.rs").contains(forbidden));
        assert!(include_str!("mldsa.rs").contains(forbidden));
    }

    #[test]
    fn nist_acvp_mldsa65_key_generation_vectors() {
        // NIST ACVP-Server / ML-DSA-keyGen-FIPS204, test group 2 (ML-DSA-65),
        // tcId 26 and 27. The expected values below are BLAKE3-256 fingerprints
        // of the complete 1952-byte official `pk` fields. Fingerprinting keeps
        // the repository concise while still requiring byte-for-byte equality.
        // Source: https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json
        let vectors = [
            (
                [
                    0xA9, 0x91, 0xFD, 0x42, 0xB0, 0x71, 0xD4, 0x9C, 0x48, 0xAE, 0x3E, 0x75, 0xC6,
                    0x47, 0x45, 0x9E, 0x0D, 0xAA, 0xD1, 0xE1, 0xBA, 0x35, 0x6A, 0x04, 0x80, 0x19,
                    0x12, 0xD3, 0x29, 0x4B, 0xCF, 0xF8,
                ],
                "def581b81977c7f6ff10ebe0ab358bf78b6a86850087ef0b30274086b8ae0c77",
            ),
            (
                [
                    0x49, 0x4F, 0x29, 0xAD, 0x1C, 0x93, 0xAB, 0xB2, 0xB9, 0x54, 0x5B, 0xD1, 0x4C,
                    0xC5, 0x75, 0xA9, 0x8E, 0xCD, 0x30, 0x62, 0x13, 0x7B, 0x43, 0x9B, 0x49, 0xEB,
                    0x1A, 0x8C, 0xC6, 0x65, 0x2F, 0xC6,
                ],
                "8cc30f0280223383282785525ee2bfeecb1a050c50ba520e33f2a18bfc87bc94",
            ),
        ];

        for (seed, expected_public_key_fingerprint) in vectors {
            let private_key = PrivateKey::from_seed(&seed).unwrap();
            let public_key = private_key.public_key().unwrap();
            assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_BYTES);
            assert_eq!(
                blake3::hash(public_key.as_bytes()).to_hex().as_str(),
                expected_public_key_fingerprint
            );
        }
    }
}
