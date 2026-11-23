//! Local ML-DSA-65 ITACOIN wallets and encrypted private-key storage.
//!
//! This module encrypts the 32-byte ML-DSA private seed using Argon2id-derived
//! keys and XChaCha20-Poly1305. It has no recovery phrase support: a backup of
//! the encrypted bytes and its password are both required for recovery.
//!
//! # File format `ITCW` version 2
//!
//! ```text
//! magic "ITCW" (4) || version = 2 (1)
//! || argon2 memory KiB (u32 BE) || argon2 passes (u32 BE) || argon2 lanes (u32 BE)
//! || salt (16) || XChaCha20 nonce (24)
//! || wallet id (32) || generation (u64 BE)
//! || ciphertext + Poly1305 tag (48)
//! ```
//!
//! Every byte before the ciphertext is the AEAD associated data, so the KDF
//! parameters, the wallet identity and the generation counter are all
//! authenticated. The wallet id and generation are readable without the
//! password so callers can check them before running the expensive KDF.

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use itacoin_crypto::{CryptoError, KeyPair, PrivateKey, PublicKey, Signature, SigningDomain};
use itacoin_primitives::{Address, Hash256, Network, WalletId};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

mod storage;

const WALLET_FILE_MAGIC: [u8; 4] = *b"ITCW";
const WALLET_FILE_VERSION: u8 = 2;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const WALLET_ID_BYTES: usize = 32;
const AUTH_TAG_BYTES: usize = 16;
const CIPHERTEXT_BYTES: usize = KEY_BYTES + AUTH_TAG_BYTES;
const HEADER_BYTES: usize = 4 + 1 + 3 * 4 + SALT_BYTES + NONCE_BYTES + WALLET_ID_BYTES + 8;

/// Minimum password length in bytes accepted by [`Password::new`].
pub const MIN_PASSWORD_BYTES: usize = 12;
/// Maximum password length in bytes accepted by [`Password::new`].
pub const MAX_PASSWORD_BYTES: usize = 1_024;

/// Argon2id cost parameters stored in, and authenticated by, a wallet file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes over memory.
    pub passes: u32,
    /// Degree of parallelism.
    pub lanes: u32,
}

impl KdfParams {
    /// Parameters used for newly encrypted wallets: 64 MiB, three passes,
    /// four lanes, the second recommended option of RFC 9106 section 4.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 4,
    };

    /// Weakest parameters a wallet file may declare (OWASP 2023 baseline).
    pub const MINIMUM: Self = Self {
        memory_kib: 19 * 1024,
        passes: 2,
        lanes: 1,
    };

    /// Strongest parameters a wallet file may declare. The upper bound keeps
    /// a hostile file from forcing the process to allocate unbounded memory.
    pub const MAXIMUM: Self = Self {
        memory_kib: 1024 * 1024,
        passes: 16,
        lanes: 16,
    };

    fn is_within_bounds(self) -> bool {
        (Self::MINIMUM.memory_kib..=Self::MAXIMUM.memory_kib).contains(&self.memory_kib)
            && (Self::MINIMUM.passes..=Self::MAXIMUM.passes).contains(&self.passes)
            && (Self::MINIMUM.lanes..=Self::MAXIMUM.lanes).contains(&self.lanes)
    }
}

/// A wallet password held in memory that is wiped when dropped.
///
/// Construct it directly from the buffer that received user input so that no
/// unprotected copy outlives this value.
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// Takes ownership of a password and checks the length policy.
    ///
    /// Length is only a floor: a long but guessable password is still weak
    /// against an offline attack on a stolen wallet file. Use a password
    /// manager to generate it.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, WalletError> {
        let bytes = Zeroizing::new(bytes.into());
        if bytes.len() < MIN_PASSWORD_BYTES {
            return Err(WalletError::PasswordTooShort {
                minimum: MIN_PASSWORD_BYTES,
            });
        }
        if bytes.len() > MAX_PASSWORD_BYTES {
            return Err(WalletError::PasswordTooLong {
                maximum: MAX_PASSWORD_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password(REDACTED)")
    }
}

/// An in-memory ITACOIN wallet.
///
/// `Debug` never prints private key material. Prefer encrypting and dropping a
/// wallet promptly once it has been persisted.
#[derive(Debug)]
pub struct Wallet {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Wallet {
    /// Creates a new ML-DSA-65 wallet using the operating system CSPRNG.
    pub fn create() -> Result<Self, WalletError> {
        let pair = KeyPair::generate().map_err(WalletError::Crypto)?;
        Ok(Self {
            private_key: pair.private_key,
            public_key: pair.public_key,
        })
    }

    /// Restores a wallet from a ML-DSA-65 private-key seed.
    pub fn from_private_key(private_key: PrivateKey) -> Result<Self, WalletError> {
        let public_key = private_key.public_key().map_err(WalletError::Crypto)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Returns this wallet's ML-DSA-65 public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the stable identifier derived from the public key.
    #[must_use]
    pub fn wallet_id(&self) -> WalletId {
        self.public_key.wallet_id()
    }

    /// Returns the checksummed address of this wallet on `network`.
    #[must_use]
    pub fn address(&self, network: Network) -> Address {
        Address::new(network, self.wallet_id())
    }

    /// Signs `message` in `domain` with this wallet's ML-DSA-65 key.
    pub fn sign(&self, domain: SigningDomain, message: &[u8]) -> Result<Signature, WalletError> {
        self.private_key
            .sign(domain, message)
            .map_err(WalletError::Crypto)
    }

    /// Verifies a signature made by a public key in `domain`.
    pub fn verify(
        public_key: &PublicKey,
        domain: SigningDomain,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), WalletError> {
        itacoin_crypto::verify(public_key, domain, message, signature).map_err(WalletError::Crypto)
    }

    /// Encrypts the private signing seed for local storage.
    ///
    /// `generation` must increase every time the stored wallet is rewritten
    /// so that a restored stale file can be detected as a rollback. A distinct
    /// random salt and nonce are created for every call.
    pub fn encrypt(
        &self,
        password: &Password,
        generation: u64,
    ) -> Result<EncryptedWallet, WalletError> {
        self.encrypt_with_params(password, generation, KdfParams::DEFAULT)
    }

    /// Like [`Wallet::encrypt`], with explicit Argon2id parameters.
    ///
    /// The parameters must lie between [`KdfParams::MINIMUM`] and
    /// [`KdfParams::MAXIMUM`].
    pub fn encrypt_with_params(
        &self,
        password: &Password,
        generation: u64,
        kdf: KdfParams,
    ) -> Result<EncryptedWallet, WalletError> {
        if !kdf.is_within_bounds() {
            return Err(WalletError::UnsupportedKdfParams);
        }
        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let mut encrypted = EncryptedWallet {
            kdf,
            salt,
            nonce,
            wallet_id: self.wallet_id(),
            generation,
            ciphertext: [0; CIPHERTEXT_BYTES],
        };
        let key = derive_key(password, &salt, kdf)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let seed = self.private_key.to_seed();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &*seed,
                    aad: &encrypted.header(),
                },
            )
            .map_err(|_| WalletError::EncryptionFailed)?;
        encrypted.ciphertext = ciphertext
            .try_into()
            .map_err(|_| WalletError::EncryptionFailed)?;
        Ok(encrypted)
    }
}

/// A versioned encrypted representation of a wallet's private signing seed.
///
/// See the crate documentation for the binary format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedWallet {
    kdf: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    wallet_id: WalletId,
    generation: u64,
    ciphertext: [u8; CIPHERTEXT_BYTES],
}

impl EncryptedWallet {
    /// Returns the wallet identifier recorded in the file.
    ///
    /// It is authenticated only once [`EncryptedWallet::decrypt`] succeeds;
    /// before that it is a claim, useful to reject the wrong file cheaply.
    #[must_use]
    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    /// Returns the generation counter recorded in the file.
    ///
    /// Like [`EncryptedWallet::wallet_id`], it is authenticated by decryption.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the Argon2id parameters recorded in the file.
    #[must_use]
    pub const fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    /// Decrypts a wallet using its password.
    ///
    /// Wrong passwords and tampered data deliberately yield the same error,
    /// avoiding an authenticity oracle. After decryption the recovered key
    /// must match the recorded wallet id.
    pub fn decrypt(&self, password: &Password) -> Result<Wallet, WalletError> {
        let key = derive_key(password, &self.salt, self.kdf)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let seed = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &self.header(),
                    },
                )
                .map_err(|_| WalletError::DecryptionFailed)?,
        );
        let private_key =
            PrivateKey::from_seed(&seed).map_err(|_| WalletError::DecryptionFailed)?;
        let wallet = Wallet::from_private_key(private_key)?;
        if wallet.wallet_id() != self.wallet_id {
            return Err(WalletError::IdentityMismatch);
        }
        Ok(wallet)
    }

    /// Decrypts a wallet only if it is the expected one and not a rollback.
    ///
    /// `expected` is the wallet id the caller already knows, for example from
    /// an address the user confirmed. `minimum_generation` is the highest
    /// generation the caller has previously seen. Both are checked before the
    /// KDF runs and are authenticated again by decryption.
    pub fn decrypt_checked(
        &self,
        password: &Password,
        expected: &WalletId,
        minimum_generation: u64,
    ) -> Result<Wallet, WalletError> {
        if self.wallet_id != *expected {
            return Err(WalletError::WrongWallet);
        }
        if self.generation < minimum_generation {
            return Err(WalletError::RolledBack {
                found: self.generation,
                minimum: minimum_generation,
            });
        }
        self.decrypt(password)
    }

    fn header(&self) -> [u8; HEADER_BYTES] {
        let mut header = [0_u8; HEADER_BYTES];
        let mut writer = Writer::new(&mut header);
        writer.put(&WALLET_FILE_MAGIC);
        writer.put(&[WALLET_FILE_VERSION]);
        writer.put(&self.kdf.memory_kib.to_be_bytes());
        writer.put(&self.kdf.passes.to_be_bytes());
        writer.put(&self.kdf.lanes.to_be_bytes());
        writer.put(&self.salt);
        writer.put(&self.nonce);
        writer.put(self.wallet_id.as_bytes());
        writer.put(&self.generation.to_be_bytes());
        header
    }

    /// Serializes the encrypted wallet into its fixed-size versioned binary form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::serialized_len());
        encoded.extend_from_slice(&self.header());
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    /// Parses an encrypted wallet from its fixed-size binary form.
    ///
    /// Version 1 files are rejected: that format did not authenticate its
    /// header and was never used to hold funds.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, WalletError> {
        if encoded.len() != Self::serialized_len()
            || encoded[..4] != WALLET_FILE_MAGIC
            || encoded[4] != WALLET_FILE_VERSION
        {
            return Err(WalletError::InvalidStorageFormat);
        }

        let mut reader = Reader::new(&encoded[5..]);
        let kdf = KdfParams {
            memory_kib: u32::from_be_bytes(reader.take()),
            passes: u32::from_be_bytes(reader.take()),
            lanes: u32::from_be_bytes(reader.take()),
        };
        if !kdf.is_within_bounds() {
            return Err(WalletError::UnsupportedKdfParams);
        }
        Ok(Self {
            kdf,
            salt: reader.take(),
            nonce: reader.take(),
            wallet_id: WalletId::new(Hash256::new(reader.take())),
            generation: u64::from_be_bytes(reader.take()),
            ciphertext: reader.take(),
        })
    }

    /// Returns the exact serialized wallet size in bytes.
    #[must_use]
    pub const fn serialized_len() -> usize {
        HEADER_BYTES + CIPHERTEXT_BYTES
    }
}

struct Writer<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        self.buffer[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
    }
}

/// Reads fixed-size fields from a buffer whose total length was checked.
struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (field, rest) = self.remaining.split_at(N);
        self.remaining = rest;
        field.try_into().expect("split_at returned N bytes")
    }
}

fn derive_key(
    password: &Password,
    salt: &[u8; SALT_BYTES],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, WalletError> {
    if !kdf.is_within_bounds() {
        return Err(WalletError::UnsupportedKdfParams);
    }
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(KEY_BYTES))
        .map_err(|_| WalletError::KeyDerivationFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|_| WalletError::KeyDerivationFailed)?;
    Ok(key)
}

/// Errors emitted by wallet creation, signing, encryption, storage and recovery.
#[derive(Debug)]
pub enum WalletError {
    /// An operation from the signature layer failed.
    Crypto(CryptoError),
    /// Encryption unexpectedly failed.
    EncryptionFailed,
    /// The password is shorter than the policy minimum.
    PasswordTooShort {
        /// Minimum length in bytes.
        minimum: usize,
    },
    /// The password is longer than the policy maximum.
    PasswordTooLong {
        /// Maximum length in bytes.
        maximum: usize,
    },
    /// The stored wallet bytes are malformed, unsupported, or truncated.
    InvalidStorageFormat,
    /// The Argon2id parameters are outside the accepted bounds.
    UnsupportedKdfParams,
    /// Password-based key derivation failed.
    KeyDerivationFailed,
    /// Authentication failed because the password was wrong or data was altered.
    DecryptionFailed,
    /// The decrypted key does not match the wallet id recorded in the file.
    IdentityMismatch,
    /// The file belongs to a different wallet than the caller expected.
    WrongWallet,
    /// The file is older than a generation the caller has already seen.
    RolledBack {
        /// Generation recorded in the file.
        found: u64,
        /// Minimum generation the caller required.
        minimum: u64,
    },
    /// The destination wallet file already exists.
    AlreadyExists,
    /// Another process or handle is writing this wallet file.
    Locked,
    /// The wallet file is readable or writable by other users.
    InsecurePermissions,
    /// A file-system operation failed.
    Io(std::io::Error),
}

impl fmt::Display for WalletError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => {
                write!(formatter, "wallet cryptographic operation failed: {error}")
            }
            Self::EncryptionFailed => formatter.write_str("wallet encryption failed"),
            Self::PasswordTooShort { minimum } => {
                write!(
                    formatter,
                    "wallet password must have at least {minimum} bytes"
                )
            }
            Self::PasswordTooLong { maximum } => {
                write!(
                    formatter,
                    "wallet password must have at most {maximum} bytes"
                )
            }
            Self::InvalidStorageFormat => formatter.write_str("invalid encrypted wallet format"),
            Self::UnsupportedKdfParams => {
                formatter.write_str("unsupported wallet key-derivation parameters")
            }
            Self::KeyDerivationFailed => formatter.write_str("wallet key derivation failed"),
            Self::DecryptionFailed => formatter.write_str("wallet decryption failed"),
            Self::IdentityMismatch => {
                formatter.write_str("decrypted key does not match the wallet id in the file")
            }
            Self::WrongWallet => formatter.write_str("wallet file belongs to a different wallet"),
            Self::RolledBack { found, minimum } => write!(
                formatter,
                "wallet file generation {found} is older than required generation {minimum}"
            ),
            Self::AlreadyExists => formatter.write_str("wallet file already exists"),
            Self::Locked => formatter.write_str("wallet file is locked by another writer"),
            Self::InsecurePermissions => {
                formatter.write_str("wallet file is accessible by other users")
            }
            Self::Io(error) => write!(formatter, "wallet file I/O failed: {error}"),
        }
    }
}

impl std::error::Error for WalletError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn password(text: &str) -> Password {
        Password::new(text).unwrap()
    }

    /// Cheapest accepted parameters, to keep tests fast.
    pub(crate) fn fast(wallet: &Wallet, pass: &Password, generation: u64) -> EncryptedWallet {
        wallet
            .encrypt_with_params(pass, generation, KdfParams::MINIMUM)
            .unwrap()
    }

    #[test]
    fn creates_signs_and_recovers_a_wallet() {
        let wallet = Wallet::create().unwrap();
        let message = b"wallet test";
        let signature = wallet.sign(SigningDomain::Message, message).unwrap();
        Wallet::verify(
            wallet.public_key(),
            SigningDomain::Message,
            message,
            &signature,
        )
        .unwrap();

        let pass = password("correct horse battery staple");
        let encrypted = wallet.encrypt(&pass, 0).unwrap();
        assert_eq!(encrypted.kdf_params(), KdfParams::DEFAULT);
        let encoded = encrypted.to_bytes();
        assert_eq!(encoded.len(), EncryptedWallet::serialized_len());
        let recovered = EncryptedWallet::from_bytes(&encoded)
            .unwrap()
            .decrypt(&pass)
            .unwrap();
        assert_eq!(recovered.wallet_id(), wallet.wallet_id());
        assert_eq!(
            recovered.address(Network::Mainnet),
            wallet.address(Network::Mainnet)
        );
        Wallet::verify(
            recovered.public_key(),
            SigningDomain::Message,
            message,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn encrypted_wallet_uses_fresh_randomness() {
        let wallet = Wallet::create().unwrap();
        let pass = password("same password!");
        assert_ne!(fast(&wallet, &pass, 0), fast(&wallet, &pass, 0));
    }

    #[test]
    fn rejects_wrong_password_and_tampering_of_every_byte() {
        let wallet = Wallet::create().unwrap();
        let pass = password("good password");
        let encrypted = fast(&wallet, &pass, 0);
        assert!(matches!(
            encrypted.decrypt(&password("wrong password")),
            Err(WalletError::DecryptionFailed)
        ));

        // Regression test for audit findings V-04 and V-05: every header byte
        // is authenticated, not only the ciphertext. KDF parameters are left
        // out because changing them is rejected or only changes the key.
        let encoded = encrypted.to_bytes();
        let kdf_fields = 5..17;
        for index in (0..encoded.len()).filter(|index| !kdf_fields.contains(index)) {
            let mut tampered = encoded.clone();
            tampered[index] ^= 1;
            match EncryptedWallet::from_bytes(&tampered) {
                Err(WalletError::InvalidStorageFormat) => assert!(index < 5),
                Ok(parsed) => assert!(
                    matches!(parsed.decrypt(&pass), Err(WalletError::DecryptionFailed)),
                    "byte {index}"
                ),
                Err(other) => panic!("byte {index}: {other}"),
            }
        }
    }

    #[test]
    fn detects_substitution_and_rollback() {
        let wallet = Wallet::create().unwrap();
        let other = Wallet::create().unwrap();
        let pass = password("shared password");
        let old = fast(&wallet, &pass, 1);
        let current = fast(&wallet, &pass, 2);
        let foreign = fast(&other, &pass, 2);

        current
            .decrypt_checked(&pass, &wallet.wallet_id(), 2)
            .unwrap();
        assert!(matches!(
            foreign.decrypt_checked(&pass, &wallet.wallet_id(), 2),
            Err(WalletError::WrongWallet)
        ));
        assert!(matches!(
            old.decrypt_checked(&pass, &wallet.wallet_id(), 2),
            Err(WalletError::RolledBack {
                found: 1,
                minimum: 2
            })
        ));

        // Forging the cleartext wallet id or generation breaks authentication.
        let mut forged = old.clone();
        forged.generation = 2;
        assert!(matches!(
            forged.decrypt_checked(&pass, &wallet.wallet_id(), 2),
            Err(WalletError::DecryptionFailed)
        ));
        let mut forged = foreign.clone();
        forged.wallet_id = wallet.wallet_id();
        assert!(matches!(
            forged.decrypt_checked(&pass, &wallet.wallet_id(), 2),
            Err(WalletError::DecryptionFailed)
        ));
    }

    #[test]
    fn enforces_password_policy() {
        assert!(matches!(
            Password::new(""),
            Err(WalletError::PasswordTooShort { .. })
        ));
        assert!(matches!(
            Password::new("a".repeat(MIN_PASSWORD_BYTES - 1)),
            Err(WalletError::PasswordTooShort { .. })
        ));
        Password::new("a".repeat(MIN_PASSWORD_BYTES)).unwrap();
        assert!(matches!(
            Password::new(vec![b'a'; MAX_PASSWORD_BYTES + 1]),
            Err(WalletError::PasswordTooLong { .. })
        ));
        assert_eq!(
            format!("{:?}", password("do not print me")),
            "Password(REDACTED)"
        );
    }

    #[test]
    fn rejects_out_of_bounds_kdf_parameters() {
        let wallet = Wallet::create().unwrap();
        let pass = password("good password");
        let weak = KdfParams {
            memory_kib: 1024,
            ..KdfParams::MINIMUM
        };
        assert!(matches!(
            wallet.encrypt_with_params(&pass, 0, weak),
            Err(WalletError::UnsupportedKdfParams)
        ));

        let mut encoded = fast(&wallet, &pass, 0).to_bytes();
        encoded[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            EncryptedWallet::from_bytes(&encoded),
            Err(WalletError::UnsupportedKdfParams)
        ));
    }

    #[test]
    fn rejects_malformed_and_legacy_storage() {
        assert!(matches!(
            EncryptedWallet::from_bytes(b"ITCW\x02"),
            Err(WalletError::InvalidStorageFormat)
        ));
        let mut legacy = vec![0_u8; EncryptedWallet::serialized_len()];
        legacy[..4].copy_from_slice(b"ITCW");
        legacy[4] = 1;
        assert!(matches!(
            EncryptedWallet::from_bytes(&legacy),
            Err(WalletError::InvalidStorageFormat)
        ));
    }
}
