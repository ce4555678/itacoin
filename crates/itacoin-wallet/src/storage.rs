//! Durable, private wallet files.
//!
//! Writes go to a fresh temporary file in the destination directory that is
//! created with owner-only permissions, flushed to disk, and then atomically
//! moved into place. The directory is synced so the rename itself survives a
//! crash. A reader never observes a partially written wallet.
//!
//! Writers take an exclusive advisory lock on a sibling `.<name>.lock` file
//! for the whole check-then-write sequence, so two processes cannot both pass
//! the rollback check in [`EncryptedWallet::replace`] and race their renames.
//! The lock file is never deleted: removing it would let a waiting writer lock
//! an unlinked inode while a new writer locks a fresh one. Readers do not lock,
//! because the rename that publishes a new version is atomic.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use rand_core::{OsRng, RngCore};

use crate::{EncryptedWallet, WalletError};

impl EncryptedWallet {
    /// Writes a new wallet file, failing if `path` already exists.
    ///
    /// Fails with [`WalletError::Locked`] while another writer holds the lock.
    pub fn write_new(&self, path: &Path) -> Result<(), WalletError> {
        let _lock = WriteLock::acquire(path)?;
        let temporary = write_temporary(path, &self.to_bytes())?;
        // A hard link never replaces an existing file, so this is an atomic
        // "create if absent" that cannot clobber another wallet.
        let linked = fs::hard_link(&temporary, path);
        let removed = fs::remove_file(&temporary);
        match linked {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(WalletError::AlreadyExists);
            }
            other => other.map_err(WalletError::Io)?,
        }
        removed.map_err(WalletError::Io)?;
        sync_parent(path)
    }

    /// Atomically replaces an existing wallet file with this one.
    ///
    /// The existing file must belong to the same wallet and have a strictly
    /// lower generation; this refuses accidental rollbacks and substitutions.
    /// The check and the rename happen under one exclusive lock, and the call
    /// fails with [`WalletError::Locked`] while another writer holds it.
    pub fn replace(&self, path: &Path) -> Result<(), WalletError> {
        let _lock = WriteLock::acquire(path)?;
        let existing = Self::read(path)?;
        if existing.identity() != self.identity() || existing.kind() != self.kind() {
            return Err(WalletError::WrongWallet);
        }
        if existing.generation() >= self.generation() {
            return Err(WalletError::RolledBack {
                found: self.generation(),
                minimum: existing.generation().saturating_add(1),
            });
        }

        let temporary = write_temporary(path, &self.to_bytes())?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(WalletError::Io(error));
        }
        sync_parent(path)
    }

    /// Reads and parses a wallet file.
    ///
    /// On Unix the file must not be accessible by group or other users.
    pub fn read(path: &Path) -> Result<Self, WalletError> {
        let file = File::open(path).map_err(WalletError::Io)?;
        let metadata = file.metadata().map_err(WalletError::Io)?;
        check_private(&metadata)?;
        let expected = Self::serialized_len();
        if usize::try_from(metadata.len()).ok() != Some(expected) {
            return Err(WalletError::InvalidStorageFormat);
        }

        // Bound the read even if the file grows after the metadata check.
        let mut encoded = Vec::with_capacity(expected);
        file.take(expected as u64 + 1)
            .read_to_end(&mut encoded)
            .map_err(WalletError::Io)?;
        Self::from_bytes(&encoded)
    }
}

/// An exclusive lock on a wallet path, released when dropped.
struct WriteLock(#[allow(dead_code)] File);

impl WriteLock {
    fn acquire(path: &Path) -> Result<Self, WalletError> {
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(file_name(path)?);
        lock_name.push(".lock");

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options
            .open(path.with_file_name(lock_name))
            .map_err(WalletError::Io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self(file)),
            Err(TryLockError::WouldBlock) => Err(WalletError::Locked),
            Err(TryLockError::Error(error)) => Err(WalletError::Io(error)),
        }
    }
}

fn file_name(path: &Path) -> Result<&std::ffi::OsStr, WalletError> {
    path.file_name()
        .ok_or_else(|| WalletError::Io(io::Error::from(io::ErrorKind::InvalidInput)))
}

fn write_temporary(path: &Path, bytes: &[u8]) -> Result<PathBuf, WalletError> {
    let file_name = file_name(path)?;
    let mut suffix = [0_u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{suffix}.tmp"));
    let temporary = path.with_file_name(temporary_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

    let result = options.open(&temporary).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    match result {
        Ok(()) => Ok(temporary),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(WalletError::Io(error))
        }
    }
}

#[cfg(unix)]
fn check_private(metadata: &fs::Metadata) -> Result<(), WalletError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(WalletError::InsecurePermissions)
    }
}

#[cfg(not(unix))]
fn check_private(_metadata: &fs::Metadata) -> Result<(), WalletError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), WalletError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(WalletError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), WalletError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Wallet,
        tests::{fast, password},
    };

    #[test]
    fn writes_reads_and_refuses_to_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.itcw");
        let wallet = Wallet::create().unwrap();
        let pass = password("file password");
        let encrypted = fast(&wallet, &pass, 0);

        encrypted.write_new(&path).unwrap();
        assert_eq!(EncryptedWallet::read(&path).unwrap(), encrypted);
        assert!(matches!(
            fast(&wallet, &pass, 0).write_new(&path),
            Err(WalletError::AlreadyExists)
        ));
        assert_eq!(EncryptedWallet::read(&path).unwrap(), encrypted);
        // No temporary files are left behind; only the wallet and its lock.
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn replace_requires_same_wallet_and_newer_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.itcw");
        let wallet = Wallet::create().unwrap();
        let pass = password("file password");
        fast(&wallet, &pass, 1).write_new(&path).unwrap();

        assert!(matches!(
            fast(&wallet, &pass, 1).replace(&path),
            Err(WalletError::RolledBack { .. })
        ));
        assert!(matches!(
            fast(&Wallet::create().unwrap(), &pass, 5).replace(&path),
            Err(WalletError::WrongWallet)
        ));

        let newer = fast(&wallet, &pass, 2);
        newer.replace(&path).unwrap();
        assert_eq!(EncryptedWallet::read(&path).unwrap(), newer);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn concurrent_writers_are_refused_while_locked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.itcw");
        let wallet = Wallet::create().unwrap();
        let pass = password("file password");
        fast(&wallet, &pass, 1).write_new(&path).unwrap();

        let held = WriteLock::acquire(&path).unwrap();
        assert!(matches!(
            fast(&wallet, &pass, 2).replace(&path),
            Err(WalletError::Locked)
        ));
        let other = directory.path().join("other.itcw");
        let _other_lock = WriteLock::acquire(&other).unwrap();
        assert!(matches!(
            fast(&wallet, &pass, 0).write_new(&other),
            Err(WalletError::Locked)
        ));
        // Readers never block on the writer lock.
        assert_eq!(EncryptedWallet::read(&path).unwrap().generation(), 1);

        drop(held);
        fast(&wallet, &pass, 2).replace(&path).unwrap();
        assert_eq!(EncryptedWallet::read(&path).unwrap().generation(), 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock = directory.path().join(".wallet.itcw.lock");
            assert_eq!(
                fs::metadata(lock).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_files_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.itcw");
        let wallet = Wallet::create().unwrap();
        fast(&wallet, &password("file password"), 0)
            .write_new(&path)
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            EncryptedWallet::read(&path),
            Err(WalletError::InsecurePermissions)
        ));
    }

    #[test]
    fn rejects_files_of_the_wrong_size() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.itcw");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(&path)
            .unwrap()
            .write_all(&vec![0; EncryptedWallet::serialized_len() + 1])
            .unwrap();
        assert!(matches!(
            EncryptedWallet::read(&path),
            Err(WalletError::InvalidStorageFormat)
        ));
    }
}
