//! Process protections (section 6.4 of `docs/NODE_PROPOSAL.md`, finding
//! V-07) and the data directory lock (section 6.2), through `rustix` so the
//! workspace keeps `unsafe` forbidden.

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

/// Disables core dumps, `ptrace` by same-user processes and group/other
/// access to new files. Returns warnings for steps the platform refused.
pub fn harden() -> Vec<String> {
    let mut warnings = Vec::new();
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        if let Err(error) = setrlimit(Resource::Core, none) {
            warnings.push(format!("could not disable core dumps: {error}"));
        }
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        if let Err(error) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
            warnings.push(format!("could not mark the process non-dumpable: {error}"));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    warnings.push("PR_SET_DUMPABLE is unavailable on this platform".into());
    warnings
}

/// Creates the data directory with permission 0700.
pub fn create_data_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// An exclusive lock on the data directory, released and removed on drop.
#[derive(Debug)]
pub struct DirLock {
    path: PathBuf,
    _file: File,
}

impl DirLock {
    /// Takes the lock, failing at once if another process holds it.
    pub fn acquire(directory: &Path) -> Result<Self, String> {
        let path = directory.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|error| format!("could not open {}: {error}", path.display()))?;
        #[cfg(unix)]
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |_| {
                format!(
                    "another itacoin-node is using {}; stop it first",
                    directory.display()
                )
            },
        )?;
        Ok(Self { path, _file: file })
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
