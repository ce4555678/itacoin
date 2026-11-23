//! Process protections shared by `itacoin-node` and `itacoin-wallet`
//! (section 6.4 of `docs/NODE_PROPOSAL.md`, section 9 of
//! `docs/WALLET_PROPOSAL.md`, finding V-07): core dumps off, the process
//! non-dumpable, private files, exclusive directory locks and passwords read
//! without echo. Everything goes through `rustix`, so the workspace keeps
//! `unsafe` forbidden.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

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

/// Reads one line of secret input: from the terminal with echo off, or the
/// first line of standard input when it is not a terminal (for scripts).
/// The prompt goes to standard error. The trailing newline is removed.
pub fn read_secret(prompt: &str) -> std::io::Result<Zeroizing<String>> {
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    if terminal {
        let mut stderr = std::io::stderr();
        write!(stderr, "{prompt}")?;
        stderr.flush()?;
    }
    #[cfg(unix)]
    let saved = if terminal {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
        let saved = tcgetattr(&stdin)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&stdin, OptionalActions::Now, &quiet)?;
        Some(saved)
    } else {
        None
    };
    let mut line = Zeroizing::new(String::new());
    let result = stdin.lock().read_line(&mut line);
    #[cfg(unix)]
    if let Some(saved) = saved {
        let _ = rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &saved);
        let _ = writeln!(std::io::stderr());
    }
    result?;
    let trimmed = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(trimmed);
    Ok(line)
}

/// Reads one line of ordinary input, echoed, after printing `prompt` to
/// standard error.
pub fn read_line(prompt: &str) -> std::io::Result<String> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt}")?;
    stderr.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Writes `bytes` to `path` atomically with permission 0600: a temporary
/// file in the same directory, flushed, then renamed over the target.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".{}.tmp", std::process::id()));
    let temporary = directory.join(temporary_name);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options.open(&temporary).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_writes_replace_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn directory_locks_are_exclusive() {
        let directory = tempfile::tempdir().unwrap();
        create_data_dir(&directory.path().join("x")).unwrap();
        let lock = DirLock::acquire(directory.path()).unwrap();
        assert!(DirLock::acquire(directory.path()).is_err());
        drop(lock);
        assert!(DirLock::acquire(directory.path()).is_ok());
    }
}
