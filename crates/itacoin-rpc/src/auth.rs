//! RPC authentication and exposure (section 4.2 of `docs/NODE_PROPOSAL.md`).

use std::{
    fs::OpenOptions,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::text::{decode_hex, encode_hex};

/// User name of the cookie credential.
pub const COOKIE_USER: &str = "__cookie__";
/// Argon2id memory for `--rpc-auth` hashes, the wallet default (64 MiB).
const AUTH_MEMORY_KIB: u32 = 64 * 1024;
const AUTH_PASSES: u32 = 3;
const AUTH_LANES: u32 = 4;

/// Compares two byte strings in time that depends only on their lengths.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The cookie file and the secret it holds. The file is removed on drop.
#[derive(Debug)]
pub struct Cookie {
    path: PathBuf,
    secret: Zeroizing<String>,
}

impl Cookie {
    /// Writes a fresh random cookie to `path` with permission 0600,
    /// replacing a stale one left by a crash.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        let secret = Zeroizing::new(encode_hex(bytes.as_ref()));
        let _ = std::fs::remove_file(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(format!("{COOKIE_USER}:{}", secret.as_str()).as_bytes())?;
        file.sync_all()?;
        Ok(Self {
            path: path.to_path_buf(),
            secret,
        })
    }

    /// Reads the `user:password` pair from a cookie file.
    pub fn read(path: &Path) -> std::io::Result<(String, Zeroizing<String>)> {
        let content = Zeroizing::new(std::fs::read_to_string(path)?);
        let (user, password) = content.trim_end().split_once(':').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed cookie file")
        })?;
        Ok((user.to_owned(), Zeroizing::new(password.to_owned())))
    }

    /// The path of the file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn matches(&self, user: &str, password: &str) -> bool {
        // Evaluate both to keep timing independent of which one differs.
        let user_ok = constant_time_eq(user.as_bytes(), COOKIE_USER.as_bytes());
        let password_ok = constant_time_eq(password.as_bytes(), self.secret.as_bytes());
        user_ok & password_ok
    }
}

impl Drop for Cookie {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A fixed credential from `--rpc-auth user:salt:hash`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcAuth {
    user: String,
    salt: [u8; 16],
    hash: [u8; 32],
}

impl RpcAuth {
    /// Parses `user:salt:hash`, with a 32-hex-digit salt and a 64-digit hash.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let mut parts = text.split(':');
        let (Some(user), Some(salt), Some(hash), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("expected user:salt:hash");
        };
        if user.is_empty() || user == COOKIE_USER {
            return Err("invalid user name");
        }
        let salt = decode_hex::<16>(salt).map_err(|_| "the salt must be 32 hex digits")?;
        let hash = decode_hex::<32>(hash).map_err(|_| "the hash must be 64 hex digits")?;
        Ok(Self {
            user: user.to_owned(),
            salt,
            hash,
        })
    }

    /// Creates a credential for `user` and `password` with a random salt and
    /// returns its `user:salt:hash` text.
    pub fn generate(user: &str, password: &str) -> Result<String, &'static str> {
        if user.is_empty() || user.contains(':') || user == COOKIE_USER {
            return Err("invalid user name");
        }
        let mut salt = [0_u8; 16];
        OsRng.fill_bytes(&mut salt);
        let hash = derive(password.as_bytes(), &salt)?;
        Ok(format!(
            "{user}:{}:{}",
            encode_hex(&salt),
            encode_hex(hash.as_ref())
        ))
    }

    /// The user name.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    fn matches(&self, user: &str, password: &str) -> bool {
        if !constant_time_eq(user.as_bytes(), self.user.as_bytes()) {
            return false;
        }
        derive(password.as_bytes(), &self.salt)
            .is_ok_and(|hash| constant_time_eq(hash.as_ref(), &self.hash))
    }
}

fn derive(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let params = Params::new(AUTH_MEMORY_KIB, AUTH_PASSES, AUTH_LANES, Some(32))
        .map_err(|_| "invalid parameters")?;
    let mut output = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|_| "hashing failed")?;
    Ok(output)
}

/// The credentials the server accepts.
#[derive(Debug, Default)]
pub struct Credentials {
    /// The cookie, if one was written.
    pub cookie: Option<Cookie>,
    /// Fixed credentials.
    pub fixed: Vec<RpcAuth>,
}

impl Credentials {
    /// Checks an `Authorization` header value. Slow for fixed credentials:
    /// call it off the async runtime.
    #[must_use]
    pub fn check(&self, header: &str) -> bool {
        let Some(encoded) = header.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        let decoded = Zeroizing::new(decoded);
        let Ok(text) = core::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((user, password)) = text.split_once(':') else {
            return false;
        };
        if self
            .cookie
            .as_ref()
            .is_some_and(|cookie| cookie.matches(user, password))
        {
            return true;
        }
        self.fixed
            .iter()
            .any(|credential| credential.matches(user, password))
    }
}

/// An IP network in CIDR form, for `--rpc-allow-ip`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parses `a.b.c.d/n`, `x::y/n` or a single address.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| "invalid IP address")?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .ok_or("invalid prefix length")?,
        };
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` is in the network.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*ip, IpAddr::V4),
            IpAddr::V4(_) => *ip,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    #[test]
    fn cookies_are_private_and_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".cookie");
        let cookie = Cookie::create(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let (user, password) = Cookie::read(&path).unwrap();
        assert_eq!(user, COOKIE_USER);
        assert_eq!(password.len(), 64);
        let credentials = Credentials {
            cookie: Some(cookie),
            fixed: vec![],
        };
        assert!(credentials.check(&basic(&user, &password)));
        assert!(!credentials.check(&basic(&user, &"0".repeat(64))));
        assert!(!credentials.check(&basic("someone", &password)));
        assert!(!credentials.check("Bearer x"));
        assert!(!credentials.check("Basic !!!"));
        drop(credentials);
        assert!(!path.exists());
    }

    #[test]
    fn fixed_credentials_are_hashed() {
        let text = RpcAuth::generate("alice", "correct horse").unwrap();
        assert!(!text.contains("correct"));
        let credential = RpcAuth::parse(&text).unwrap();
        assert_eq!(credential.user(), "alice");
        let credentials = Credentials {
            cookie: None,
            fixed: vec![credential],
        };
        assert!(credentials.check(&basic("alice", "correct horse")));
        assert!(!credentials.check(&basic("alice", "wrong horse")));
        assert!(!credentials.check(&basic("bob", "correct horse")));
        assert!(RpcAuth::parse("alice:00:11").is_err());
        assert!(RpcAuth::parse("__cookie__:x:y").is_err());
        assert!(RpcAuth::generate("a:b", "x").is_err());
    }

    #[test]
    fn networks_match_by_prefix() {
        let net = IpNet::parse("192.168.0.0/16").unwrap();
        assert!(net.contains(&"192.168.4.5".parse().unwrap()));
        assert!(net.contains(&"::ffff:192.168.4.5".parse().unwrap()));
        assert!(!net.contains(&"192.169.0.1".parse().unwrap()));
        let single = IpNet::parse("10.0.0.1").unwrap();
        assert!(single.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!single.contains(&"10.0.0.2".parse().unwrap()));
        assert!(
            IpNet::parse("::/0")
                .unwrap()
                .contains(&"2001:db8::1".parse().unwrap())
        );
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(IpNet::parse("nope").is_err());
    }
}
