//! Address manager (section 6 of `docs/NETWORK_PROPOSAL.md`).
//!
//! Addresses live in a "new" table (heard of) and a "tried" table (connected
//! to successfully), each split into buckets of fixed-size slots. Bucket and
//! slot are chosen by keyed hashes with a secret local salt, over the
//! address's network group and, for new entries, the group of the peer that
//! told us about it. An attacker cannot predict where its addresses land, and
//! addresses from one source group can only reach a bounded set of buckets,
//! so flooding cannot push out the legitimate entries.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use itacoin_codec::{Reader, Writer};
use rand_core::{OsRng, RngCore};

/// Buckets in the new table.
pub const NEW_BUCKETS: usize = 256;
/// Buckets in the tried table.
pub const TRIED_BUCKETS: usize = 64;
/// Slots per bucket.
pub const BUCKET_SIZE: usize = 64;
/// Buckets of the new table one source group can reach.
const NEW_BUCKETS_PER_SOURCE: u64 = 64;
/// Buckets of the tried table one address group can reach.
const TRIED_BUCKETS_PER_GROUP: u64 = 8;
/// An address not seen for this long is replaceable.
const HORIZON_SECS: u64 = 30 * 24 * 3600;
/// Failed attempts after which an address that never worked is replaceable.
const MAX_FAILURES: u32 = 3;
/// An address tried this recently is not offered again.
const RETRY_DELAY_SECS: u64 = 600;

/// The network group of an address: connections and buckets are limited per
/// group, so many addresses from one provider count as one.
#[must_use]
pub fn group(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() || v4.is_private() || v4.is_link_local() => {
            vec![0, 0]
        }
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            vec![4, octets[0], octets[1]]
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => group(IpAddr::V4(v4)),
            None if v6.is_loopback() => vec![0, 0],
            None => {
                let octets = v6.octets();
                vec![6, octets[0], octets[1], octets[2], octets[3]]
            }
        },
    }
}

/// What the manager knows about one address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddrInfo {
    /// The address.
    pub addr: SocketAddr,
    /// Service bits it advertised.
    pub services: u64,
    /// When it was last heard of.
    pub last_seen: u64,
    /// When we last tried to connect.
    pub last_try: u64,
    /// When a connection last succeeded (0 if never).
    pub last_success: u64,
    /// Failed attempts since the last success.
    pub attempts: u32,
}

impl AddrInfo {
    fn is_terrible(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen) > HORIZON_SECS
            || (self.last_success == 0 && self.attempts >= MAX_FAILURES)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Table {
    New,
    Tried,
}

/// The address manager.
#[derive(Clone, Debug)]
pub struct AddrMan {
    salt: [u8; 32],
    new: Vec<Option<AddrInfo>>,
    tried: Vec<Option<AddrInfo>>,
    index: HashMap<SocketAddr, (Table, usize)>,
}

impl Default for AddrMan {
    fn default() -> Self {
        let mut salt = [0_u8; 32];
        OsRng.fill_bytes(&mut salt);
        Self::with_salt(salt)
    }
}

impl AddrMan {
    /// Creates an empty manager with a given secret salt.
    #[must_use]
    pub fn with_salt(salt: [u8; 32]) -> Self {
        Self {
            salt,
            new: vec![None; NEW_BUCKETS * BUCKET_SIZE],
            tried: vec![None; TRIED_BUCKETS * BUCKET_SIZE],
            index: HashMap::new(),
        }
    }

    /// Number of known addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether no address is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Returns what is known about `addr`.
    #[must_use]
    pub fn get(&self, addr: &SocketAddr) -> Option<&AddrInfo> {
        let (table, slot) = self.index.get(addr)?;
        self.table(*table)[*slot].as_ref()
    }

    /// Whether `addr` is in the tried table.
    #[must_use]
    pub fn is_tried(&self, addr: &SocketAddr) -> bool {
        matches!(self.index.get(addr), Some((Table::Tried, _)))
    }

    fn table(&self, table: Table) -> &[Option<AddrInfo>] {
        match table {
            Table::New => &self.new,
            Table::Tried => &self.tried,
        }
    }

    fn hash(&self, parts: &[&[u8]]) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&self.salt);
        for part in parts {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        u64::from_be_bytes(
            hasher.finalize().as_bytes()[..8]
                .try_into()
                .expect("8 bytes"),
        )
    }

    fn new_slot(&self, addr: &SocketAddr, source: IpAddr) -> usize {
        let address_group = group(addr.ip());
        let source_group = group(source);
        let reach = self.hash(&[b"new1", &address_group, &source_group]) % NEW_BUCKETS_PER_SOURCE;
        let bucket =
            self.hash(&[b"new2", &source_group, &reach.to_be_bytes()]) % NEW_BUCKETS as u64;
        let slot = self.hash(&[b"slot", &bucket.to_be_bytes(), addr.to_string().as_bytes()])
            % BUCKET_SIZE as u64;
        (bucket as usize) * BUCKET_SIZE + slot as usize
    }

    fn tried_slot(&self, addr: &SocketAddr) -> usize {
        let address_group = group(addr.ip());
        let key = addr.to_string();
        let reach = self.hash(&[b"tried1", key.as_bytes()]) % TRIED_BUCKETS_PER_GROUP;
        let bucket =
            self.hash(&[b"tried2", &address_group, &reach.to_be_bytes()]) % TRIED_BUCKETS as u64;
        let slot =
            self.hash(&[b"slot", &bucket.to_be_bytes(), key.as_bytes()]) % BUCKET_SIZE as u64;
        (bucket as usize) * BUCKET_SIZE + slot as usize
    }

    /// Records an address heard from `source`. Returns whether it is new.
    ///
    /// A known address only has its timestamp refreshed. A new address takes
    /// its slot only if the slot is empty or its occupant is terrible.
    pub fn add(
        &mut self,
        addr: SocketAddr,
        services: u64,
        time: u64,
        source: IpAddr,
        now: u64,
    ) -> bool {
        if let Some((table, slot)) = self.index.get(&addr).copied() {
            let entry = match table {
                Table::New => self.new[slot].as_mut(),
                Table::Tried => self.tried[slot].as_mut(),
            }
            .expect("indexed");
            entry.last_seen = entry.last_seen.max(time.min(now));
            entry.services |= services;
            return false;
        }
        let slot = self.new_slot(&addr, source);
        if let Some(occupant) = self.new[slot] {
            if !occupant.is_terrible(now) {
                return false;
            }
            self.index.remove(&occupant.addr);
        }
        self.new[slot] = Some(AddrInfo {
            addr,
            services,
            last_seen: time.min(now),
            last_try: 0,
            last_success: 0,
            attempts: 0,
        });
        self.index.insert(addr, (Table::New, slot));
        true
    }

    /// Records a connection attempt.
    pub fn attempt(&mut self, addr: &SocketAddr, now: u64) {
        if let Some(entry) = self.entry_mut(addr) {
            entry.last_try = now;
            entry.attempts = entry.attempts.saturating_add(1);
        }
    }

    /// Records a successful connection and moves the address to tried. An
    /// occupant of its tried slot goes back to the new table.
    pub fn good(&mut self, addr: &SocketAddr, now: u64) {
        let Some((table, slot)) = self.index.get(addr).copied() else {
            return;
        };
        let mut info = match table {
            Table::New => self.new[slot].take().expect("indexed"),
            Table::Tried => self.tried[slot].take().expect("indexed"),
        };
        self.index.remove(addr);
        info.last_success = now;
        info.last_try = now;
        info.last_seen = now;
        info.attempts = 0;

        let tried_slot = self.tried_slot(addr);
        if let Some(evicted) = self.tried[tried_slot].take() {
            self.index.remove(&evicted.addr);
            // Demote to the new table, as if heard from itself.
            let new_slot = self.new_slot(&evicted.addr, evicted.addr.ip());
            if self.new[new_slot].is_none() {
                self.new[new_slot] = Some(evicted);
                self.index.insert(evicted.addr, (Table::New, new_slot));
            }
        }
        self.tried[tried_slot] = Some(info);
        self.index.insert(*addr, (Table::Tried, tried_slot));
    }

    fn entry_mut(&mut self, addr: &SocketAddr) -> Option<&mut AddrInfo> {
        let (table, slot) = self.index.get(addr).copied()?;
        match table {
            Table::New => self.new[slot].as_mut(),
            Table::Tried => self.tried[slot].as_mut(),
        }
    }

    /// Picks an address to connect to: tried or new with equal odds, skipping
    /// addresses tried in the last 10 minutes and those `exclude` rejects.
    pub fn select(&self, now: u64, exclude: impl Fn(&SocketAddr) -> bool) -> Option<SocketAddr> {
        let candidates: Vec<&AddrInfo> = self
            .new
            .iter()
            .chain(self.tried.iter())
            .flatten()
            .filter(|info| {
                now.saturating_sub(info.last_try) >= RETRY_DELAY_SECS || info.last_try == 0
            })
            .filter(|info| !exclude(&info.addr))
            .collect();
        let (tried, new): (Vec<&AddrInfo>, Vec<&AddrInfo>) = candidates
            .into_iter()
            .partition(|info| self.is_tried(&info.addr));
        let pool = match (tried.is_empty(), new.is_empty()) {
            (true, true) => return None,
            (true, false) => new,
            (false, true) => tried,
            (false, false) => {
                if OsRng.next_u32().is_multiple_of(2) {
                    tried
                } else {
                    new
                }
            }
        };
        let index = (OsRng.next_u64() % pool.len() as u64) as usize;
        Some(pool[index].addr)
    }

    /// A random sample for an `addr` reply: at most `limit` entries and at
    /// most 23% of all known addresses, skipping terrible ones.
    #[must_use]
    pub fn sample(&self, limit: usize, now: u64) -> Vec<AddrInfo> {
        let mut all: Vec<AddrInfo> = self
            .new
            .iter()
            .chain(self.tried.iter())
            .flatten()
            .filter(|info| !info.is_terrible(now))
            .copied()
            .collect();
        let count = limit
            .min(all.len() * 23 / 100)
            .max(all.len().min(1).min(limit));
        // Partial Fisher–Yates shuffle.
        for index in 0..count.min(all.len()) {
            let pick = index + (OsRng.next_u64() % (all.len() - index) as u64) as usize;
            all.swap(index, pick);
        }
        all.truncate(count);
        all
    }

    /// Serializes the salt and all entries.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.bytes(&self.salt);
        let entries: Vec<(&AddrInfo, bool)> = self
            .new
            .iter()
            .flatten()
            .map(|info| (info, false))
            .chain(self.tried.iter().flatten().map(|info| (info, true)))
            .collect();
        writer.count_u32(entries.len());
        for (info, tried) in entries {
            let text = info.addr.to_string();
            writer.u8(u8::try_from(text.len()).expect("socket address text is short"));
            writer.bytes(text.as_bytes());
            writer.u64(info.services);
            writer.u64(info.last_seen);
            writer.u64(info.last_try);
            writer.u64(info.last_success);
            writer.u32(info.attempts);
            writer.u8(u8::from(tried));
        }
        writer.into_bytes()
    }

    /// Restores a manager saved by [`AddrMan::to_bytes`]. Entries are placed
    /// again by their hashes, so the result does not depend on the old layout.
    pub fn from_bytes(bytes: &[u8], now: u64) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let salt = reader.array::<32>().ok()?;
        let mut manager = Self::with_salt(salt);
        let count = reader
            .count_u32(0..=(NEW_BUCKETS + TRIED_BUCKETS) * BUCKET_SIZE, 1)
            .ok()?;
        for _ in 0..count {
            let length = usize::from(reader.u8().ok()?);
            let text = std::str::from_utf8(reader.take(length).ok()?).ok()?;
            let addr: SocketAddr = text.parse().ok()?;
            let services = reader.u64().ok()?;
            let last_seen = reader.u64().ok()?;
            let last_try = reader.u64().ok()?;
            let last_success = reader.u64().ok()?;
            let attempts = reader.u32().ok()?;
            let tried = reader.u8().ok()? == 1;
            manager.add(addr, services, last_seen, addr.ip(), now.max(last_seen));
            if tried {
                manager.good(&addr, last_success);
            }
            if let Some(entry) = manager.entry_mut(&addr) {
                entry.last_try = last_try;
                entry.attempts = attempts;
                entry.last_success = last_success;
            }
        }
        reader.finish().ok()?;
        Some(manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn groups_limit_by_provider() {
        assert_eq!(
            group("1.2.3.4".parse().unwrap()),
            group("1.2.200.9".parse().unwrap())
        );
        assert_ne!(
            group("1.2.3.4".parse().unwrap()),
            group("1.3.3.4".parse().unwrap())
        );
        assert_eq!(
            group("2001:db8:1::1".parse().unwrap()),
            group("2001:db8:ffff::2".parse().unwrap())
        );
        assert_eq!(
            group("::ffff:1.2.3.4".parse().unwrap()),
            group("1.2.9.9".parse().unwrap())
        );
    }

    #[test]
    fn add_attempt_good_and_select() {
        let mut manager = AddrMan::with_salt([1; 32]);
        let source: IpAddr = "9.9.9.9".parse().unwrap();
        assert!(manager.add(addr("1.2.3.4:7210"), 1, NOW, source, NOW));
        assert!(!manager.add(addr("1.2.3.4:7210"), 1, NOW, source, NOW));
        assert_eq!(manager.len(), 1);
        manager.good(&addr("1.2.3.4:7210"), NOW);
        assert!(manager.is_tried(&addr("1.2.3.4:7210")));
        // Just connected: not offered again for 10 minutes.
        assert_eq!(manager.select(NOW + 1, |_| false), None);
        assert_eq!(
            manager.select(NOW + RETRY_DELAY_SECS, |_| false),
            Some(addr("1.2.3.4:7210"))
        );
        assert_eq!(manager.select(NOW + RETRY_DELAY_SECS, |_| true), None);
    }

    #[test]
    fn one_source_cannot_flood_the_table() {
        let mut manager = AddrMan::with_salt([2; 32]);
        let attacker: IpAddr = "6.6.6.6".parse().unwrap();
        // 100 000 addresses from one source group land in at most 64 buckets.
        for index in 0..100_000_u32 {
            let [a, b, c, d] = index.to_be_bytes();
            let address = SocketAddr::new(IpAddr::from([a.wrapping_add(11), b, c, d]), 7210);
            manager.add(address, 1, NOW, attacker, NOW);
        }
        assert!(manager.len() <= (NEW_BUCKETS_PER_SOURCE as usize) * BUCKET_SIZE);

        // Legitimate addresses from other sources still find room.
        let mut legitimate = 0;
        for index in 0..200_u32 {
            let source = IpAddr::from([20, (index % 200) as u8, 1, 1]);
            let address = SocketAddr::new(IpAddr::from([30, index as u8, 1, 1]), 7210);
            if manager.add(address, 1, NOW, source, NOW) {
                legitimate += 1;
            }
        }
        assert!(legitimate > 100, "{legitimate}");
    }

    #[test]
    fn terrible_entries_are_replaceable() {
        let mut manager = AddrMan::with_salt([3; 32]);
        let source: IpAddr = "9.9.9.9".parse().unwrap();
        let old = addr("1.2.3.4:7210");
        manager.add(old, 1, NOW - HORIZON_SECS - 1, source, NOW);
        let info = manager.get(&old).unwrap();
        assert!(info.is_terrible(NOW));
        for _ in 0..MAX_FAILURES {
            manager.attempt(&addr("1.2.3.4:7210"), NOW);
        }
        assert!(manager.get(&old).unwrap().is_terrible(NOW));
    }

    #[test]
    fn serialization_round_trips() {
        let mut manager = AddrMan::with_salt([4; 32]);
        let source: IpAddr = "9.9.9.9".parse().unwrap();
        for index in 0..50_u8 {
            manager.add(addr(&format!("1.{index}.3.4:7210")), 1, NOW, source, NOW);
        }
        manager.good(&addr("1.7.3.4:7210"), NOW);
        let restored = AddrMan::from_bytes(&manager.to_bytes(), NOW).unwrap();
        assert_eq!(restored.len(), manager.len());
        assert!(restored.is_tried(&addr("1.7.3.4:7210")));
        assert!(AddrMan::from_bytes(&[0; 10], NOW).is_none());
    }

    #[test]
    fn samples_are_bounded() {
        let mut manager = AddrMan::with_salt([5; 32]);
        let source: IpAddr = "9.9.9.9".parse().unwrap();
        for index in 0..200_u8 {
            manager.add(
                addr(&format!("{}.{index}.3.4:7210", index % 50 + 1)),
                1,
                NOW,
                source,
                NOW,
            );
        }
        let sample = manager.sample(1_000, NOW);
        assert!(sample.len() <= manager.len() * 23 / 100 + 1);
        assert!(!sample.is_empty());
    }
}
