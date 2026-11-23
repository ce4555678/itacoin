//! ITACOIN consensus rules, as specified in `docs/CONSENSUS_PROPOSAL.md`.
//!
//! Everything here is a pure function of its inputs: emission, the Argon2id
//! proof of work, aserti3-2d difficulty, median time past, chain work and the
//! per-network genesis blocks. Chain state and I/O live in `itacoin-storage`.

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use itacoin_blockchain::{Block, BlockHeader, BlockRules};
use itacoin_codec::Encode;
use itacoin_primitives::{Amount, BlockId, COIN, Hash256, Network, WalletId};
use itacoin_transaction::{CoinbaseTransaction, Output, Transaction};

mod u256;

pub use u256::U256;

/// Number of eras in the emission schedule.
pub const ERAS: u64 = 100;
/// Number of previous blocks whose median timestamp a block must exceed.
pub const MEDIAN_TIME_SPAN: usize = 11;
/// Argon2id memory cost of the proof of work, in KiB.
pub const POW_MEMORY_KIB: u32 = 4096;
/// Prefix of the Argon2id salt; the chain id follows it.
pub const POW_SALT_PREFIX: &[u8] = b"ITACOIN:pow:v1";

/// The consensus parameters of one network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusParams {
    /// The network these parameters belong to.
    pub network: Network,
    /// Ideal seconds between blocks.
    pub target_spacing: u64,
    /// aserti3-2d half-life in seconds.
    pub halflife: u64,
    /// The easiest allowed target, also the genesis target.
    pub pow_limit: U256,
    /// Blocks per emission era.
    pub era_blocks: u64,
    /// Blocks a coinbase output waits before it can be spent.
    pub coinbase_maturity: u64,
    /// Seconds a block timestamp may be ahead of the local clock.
    pub max_future_drift: u64,
    /// Timestamp of the genesis block.
    pub genesis_timestamp: u64,
}

impl ConsensusParams {
    /// Main network parameters.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            network: Network::Mainnet,
            target_spacing: 120,
            halflife: 43_200,
            pow_limit: U256::MAX >> 15,
            era_blocks: 262_800,
            coinbase_maturity: 100,
            max_future_drift: 600,
            // 2027-01-01T00:00:00Z
            genesis_timestamp: 1_798_761_600,
        }
    }

    /// Public test network: mainnet rules, a different genesis.
    #[must_use]
    pub fn testnet() -> Self {
        Self {
            network: Network::Testnet,
            // 2026-11-23T00:00:00Z
            genesis_timestamp: 1_795_392_000,
            ..Self::mainnet()
        }
    }

    /// Local regression tests: every proof of work is valid and coinbases
    /// mature after one block.
    #[must_use]
    pub fn regtest() -> Self {
        Self {
            network: Network::Regtest,
            pow_limit: U256::MAX,
            coinbase_maturity: 1,
            // 2026-01-01T00:00:00Z
            genesis_timestamp: 1_767_225_600,
            ..Self::mainnet()
        }
    }

    /// Returns the genesis block of this network.
    ///
    /// The genesis is fixed in code and accepted by its id; its proof of work
    /// is not checked, because the chain id that salts the proof of work is
    /// the genesis id itself. Its regular height-0 reward is paid to the
    /// all-zero wallet id, whose key nobody knows, so it is burned.
    #[must_use]
    pub fn genesis(&self) -> Block {
        let coinbase = Transaction::Coinbase(
            CoinbaseTransaction::new(
                0,
                vec![Output {
                    amount: subsidy(0, self),
                    wallet_id: WalletId::new(Hash256::new([0; 32])),
                }],
            )
            .expect("genesis coinbase is valid"),
        );
        let transactions = vec![coinbase];
        let (tx_root, witness_root) = Block::roots(&transactions).expect("one leaf");
        let header = BlockHeader {
            prev_block: BlockId::new(Hash256::new([0; 32])),
            tx_root,
            witness_root,
            timestamp: self.genesis_timestamp,
            target: self.pow_limit.to_hash(),
            nonce: match self.network {
                Network::Mainnet => 0,
                Network::Testnet => 1,
                Network::Regtest => 2,
            },
        };
        Block::new(header, transactions).expect("genesis block is valid")
    }

    /// Returns the chain id: the genesis block id.
    #[must_use]
    pub fn chain_id(&self) -> Hash256 {
        self.genesis().id().into_hash()
    }

    /// Returns the aserti3-2d anchor: the genesis block.
    ///
    /// The anchor's parent time is defined as one spacing before genesis, so
    /// that the block after genesis keeps the genesis target.
    #[must_use]
    pub fn asert_anchor(&self) -> AsertAnchor {
        AsertAnchor {
            height: 0,
            parent_time: i64::try_from(self.genesis_timestamp).expect("timestamp fits")
                - i64::try_from(self.target_spacing).expect("spacing fits"),
            target: self.pow_limit,
        }
    }

    /// Returns the rules for applying the block at `height`.
    #[must_use]
    pub fn block_rules(&self, chain_id: Hash256, height: u64) -> BlockRules {
        BlockRules {
            chain_id,
            coinbase_maturity: self.coinbase_maturity,
            subsidy: subsidy(height, self),
        }
    }
}

/// Returns the new coins the coinbase at `height` may create.
///
/// Era `i` emits `(1_990_000 − 20_000 × i) × COIN` over `era_blocks` blocks;
/// the first `E % N` blocks of the era get one extra satoshi so the era total
/// is exact. Zero after the last era.
#[must_use]
pub fn subsidy(height: u64, params: &ConsensusParams) -> Amount {
    let era = height / params.era_blocks;
    if era >= ERAS {
        return Amount::ZERO;
    }
    let emission = (1_990_000 - 20_000 * era) * COIN;
    let base = emission / params.era_blocks;
    let extra = emission % params.era_blocks;
    let reward = base + u64::from(height % params.era_blocks < extra);
    Amount::from_satoshis(reward).expect("era reward is below the maximum supply")
}

/// Computes the Argon2id proof-of-work hash of a header.
#[must_use]
pub fn pow_hash(header: &BlockHeader, chain_id: &Hash256) -> Hash256 {
    let params = Params::new(POW_MEMORY_KIB, 1, 1, Some(32)).expect("constant parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt = Vec::with_capacity(POW_SALT_PREFIX.len() + 32);
    salt.extend_from_slice(POW_SALT_PREFIX);
    salt.extend_from_slice(chain_id.as_bytes());
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(&header.to_bytes(), &salt, &mut output)
        .expect("constant parameters and lengths");
    Hash256::new(output)
}

/// Returns whether the header's proof of work meets its own target.
#[must_use]
pub fn check_pow(header: &BlockHeader, chain_id: &Hash256) -> bool {
    U256::from_hash(&pow_hash(header, chain_id)) <= U256::from_hash(&header.target)
}

/// Returns the work a block with `target` represents: `⌊2^256 / (target + 1)⌋`.
///
/// A zero target, which no valid block has, saturates at `2^256 − 1`.
#[must_use]
pub fn block_work(target: U256) -> U256 {
    // 2^256 / (t + 1) == (2^256 - t - 1) / (t + 1) + 1 == !t / (t + 1) + 1,
    // which stays within 256 bits.
    match target.checked_add(U256::ONE) {
        None => U256::ONE,
        Some(divisor) => (!target)
            .checked_div(divisor)
            .expect("divisor is non-zero")
            .checked_add(U256::ONE)
            .unwrap_or(U256::MAX),
    }
}

/// The reference block of the aserti3-2d schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsertAnchor {
    /// Height of the anchor block.
    pub height: u64,
    /// Timestamp of the anchor's parent.
    pub parent_time: i64,
    /// Target of the anchor block.
    pub target: U256,
}

/// Computes the target of the block after `prev_height`/`prev_time` with the
/// aserti3-2d algorithm, exactly as specified for Bitcoin Cash.
#[must_use]
pub fn next_target(
    anchor: &AsertAnchor,
    prev_height: u64,
    prev_time: i64,
    params: &ConsensusParams,
) -> U256 {
    let spacing = i128::from(params.target_spacing);
    let time_delta = i128::from(prev_time) - i128::from(anchor.parent_time);
    let height_delta = i128::from(prev_height) - i128::from(anchor.height);
    // Rust's `/` truncates toward zero and `>>` on signed integers rounds
    // toward negative infinity, matching the C++ reference implementation.
    let exponent =
        ((time_delta - spacing * (height_delta + 1)) * 65_536) / i128::from(params.halflife);
    let shifts = exponent >> 16;
    let frac = (exponent & 0xffff) as u128;
    let factor = 65_536
        + ((195_766_423_245_049 * frac
            + 971_821_376 * frac * frac
            + 5_127 * frac * frac * frac
            + (1 << 47))
            >> 48);
    let factor = u64::try_from(factor).expect("factor is at most 2^17");

    let shift = i64::try_from(shifts - 16).unwrap_or(if shifts > 0 { i64::MAX } else { i64::MIN });
    let target = anchor
        .target
        .mul_u64_shift(factor, shift)
        .unwrap_or(params.pow_limit);
    if target.is_zero() {
        U256::ONE
    } else {
        target.min(params.pow_limit)
    }
}

/// Returns the median of the given timestamps (the previous blocks, at most
/// [`MEDIAN_TIME_SPAN`] of them, most recent first or in any order).
///
/// # Panics
///
/// Panics if `timestamps` is empty; every block after genesis has a parent.
#[must_use]
pub fn median_time_past(timestamps: &[u64]) -> u64 {
    assert!(!timestamps.is_empty(), "median of no timestamps");
    let mut sorted = timestamps.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// What a header is checked against: values derived from its ancestors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderContext {
    /// The target the aserti3-2d schedule requires.
    pub expected_target: U256,
    /// Median timestamp of up to 11 previous blocks.
    pub median_time_past: u64,
    /// The local clock, in seconds since the Unix epoch.
    pub now: u64,
}

/// Checks a non-genesis header, cheapest rule first: target, timestamps, and
/// only then the Argon2id proof of work.
pub fn check_header(
    header: &BlockHeader,
    context: &HeaderContext,
    chain_id: &Hash256,
    params: &ConsensusParams,
) -> Result<(), ConsensusError> {
    check_header_context(header, context, params)?;
    if !check_pow(header, chain_id) {
        return Err(ConsensusError::InsufficientWork);
    }
    Ok(())
}

/// The cheap header rules: target and timestamps, without the proof of work.
///
/// Callers that verify many headers run this first and then [`check_pow`] in
/// parallel; [`check_header`] does both in order.
pub fn check_header_context(
    header: &BlockHeader,
    context: &HeaderContext,
    params: &ConsensusParams,
) -> Result<(), ConsensusError> {
    if U256::from_hash(&header.target) != context.expected_target {
        return Err(ConsensusError::WrongTarget);
    }
    if header.timestamp <= context.median_time_past {
        return Err(ConsensusError::TimestampTooOld);
    }
    if header.timestamp > context.now.saturating_add(params.max_future_drift) {
        return Err(ConsensusError::TimestampInFuture);
    }
    Ok(())
}

/// Header rule violations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusError {
    /// The target differs from the aserti3-2d schedule.
    WrongTarget,
    /// The timestamp is not above the median time past.
    TimestampTooOld,
    /// The timestamp is too far ahead of the local clock. This is not
    /// permanent: the block may become acceptable later.
    TimestampInFuture,
    /// The proof-of-work hash exceeds the target.
    InsufficientWork,
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTarget => "target does not follow the difficulty schedule",
            Self::TimestampTooOld => "timestamp is not after the median time past",
            Self::TimestampInFuture => "timestamp is too far in the future",
            Self::InsufficientWork => "proof of work does not meet the target",
        })
    }
}

impl std::error::Error for ConsensusError {}

#[cfg(test)]
mod tests;
