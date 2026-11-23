use itacoin_primitives::MAX_SUPPLY;

use super::*;

#[test]
fn emission_sums_exactly_to_max_supply() {
    // Requirement 2.4: sum every block reward in u128.
    let params = ConsensusParams::mainnet();
    let mut total = 0_u128;
    for height in 0..ERAS * params.era_blocks {
        total += u128::from(subsidy(height, &params).as_satoshis());
    }
    assert_eq!(total, u128::from(MAX_SUPPLY));
    for height in [
        ERAS * params.era_blocks,
        ERAS * params.era_blocks + 1,
        u64::MAX,
    ] {
        assert_eq!(subsidy(height, &params), Amount::ZERO);
    }
}

#[test]
fn era_rewards_match_the_proposal() {
    let params = ConsensusParams::mainnet();
    let n = params.era_blocks;
    assert_eq!(subsidy(0, &params).as_satoshis(), 757_229_833);
    assert_eq!(subsidy(150_399, &params).as_satoshis(), 757_229_833);
    assert_eq!(subsidy(150_400, &params).as_satoshis(), 757_229_832);
    assert_eq!(subsidy(n, &params).as_satoshis(), 749_619_483);
    assert_eq!(subsidy(99 * n, &params).as_satoshis(), 3_805_176);
    assert_eq!(subsidy(100 * n - 1, &params).as_satoshis(), 3_805_175);
}

#[test]
fn block_work_is_two_to_the_256_over_target_plus_one() {
    assert_eq!(block_work(U256::MAX), U256::ONE);
    assert_eq!(block_work(U256::MAX >> 1), U256::from_u64(2));
    assert_eq!(block_work(U256::ZERO), U256::MAX);
    assert_eq!(
        block_work(ConsensusParams::mainnet().pow_limit),
        U256::from_u64(1 << 15)
    );
    assert_eq!(block_work(U256::from_u64(1)), U256::ONE << 255);
}

#[test]
fn median_time_past_is_the_middle_value() {
    assert_eq!(median_time_past(&[5]), 5);
    assert_eq!(median_time_past(&[3, 1, 2]), 2);
    assert_eq!(median_time_past(&[11, 1, 10, 2, 9, 3, 8, 4, 7, 5, 6]), 6);
}

/// Bitcoin's compact target encoding, used only to read the BCH vectors.
fn from_compact(compact: u32) -> U256 {
    let size = compact >> 24;
    let word = U256::from_u64(u64::from(compact & 0x007f_ffff));
    if size <= 3 {
        word >> (8 * (3 - size))
    } else {
        word << (8 * (size - 3))
    }
}

fn to_compact(target: U256) -> u32 {
    let mut size = target.bits().div_ceil(8);
    let mut compact = if size <= 3 {
        (target.low_u64() << (8 * (3 - size))) as u32
    } else {
        (target >> (8 * (size - 3))).low_u64() as u32
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (size << 24)
}

fn header_value<'a>(file: &'a str, name: &str) -> &'a str {
    file.lines()
        .find_map(|line| {
            line.strip_prefix("##")?
                .trim()
                .strip_prefix(name)?
                .strip_prefix(':')
        })
        .unwrap_or_else(|| panic!("missing {name}"))
        .trim()
}

fn parse_hex_u32(value: &str) -> u32 {
    u32::from_str_radix(value.trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn matches_the_official_aserti3_2d_vectors() {
    let bch = ConsensusParams {
        target_spacing: 600,
        halflife: 172_800,
        pow_limit: from_compact(0x1d00_ffff),
        ..ConsensusParams::mainnet()
    };
    let runs = [
        include_str!("../vectors/run01"),
        include_str!("../vectors/run02"),
        include_str!("../vectors/run03"),
        include_str!("../vectors/run04"),
        include_str!("../vectors/run05"),
        include_str!("../vectors/run06"),
        include_str!("../vectors/run07"),
        include_str!("../vectors/run08"),
        include_str!("../vectors/run09"),
        include_str!("../vectors/run10"),
        include_str!("../vectors/run11"),
        include_str!("../vectors/run12"),
    ];
    let mut checked = 0;
    for (run, file) in runs.iter().enumerate() {
        let anchor = AsertAnchor {
            height: header_value(file, "anchor height").parse().unwrap(),
            parent_time: header_value(file, "anchor parent time").parse().unwrap(),
            target: from_compact(parse_hex_u32(header_value(file, "anchor nBits"))),
        };
        for line in file
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
        {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let height: u64 = fields[1].parse().unwrap();
            let time: i64 = fields[2].parse().unwrap();
            let expected = parse_hex_u32(fields[3]);
            let target = next_target(&anchor, height, time, &bch);
            assert_eq!(
                to_compact(target),
                expected,
                "run {} iteration {}",
                run + 1,
                fields[0]
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked,
        10 * 3 + 225 * 2 + 1000 * 2 + 500 + 10 * 2 + 1000 + 10_000
    );
}

#[test]
fn itacoin_schedule_halves_and_doubles_per_halflife() {
    let params = ConsensusParams::mainnet();
    let anchor = AsertAnchor {
        height: 0,
        parent_time: 0,
        target: params.pow_limit >> 10,
    };
    // On schedule: the target stays put.
    assert_eq!(next_target(&anchor, 9, 1_200, &params), anchor.target);
    // 12 hours behind schedule: the target doubles (difficulty halves).
    assert_eq!(
        next_target(&anchor, 9, 1_200 + 43_200, &params),
        anchor.target << 1
    );
    // 12 hours ahead: the target halves.
    assert_eq!(
        next_target(&anchor, 9 + 360, 1_200, &params),
        anchor.target >> 1
    );
    // Never above the limit, never zero.
    assert_eq!(
        next_target(&anchor, 0, i64::MAX / 2, &params),
        params.pow_limit
    );
    assert_eq!(next_target(&anchor, u64::MAX / 2, 0, &params), U256::ONE);
}

#[test]
fn block_after_genesis_keeps_the_genesis_target() {
    for params in [
        ConsensusParams::mainnet(),
        ConsensusParams::testnet(),
        ConsensusParams::regtest(),
    ] {
        let genesis = params.genesis();
        let anchor = params.asert_anchor();
        let time = i64::try_from(genesis.header().timestamp).unwrap();
        assert_eq!(next_target(&anchor, 0, time, &params), params.pow_limit);
    }
}

#[test]
fn genesis_blocks_are_distinct_and_burn_their_reward() {
    let networks = [
        ConsensusParams::mainnet(),
        ConsensusParams::testnet(),
        ConsensusParams::regtest(),
    ];
    let ids: Vec<Hash256> = networks.iter().map(ConsensusParams::chain_id).collect();
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(ids[0], ids[2]);
    for params in &networks {
        let genesis = params.genesis();
        assert_eq!(genesis.height(), 0);
        let outputs = genesis.transactions()[0].outputs();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].amount, subsidy(0, params));
        assert_eq!(outputs[0].wallet_id, WalletId::new(Hash256::new([0; 32])));
    }
    // A change here is a consensus change.
    assert_eq!(
        ids[0].to_string(),
        "b97fa417ac636bb6d901c05e34b4d7785cb4a180b49e3e452ab338c87f0c065c"
    );
    assert_eq!(
        ids[1].to_string(),
        "cdee9e3c0db32519de594e136843b9aac4a8597441dc3cc7a4fd08f064b2a055"
    );
}

#[test]
fn proof_of_work_is_bound_to_header_and_chain() {
    let params = ConsensusParams::mainnet();
    let header = *params.genesis().header();
    let chain = params.chain_id();
    let hash = pow_hash(&header, &chain);
    assert_eq!(pow_hash(&header, &chain), hash);
    assert_ne!(pow_hash(&header, &Hash256::new([1; 32])), hash);
    let mut other = header;
    other.nonce += 1;
    assert_ne!(pow_hash(&other, &chain), hash);

    let mut easy = header;
    easy.target = U256::MAX.to_hash();
    assert!(check_pow(&easy, &chain));
    let mut impossible = header;
    impossible.target = Hash256::new([0; 32]);
    assert!(!check_pow(&impossible, &chain));
    assert_eq!(
        hash.to_string(),
        "58a18900e128f2e957852e804e7c277926629201b6575c771a36db40d3ccd816"
    );
}

#[test]
fn header_rules_are_checked_cheapest_first() {
    let params = ConsensusParams::mainnet();
    let chain = params.chain_id();
    let mut header = *params.genesis().header();
    header.timestamp = 1_000;
    header.target = Hash256::new([0; 32]);
    let context = HeaderContext {
        expected_target: U256::ZERO,
        median_time_past: 900,
        now: 1_000,
    };
    // Valid target and time but impossible work.
    assert_eq!(
        check_header(&header, &context, &chain, &params),
        Err(ConsensusError::InsufficientWork)
    );
    let wrong_target = HeaderContext {
        expected_target: U256::ONE,
        ..context
    };
    assert_eq!(
        check_header(&header, &wrong_target, &chain, &params),
        Err(ConsensusError::WrongTarget)
    );
    let old = HeaderContext {
        median_time_past: 1_000,
        ..context
    };
    assert_eq!(
        check_header(&header, &old, &chain, &params),
        Err(ConsensusError::TimestampTooOld)
    );
    header.timestamp = 1_601;
    assert_eq!(
        check_header(&header, &context, &chain, &params),
        Err(ConsensusError::TimestampInFuture)
    );
    header.timestamp = 1_600;
    header.target = U256::MAX.to_hash();
    let easy = HeaderContext {
        expected_target: U256::MAX,
        ..context
    };
    assert_eq!(check_header(&header, &easy, &chain, &params), Ok(()));
}
