use super::*;

const NOW: u64 = 4_000_000_000;

fn tree() -> HeaderTree {
    let params = ConsensusParams::regtest();
    let genesis = params.genesis();
    HeaderTree::new(
        params,
        params.chain_id(),
        U256::ZERO,
        [(
            genesis.id(),
            *genesis.header(),
            0,
            block_work(params.pow_limit),
            false,
        )],
    )
}

/// `count` valid regtest headers after `parent`, distinguished by `tag`.
fn branch(tree: &HeaderTree, parent: BlockId, count: usize, tag: u8) -> Vec<BlockHeader> {
    let mut headers = Vec::with_capacity(count);
    let mut prev = parent;
    let mut timestamp = tree.get(&parent).unwrap().header.timestamp;
    for index in 0..count {
        timestamp += 120;
        let header = BlockHeader {
            prev_block: prev,
            tx_root: Hash256::new([tag; 32]),
            witness_root: Hash256::new([0; 32]),
            timestamp,
            target: U256::MAX.to_hash(),
            nonce: index as u64,
        };
        prev = header.id();
        headers.push(header);
    }
    headers
}

fn genesis(tree: &HeaderTree) -> BlockId {
    BlockId::new(tree.chain_id)
}

#[test]
fn a_valid_batch_is_stored_and_becomes_best() {
    let mut tree = tree();
    let mut sync = PeerHeaderSync::default();
    let headers = branch(&tree, genesis(&tree), 20, 1);
    let outcome = tree.process(&mut sync, &headers, NOW).unwrap();
    let HeaderOutcome::Stored { new, last, full } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(new.len(), 20);
    assert_eq!(last, headers[19].id());
    assert!(!full);
    assert_eq!(tree.best().0, last);
    assert_eq!(tree.best().1.height, 20);
    // Resending is harmless.
    assert!(matches!(
        tree.process(&mut sync, &headers, NOW).unwrap(),
        HeaderOutcome::Stored { new, .. } if new.is_empty()
    ));
    assert_eq!(tree.missing_blocks(last, 5).len(), 5);
    assert_eq!(tree.missing_blocks(last, 5)[0], headers[0].id());
}

#[test]
fn invalid_batches_are_rejected() {
    let mut tree = tree();
    let mut sync = PeerHeaderSync::default();
    let mut headers = branch(&tree, genesis(&tree), 3, 1);
    headers[2].prev_block = headers[0].id();
    assert_eq!(
        tree.process(&mut sync, &headers, NOW),
        Err(HeaderError::NotContinuous)
    );

    let mut headers = branch(&tree, genesis(&tree), 1, 1);
    headers[0].target = (U256::MAX >> 1).to_hash();
    assert_eq!(
        tree.process(&mut sync, &headers, NOW),
        Err(HeaderError::Consensus(ConsensusError::WrongTarget))
    );

    let headers = branch(&tree, genesis(&tree), 1, 1);
    assert_eq!(
        tree.process(&mut sync, &headers, headers[0].timestamp - 601),
        Err(HeaderError::Consensus(ConsensusError::TimestampInFuture))
    );

    let mut orphan = branch(&tree, genesis(&tree), 1, 1);
    orphan[0].prev_block = BlockId::new(Hash256::new([9; 32]));
    assert_eq!(
        tree.process(&mut sync, &orphan, NOW),
        Ok(HeaderOutcome::Unconnected)
    );
    assert_eq!(tree.len(), 1);
}

#[test]
fn proof_of_work_is_checked_for_every_header_of_a_batch() {
    // A target of 256: a valid proof of work is practically impossible.
    let params = ConsensusParams {
        pow_limit: U256::ONE << 8,
        ..ConsensusParams::regtest()
    };
    let genesis = params.genesis();
    let mut tree = HeaderTree::new(
        params,
        params.chain_id(),
        U256::ZERO,
        [(
            genesis.id(),
            *genesis.header(),
            0,
            block_work(params.pow_limit),
            false,
        )],
    );
    let mut header = branch(&tree, genesis.id(), 1, 1)[0];
    header.target = (U256::ONE << 8).to_hash();
    assert_eq!(
        tree.process(&mut PeerHeaderSync::default(), &[header], NOW),
        Err(HeaderError::Consensus(ConsensusError::InsufficientWork))
    );
}

#[test]
fn low_work_deep_forks_are_presynced_then_redownloaded() {
    let mut tree = tree();
    let honest = branch(&tree, genesis(&tree), 300, 1);
    tree.process(&mut PeerHeaderSync::default(), &honest, NOW)
        .unwrap();
    assert_eq!(tree.best().1.height, 300);
    let size_before = tree.len();

    // An attacker's branch from genesis: deeper than 288 below the best and
    // with less work, so it is verified but not stored.
    let mut sync = PeerHeaderSync::default();
    let attack = branch(&tree, genesis(&tree), 350, 2);
    let first = tree.process(&mut sync, &attack[..100], NOW).unwrap();
    assert_eq!(
        first,
        HeaderOutcome::Presyncing {
            last: attack[99].id(),
            full: false
        }
    );
    assert_eq!(tree.len(), size_before);
    assert!(sync.is_presyncing());

    // The branch keeps going and overtakes the best chain: redownload.
    let outcome = tree.process(&mut sync, &attack[100..], NOW).unwrap();
    assert_eq!(
        outcome,
        HeaderOutcome::Redownload {
            fork: genesis(&tree)
        }
    );
    assert_eq!(tree.len(), size_before);

    // The same headers again are stored.
    let outcome = tree.process(&mut sync, &attack, NOW).unwrap();
    assert!(matches!(outcome, HeaderOutcome::Stored { ref new, .. } if new.len() == 350));
    assert_eq!(tree.best().0, attack[349].id());
}

#[test]
fn a_different_branch_on_redownload_is_caught() {
    let mut tree = tree();
    let honest = branch(&tree, genesis(&tree), 300, 1);
    tree.process(&mut PeerHeaderSync::default(), &honest, NOW)
        .unwrap();
    let mut sync = PeerHeaderSync::default();
    let presynced = branch(&tree, genesis(&tree), 310, 2);
    assert!(matches!(
        tree.process(&mut sync, &presynced[..100], NOW).unwrap(),
        HeaderOutcome::Presyncing { .. }
    ));
    assert!(matches!(
        tree.process(&mut sync, &presynced[100..], NOW).unwrap(),
        HeaderOutcome::Redownload { .. }
    ));
    let swapped = branch(&tree, genesis(&tree), 310, 3);
    assert_eq!(
        tree.process(&mut sync, &swapped, NOW),
        Err(HeaderError::CommitmentMismatch)
    );
    assert_eq!(tree.best().0, honest[299].id());
}

#[test]
fn shallow_forks_are_stored_directly() {
    let mut tree = tree();
    let honest = branch(&tree, genesis(&tree), 50, 1);
    tree.process(&mut PeerHeaderSync::default(), &honest, NOW)
        .unwrap();
    let side = branch(&tree, honest[39].id(), 5, 2);
    assert!(matches!(
        tree.process(&mut PeerHeaderSync::default(), &side, NOW).unwrap(),
        HeaderOutcome::Stored { ref new, .. } if new.len() == 5
    ));
    assert_eq!(tree.best().0, honest[49].id());
}

#[test]
fn invalid_marks_propagate_and_best_moves() {
    let mut tree = tree();
    let main = branch(&tree, genesis(&tree), 10, 1);
    tree.process(&mut PeerHeaderSync::default(), &main, NOW)
        .unwrap();
    let side = branch(&tree, main[4].id(), 3, 2);
    tree.process(&mut PeerHeaderSync::default(), &side, NOW)
        .unwrap();
    tree.mark_invalid(main[5].id());
    assert!(tree.get(&main[9].id()).unwrap().invalid);
    assert!(!tree.get(&side[2].id()).unwrap().invalid);
    assert_eq!(tree.best().0, side[2].id());
    let child = branch(&tree, main[9].id(), 1, 3);
    assert_eq!(
        tree.process(&mut PeerHeaderSync::default(), &child, NOW),
        Err(HeaderError::InvalidAncestor)
    );
}

#[test]
fn locators_are_dense_near_the_tip_and_end_at_genesis() {
    let mut tree = tree();
    let headers = branch(&tree, genesis(&tree), 100, 1);
    tree.process(&mut PeerHeaderSync::default(), &headers, NOW)
        .unwrap();
    let locator = tree.locator(headers[99].id());
    let heights: Vec<u64> = locator
        .iter()
        .map(|id| tree.get(id).unwrap().height)
        .collect();
    assert_eq!(&heights[..10], &[100, 99, 98, 97, 96, 95, 94, 93, 92, 91]);
    assert_eq!(*heights.last().unwrap(), 0);
    assert!(heights.windows(2).all(|pair| pair[0] > pair[1]));
    assert!(locator.len() < 30);
}
