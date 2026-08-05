// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    BurnWatchError, BurnWatcher, FinalizedBlock, QuantovaBurnSource, MAX_BURNS_PER_POLL,
};

use qtv_attest::{Block, Certificate, Envelope, Parent};
use qtv_codec::Encoder;

const ASSET: [u8; 16] = [0xa1; 16];
const HOLDER: [u8; 32] = [0x33; 32];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 500;
const CHAIN_ID: u64 = 9000;

fn burn_leaf(burn_ref: [u8; 32]) -> Vec<u8> {
    let mut data = Encoder::new();
    data.put_bytes(&ASSET);
    data.put_bytes(&HOLDER);
    data.put_u128(AMOUNT);
    data.put_bytes(&BENEFICIARY);
    data.put_u64(CHAIN_ID);
    data.put_u64(0);
    data.put_u64(1);
    data.put_bytes(&burn_ref);

    let mut leaf = Encoder::new();
    leaf.put_bytes(b"qtv/native");
    leaf.put_bytes(b"QBBN");
    leaf.put_bytes(&data.into_bytes());
    leaf.into_bytes()
}

fn certificate(height: u64) -> Certificate {
    let block = Block::new(height, [0u8; 32], Parent::Genesis);
    let envelope = Envelope {
        height,
        slot: 0,
        block,
        committee: [0u8; 32],
    };
    Certificate::new(envelope, Vec::new())
}

fn ref_of(n: usize) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0..8].copy_from_slice(&(n as u64).to_le_bytes());
    r
}

struct Blocks {
    head: u64,
    counts: Vec<usize>,
}

impl QuantovaBurnSource for Blocks {
    fn finalized_height(&self) -> Result<u64, BurnWatchError> {
        Ok(self.head)
    }

    fn finalized_block(&self, height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError> {
        let idx = height as usize;
        if idx == 0 || idx > self.counts.len() {
            return Ok(None);
        }
        let base = idx * 1_000_000;
        let events = (0..self.counts[idx - 1])
            .map(|n| burn_leaf(ref_of(base + n)))
            .collect();
        Ok(Some(FinalizedBlock {
            header_bytes: Vec::new(),
            certificate: certificate(height),
            events,
        }))
    }
}

#[test]
fn a_block_heavier_than_the_poll_budget_is_assembled_in_full() {
    let heavy = MAX_BURNS_PER_POLL + 100;
    let source = Blocks {
        head: 1,
        counts: vec![heavy],
    };
    let mut watcher = BurnWatcher::new(0);
    let proofs = watcher.poll(&source).expect("the poll assembles the heavy block");
    assert_eq!(proofs.len(), heavy, "the whole heavy block is assembled, nothing dropped");
    assert_eq!(watcher.scanned_through(), 1);
}

#[test]
fn burns_beyond_the_poll_budget_are_deferred_not_dropped() {
    let per_block = MAX_BURNS_PER_POLL;
    let source = Blocks {
        head: 3,
        counts: vec![per_block, per_block, per_block],
    };
    let mut watcher = BurnWatcher::new(0);
    let mut total = 0usize;
    for _ in 0..3 {
        total += watcher.poll(&source).expect("poll").len();
    }
    assert_eq!(watcher.scanned_through(), 3, "every block is scanned across the polls");
    assert_eq!(total, per_block * 3, "every burn is assembled exactly once, none dropped");
}
