// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    BurnWatchError, BurnWatcher, FinalizedBlock, QuantovaBurnSource, MAX_BURNS_PER_POLL,
};

use qtv_attest::{Block, Certificate, Envelope, Parent};
use qtv_block::{event_root, Header};
use qtv_codec::{to_bytes, Encoder};

const ASSET: [u8; 16] = [0xa1; 16];
const HOLDER: [u8; 32] = [0x33; 32];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 500;
const CHAIN_ID: u64 = 9000;

fn nonce_of(tag: &[u8; 32]) -> u64 {
    u64::from_le_bytes(tag[..8].try_into().unwrap())
}

fn bound(
    chain_id: u64,
    amount: u128,
    asset: [u8; 16],
    destination: [u8; 32],
    tag: [u8; 32],
) -> [u8; 32] {
    let mut e = Encoder::new();
    e.put_bytes(b"qtv/bridge/burn-ref/v1");
    e.put_u64(chain_id);
    e.put_bytes(&asset);
    e.put_bytes(&HOLDER);
    e.put_u128(amount);
    e.put_bytes(&destination);
    e.put_u64(nonce_of(&tag));
    e.put_u64(1);
    qtv_crypto::sha3::sha3_256(&e.into_bytes())
}

fn burn_leaf(burn_ref: [u8; 32]) -> Vec<u8> {
    let mut data = Encoder::new();
    data.put_bytes(&ASSET);
    data.put_bytes(&HOLDER);
    data.put_u128(AMOUNT);
    data.put_bytes(&BENEFICIARY);
    data.put_u64(CHAIN_ID);
    data.put_u64(nonce_of(&burn_ref));
    data.put_u64(1);
    data.put_bytes(&bound(CHAIN_ID, AMOUNT, ASSET, BENEFICIARY, burn_ref));

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
        let events: Vec<Vec<u8>> = (0..self.counts[idx - 1])
            .map(|n| burn_leaf(ref_of(base + n)))
            .collect();
        let header = Header::new(
            height,
            [0u8; 32],
            [0x01; 32],
            [0u8; 32],
            event_root(&events),
            [0u8; 32],
            "qtv1proposer".to_string(),
            1,
        );
        Ok(Some(FinalizedBlock {
            header_bytes: to_bytes(&header),
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
    let proofs = watcher
        .poll(&source)
        .expect("the poll assembles the heavy block");
    assert_eq!(
        proofs.len(),
        heavy,
        "the whole heavy block is assembled, nothing dropped"
    );
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
    assert_eq!(
        watcher.scanned_through(),
        3,
        "every block is scanned across the polls"
    );
    assert_eq!(
        total,
        per_block * 3,
        "every burn is assembled exactly once, none dropped"
    );
}

#[test]
fn a_finalized_height_the_node_cannot_serve_is_retried_not_skipped() {
    let short = Blocks {
        head: 5,
        counts: vec![0, 1],
    };
    let mut watcher = BurnWatcher::new(0);
    watcher.poll(&short).expect("poll succeeds");
    assert_eq!(watcher.scanned_through(), 2);
    let full = Blocks {
        head: 5,
        counts: vec![0, 1, 2, 0, 0],
    };
    let burns = watcher.poll(&full).expect("poll succeeds");
    assert_eq!(burns.len(), 2);
    assert_eq!(watcher.scanned_through(), 5);
}
