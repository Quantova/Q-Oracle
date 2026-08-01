// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    BurnWatchError, BurnWatcher, FinalizedBlock, QuantovaBurnSource, MAX_BURNS_PER_BLOCK,
};

use qtv_attest::{Block, Certificate, Envelope, Parent};
use qtv_codec::Encoder;

const ASSET: [u8; 16] = [0xa1; 16];
const HOLDER: [u8; 32] = [0x33; 32];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 500;
const CHAIN_ID: u64 = 9000;

const CHUNK: usize = MAX_BURNS_PER_BLOCK / 8;
const FULL_BLOCKS: u64 = 8;
const TAIL_HEIGHT: u64 = FULL_BLOCKS + 1;
const TAIL_BURN_REF: [u8; 32] = [0x22; 32];

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

struct FloodSource;

impl QuantovaBurnSource for FloodSource {
    fn finalized_height(&self) -> Result<u64, BurnWatchError> {
        Ok(TAIL_HEIGHT)
    }

    fn finalized_block(&self, height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError> {
        let events = if (1..=FULL_BLOCKS).contains(&height) {
            (0..CHUNK).map(|_| burn_leaf([0x11; 32])).collect()
        } else if height == TAIL_HEIGHT {
            vec![burn_leaf(TAIL_BURN_REF)]
        } else {
            return Ok(None);
        };
        Ok(Some(FinalizedBlock {
            header_bytes: Vec::new(),
            certificate: certificate(height),
            events,
        }))
    }
}

#[test]
fn a_full_earlier_block_does_not_swallow_a_later_blocks_burn() {
    assert_eq!(
        CHUNK * FULL_BLOCKS as usize,
        MAX_BURNS_PER_BLOCK,
        "the earlier blocks fill the per-block burn budget exactly"
    );

    let mut watcher = BurnWatcher::new(0);
    let proofs = watcher.poll(&FloodSource).expect("the poll assembles the burns");

    let tail = burn_leaf(TAIL_BURN_REF);
    assert!(
        proofs.iter().any(|proof| proof.leaf == tail),
        "the burn in a later block must not be dropped once earlier blocks filled the buffer"
    );
    assert_eq!(
        proofs.len(),
        MAX_BURNS_PER_BLOCK + 1,
        "every proven burn across the scanned blocks is assembled"
    );
    assert_eq!(watcher.scanned_through(), TAIL_HEIGHT);
}
