// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::Certificate;
use qtv_block::{event_root, header_from_bytes, prove_inclusion};
use qtv_codec::Decoder;

use crate::burn_proof::{leaf_digest, ProofOfBurn, EVENT_BRIDGE_BURN, NATIVE_EVENT_SOURCE};

pub const MAX_HEIGHTS_PER_POLL: u64 = 1024;
pub const MAX_BURNS_PER_POLL: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurnWatchError {
    SourceUnavailable,
    Rpc(String),
    EventRootMismatch(u64),
}

pub struct FinalizedBlock {
    pub header_bytes: Vec<u8>,
    pub certificate: Certificate,
    pub events: Vec<Vec<u8>>,
}

pub trait QuantovaBurnSource {
    fn finalized_height(&self) -> Result<u64, BurnWatchError>;
    fn finalized_block(&self, height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError>;

    fn burn_heights_after(&self, cursor: u64) -> Result<Vec<u64>, BurnWatchError> {
        let head = self.finalized_height()?;
        let last = head.min(cursor.saturating_add(MAX_HEIGHTS_PER_POLL));
        Ok((cursor.saturating_add(1)..=last).collect())
    }
}

fn served_matches_header(block: &FinalizedBlock, height: u64) -> bool {
    match header_from_bytes(&block.header_bytes) {
        Ok(header) => {
            header.height() == height && *header.event_root() == event_root(&block.events)
        }
        Err(_) => false,
    }
}

pub fn is_bridge_burn_leaf(leaf: &[u8]) -> bool {
    let mut outer = Decoder::new(leaf);
    let contract = match outer.get_bytes() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let selector = match outer.get_bytes() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    contract == NATIVE_EVENT_SOURCE && selector == EVENT_BRIDGE_BURN
}

fn assemble(block: &FinalizedBlock, index: usize) -> Option<ProofOfBurn> {
    let leaf = block.events.get(index)?;
    if !is_bridge_burn_leaf(leaf) {
        return None;
    }
    let inclusion = prove_inclusion(&block.events, index)?;
    Some(ProofOfBurn {
        header_bytes: block.header_bytes.clone(),
        certificate: block.certificate.clone(),
        leaf: leaf.clone(),
        inclusion,
    })
}

pub fn burn_proofs_for_leaf(block: &FinalizedBlock, digest: &[u8; 32]) -> Vec<ProofOfBurn> {
    (0..block.events.len())
        .filter(|&index| leaf_digest(&block.events[index]) == *digest)
        .filter_map(|index| assemble(block, index))
        .collect()
}

pub struct BurnWatcher {
    scanned_through: u64,
}

impl BurnWatcher {
    pub fn new(start_height: u64) -> BurnWatcher {
        BurnWatcher {
            scanned_through: start_height,
        }
    }

    pub fn scanned_through(&self) -> u64 {
        self.scanned_through
    }

    pub fn poll(
        &mut self,
        source: &dyn QuantovaBurnSource,
    ) -> Result<Vec<ProofOfBurn>, BurnWatchError> {
        let head = source.finalized_height()?;
        if head <= self.scanned_through {
            return Ok(Vec::new());
        }
        let mut heights = source.burn_heights_after(self.scanned_through)?;
        heights.retain(|height| *height > self.scanned_through && *height <= head);
        heights.sort_unstable();
        heights.dedup();
        if heights.is_empty() {
            self.scanned_through = head;
            return Ok(Vec::new());
        }
        let mut assembled = Vec::new();
        for height in heights.into_iter().take(MAX_HEIGHTS_PER_POLL as usize) {
            let Some(block) = source.finalized_block(height)? else {
                break;
            };
            if !served_matches_header(&block, height) {
                return Err(BurnWatchError::EventRootMismatch(height));
            }
            assembled.extend((0..block.events.len()).filter_map(|index| assemble(&block, index)));
            self.scanned_through = height;
            if assembled.len() >= MAX_BURNS_PER_POLL {
                break;
            }
        }
        Ok(assembled)
    }
}
