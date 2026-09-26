// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::burn_proof::ProofOfBurn;
use crate::errors::ExitError;
use crate::exits::{ExitDesk, ExitId};
use crate::watch::{burn_proofs_for_leaf, BurnWatchError, BurnWatcher, QuantovaBurnSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitConfig {
    pub enabled: bool,
}

impl Default for ExitConfig {
    fn default() -> ExitConfig {
        ExitConfig { enabled: false }
    }
}

impl ExitConfig {
    pub fn disabled() -> ExitConfig {
        ExitConfig { enabled: false }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    Disabled,
    Source(BurnWatchError),
    Exit(ExitError),
}

const MAX_PENDING_BURNS: usize = 1024;

fn retryable(error: &ExitError) -> bool {
    matches!(
        error,
        ExitError::ThinVault { .. }
            | ExitError::PersistFailed
            | ExitError::LedgerFull
            | ExitError::NotFinalized
    )
}

pub struct BurnFeed {
    watcher: BurnWatcher,
    enabled: bool,
    pending: Vec<ProofOfBurn>,
}

impl BurnFeed {
    pub fn new(start_height: u64, config: ExitConfig) -> BurnFeed {
        BurnFeed {
            watcher: BurnWatcher::new(start_height),
            enabled: config.enabled,
            pending: Vec::new(),
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn scanned_through(&self) -> u64 {
        self.watcher.scanned_through()
    }

    pub fn drive(
        &mut self,
        source: &dyn QuantovaBurnSource,
        desk: &mut ExitDesk,
        vault_id: u32,
        now: u64,
    ) -> Result<Vec<ExitId>, FeedError> {
        if !self.enabled {
            return Err(FeedError::Disabled);
        }
        let proofs = if self.pending.len() >= MAX_PENDING_BURNS {
            Vec::new()
        } else {
            self.watcher.poll(source).map_err(FeedError::Source)?
        };
        let mut opened = Vec::new();
        let mut still_pending = Vec::new();
        for proof in std::mem::take(&mut self.pending)
            .into_iter()
            .chain(proofs.into_iter())
        {
            match desk.open_exit(&proof, vault_id, now) {
                Ok(id) => opened.push(id),
                Err(ExitError::ReplayedExit) => {}
                Err(e) if retryable(&e) => still_pending.push(proof),
                Err(e) => {
                    if desk.dead_letter(&proof, &e, now).is_err() {
                        still_pending.push(proof);
                    }
                }
            }
        }
        self.pending = still_pending;
        Ok(opened)
    }

    pub fn retry_dead_letters(
        &mut self,
        source: &dyn QuantovaBurnSource,
        desk: &mut ExitDesk,
        vault_id: u32,
        now: u64,
    ) -> Result<Vec<ExitId>, FeedError> {
        if !self.enabled {
            return Err(FeedError::Disabled);
        }
        let mut opened = Vec::new();
        for letter in desk.dead_letters() {
            let Some(block) = source
                .finalized_block(letter.height)
                .map_err(FeedError::Source)?
            else {
                continue;
            };
            for proof in burn_proofs_for_leaf(&block, &letter.leaf_digest) {
                match desk.open_exit(&proof, vault_id, now) {
                    Ok(id) => opened.push(id),
                    Err(e) if retryable(&e) && self.pending.len() < MAX_PENDING_BURNS => {
                        self.pending.push(proof)
                    }
                    Err(_) => {}
                }
            }
        }
        Ok(opened)
    }
}
