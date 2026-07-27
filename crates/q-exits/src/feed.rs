// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::errors::ExitError;
use crate::exits::{ExitDesk, ExitId};
use crate::watch::{BurnWatchError, BurnWatcher, QuantovaBurnSource};

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

pub struct BurnFeed {
    watcher: BurnWatcher,
    enabled: bool,
}

impl BurnFeed {
    pub fn new(start_height: u64, config: ExitConfig) -> BurnFeed {
        BurnFeed {
            watcher: BurnWatcher::new(start_height),
            enabled: config.enabled,
        }
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
        let proofs = self.watcher.poll(source).map_err(FeedError::Source)?;
        let mut opened = Vec::new();
        for proof in &proofs {
            match desk.open_exit(proof, vault_id, now) {
                Ok(id) => opened.push(id),
                Err(ExitError::ReplayedExit) => continue,
                Err(_) => continue,
            }
        }
        Ok(opened)
    }
}
