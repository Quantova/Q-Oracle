// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLock {
    pub source_chain: u32,
    pub source_ref: [u8; 32],
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub recipient: [u8; 32],
    pub observed_height: u64,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorridorContext {
    pub source_chain: u32,
    pub dest_chain: u32,
    pub route_id: u32,
    pub required_confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherError {
    SourceUnavailable,
    NotFinal { got: u32, need: u32 },
}

pub trait Watcher {
    fn source_chain(&self) -> u32;
    fn poll_finalized(&self) -> Result<Vec<ObservedLock>, WatcherError>;
}

pub struct FinalityPolicy {
    required: BTreeMap<u32, u32>,
}

impl FinalityPolicy {
    pub fn new() -> FinalityPolicy {
        FinalityPolicy {
            required: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, source_chain: u32, confirmations: u32) {
        self.required.insert(source_chain, confirmations);
    }

    pub fn required(&self, source_chain: u32) -> Option<u32> {
        self.required.get(&source_chain).copied()
    }

    pub fn is_final(&self, lock: &ObservedLock) -> Result<(), WatcherError> {
        match self.required.get(&lock.source_chain) {
            None => Err(WatcherError::SourceUnavailable),
            Some(&need) => {
                if lock.confirmations >= need {
                    Ok(())
                } else {
                    Err(WatcherError::NotFinal {
                        got: lock.confirmations,
                        need,
                    })
                }
            }
        }
    }
}

impl Default for FinalityPolicy {
    fn default() -> FinalityPolicy {
        FinalityPolicy::new()
    }
}

pub struct WatcherSet {
    watchers: BTreeMap<u32, Box<dyn Watcher>>,
}

impl WatcherSet {
    pub fn new() -> WatcherSet {
        WatcherSet {
            watchers: BTreeMap::new(),
        }
    }

    pub fn attach(&mut self, watcher: Box<dyn Watcher>) {
        self.watchers.insert(watcher.source_chain(), watcher);
    }

    pub fn chains(&self) -> Vec<u32> {
        self.watchers.keys().copied().collect()
    }

    pub fn poll(&self, source_chain: u32) -> Result<Vec<ObservedLock>, WatcherError> {
        match self.watchers.get(&source_chain) {
            Some(w) => w.poll_finalized(),
            None => Err(WatcherError::SourceUnavailable),
        }
    }
}

impl Default for WatcherSet {
    fn default() -> WatcherSet {
        WatcherSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockNode {
        chain: u32,
        locks: Vec<ObservedLock>,
    }

    impl Watcher for MockNode {
        fn source_chain(&self) -> u32 {
            self.chain
        }

        fn poll_finalized(&self) -> Result<Vec<ObservedLock>, WatcherError> {
            Ok(self.locks.clone())
        }
    }

    fn lock(chain: u32) -> ObservedLock {
        ObservedLock {
            source_chain: chain,
            source_ref: [chain as u8; 32],
            asset_id: [0x22u8; 16],
            amount: 500,
            recipient: [0x33u8; 32],
            observed_height: 800_000,
            confirmations: 6,
        }
    }

    #[test]
    fn each_corridor_polls_its_own_source() {
        let mut set = WatcherSet::new();
        set.attach(Box::new(MockNode {
            chain: 1,
            locks: vec![lock(1)],
        }));
        set.attach(Box::new(MockNode {
            chain: 2,
            locks: vec![lock(2)],
        }));
        assert_eq!(set.chains(), vec![1, 2]);
        assert_eq!(set.poll(1).unwrap()[0].source_chain, 1);
        assert_eq!(set.poll(2).unwrap()[0].source_chain, 2);
    }

    #[test]
    fn an_unattached_chain_has_no_source() {
        let set = WatcherSet::new();
        assert_eq!(set.poll(7), Err(WatcherError::SourceUnavailable));
    }
}
