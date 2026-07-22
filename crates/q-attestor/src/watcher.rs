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
