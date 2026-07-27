// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use q_codec::{Reader, Writer};

use crate::errors::ExitError;
use crate::store::ReplayStore;

pub const LEDGER_VERSION: u8 = 1;
pub const MAX_LEDGER_ENTRIES: u32 = 4_000_000;

pub trait ReplayLedger {
    fn is_released(&self, burn_ref: &[u8; 32]) -> bool;
    fn record(&mut self, burn_ref: [u8; 32]) -> Result<(), ExitError>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Default)]
pub struct MemoryLedger {
    released: BTreeSet<[u8; 32]>,
}

impl MemoryLedger {
    pub fn new() -> MemoryLedger {
        MemoryLedger {
            released: BTreeSet::new(),
        }
    }
}

impl ReplayLedger for MemoryLedger {
    fn is_released(&self, burn_ref: &[u8; 32]) -> bool {
        self.released.contains(burn_ref)
    }

    fn record(&mut self, burn_ref: [u8; 32]) -> Result<(), ExitError> {
        self.released.insert(burn_ref);
        Ok(())
    }

    fn len(&self) -> usize {
        self.released.len()
    }
}

pub struct PersistentLedger {
    released: BTreeSet<[u8; 32]>,
    store: ReplayStore,
}

impl PersistentLedger {
    pub fn open(store: ReplayStore) -> Result<PersistentLedger, ExitError> {
        let released = match store.load().map_err(|_| ExitError::PersistFailed)? {
            Some(bytes) => decode_set(&bytes)?,
            None => BTreeSet::new(),
        };
        Ok(PersistentLedger { released, store })
    }

    pub fn store(&self) -> &ReplayStore {
        &self.store
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(LEDGER_VERSION);
        w.u32(self.released.len() as u32);
        for burn_ref in &self.released {
            w.fixed(burn_ref);
        }
        w.finish()
    }
}

fn decode_set(input: &[u8]) -> Result<BTreeSet<[u8; 32]>, ExitError> {
    let mut r = Reader::new(input);
    let version = r.u8().map_err(|_| ExitError::PersistFailed)?;
    if version != LEDGER_VERSION {
        return Err(ExitError::PersistFailed);
    }
    let count = r.u32().map_err(|_| ExitError::PersistFailed)?;
    if count > MAX_LEDGER_ENTRIES {
        return Err(ExitError::PersistFailed);
    }
    let mut set = BTreeSet::new();
    for _ in 0..count {
        let burn_ref = r.array32().map_err(|_| ExitError::PersistFailed)?;
        set.insert(burn_ref);
    }
    r.finish_ref().map_err(|_| ExitError::PersistFailed)?;
    Ok(set)
}

impl ReplayLedger for PersistentLedger {
    fn is_released(&self, burn_ref: &[u8; 32]) -> bool {
        self.released.contains(burn_ref)
    }

    fn record(&mut self, burn_ref: [u8; 32]) -> Result<(), ExitError> {
        if !self.released.insert(burn_ref) {
            return Ok(());
        }
        match self.store.save(&self.encode()) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.released.remove(&burn_ref);
                Err(ExitError::PersistFailed)
            }
        }
    }

    fn len(&self) -> usize {
        self.released.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("q-oracle-ledger-{tag}-{}-{nanos}.led", std::process::id()));
        path
    }

    #[test]
    fn a_memory_ledger_records_and_reports() {
        let mut ledger = MemoryLedger::new();
        assert!(!ledger.is_released(&[0x11; 32]));
        ledger.record([0x11; 32]).unwrap();
        assert!(ledger.is_released(&[0x11; 32]));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn a_recorded_ref_survives_a_reopen() {
        let path = temp_path("reopen");
        {
            let mut ledger = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
            ledger.record([0xaa; 32]).unwrap();
            assert!(ledger.is_released(&[0xaa; 32]));
        }
        let reopened = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
        assert!(reopened.is_released(&[0xaa; 32]));
        assert!(!reopened.is_released(&[0xbb; 32]));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_save_failure_rolls_the_in_memory_set_back() {
        let mut ledger = PersistentLedger {
            released: BTreeSet::new(),
            store: ReplayStore::new("/no-such-q-oracle-exit-dir/replay.led"),
        };
        assert_eq!(ledger.record([0xcc; 32]), Err(ExitError::PersistFailed));
        assert!(
            !ledger.is_released(&[0xcc; 32]),
            "a persist failure leaves memory in step with disk"
        );
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn a_corrupt_ledger_file_refuses_to_open() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"\xff\xff not a ledger").unwrap();
        assert_eq!(
            PersistentLedger::open(ReplayStore::new(path.clone())).err(),
            Some(ExitError::PersistFailed)
        );
        std::fs::remove_file(&path).ok();
    }
}
