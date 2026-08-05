// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use crate::errors::ExitError;
use crate::store::ReplayStore;

pub const LEDGER_VERSION: u8 = 1;
pub const MAX_LEDGER_ENTRIES: u32 = 4_000_000;

const MAGIC: [u8; 4] = *b"QXLG";
const HEADER_LEN: usize = 5;
const FRAME_LEN: usize = 36;

fn header() -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(&MAGIC);
    out[4] = LEDGER_VERSION;
    out
}

fn tag_of(burn_ref: &[u8; 32]) -> [u8; 4] {
    let digest = qtv_crypto::sha3::sha3_256(burn_ref);
    [digest[0], digest[1], digest[2], digest[3]]
}

fn frame_of(burn_ref: &[u8; 32]) -> [u8; FRAME_LEN] {
    let mut out = [0u8; FRAME_LEN];
    out[..32].copy_from_slice(burn_ref);
    out[32..].copy_from_slice(&tag_of(burn_ref));
    out
}

fn load_frames(bytes: &[u8]) -> Result<(BTreeSet<[u8; 32]>, bool), ExitError> {
    if bytes.len() < HEADER_LEN || bytes[..4] != MAGIC || bytes[4] != LEDGER_VERSION {
        return Err(ExitError::PersistFailed);
    }
    let body = &bytes[HEADER_LEN..];
    let whole = body.len() / FRAME_LEN;
    let torn = body.len() % FRAME_LEN != 0;
    if whole as u64 > MAX_LEDGER_ENTRIES as u64 {
        return Err(ExitError::PersistFailed);
    }
    let mut set = BTreeSet::new();
    for i in 0..whole {
        let chunk = &body[i * FRAME_LEN..(i + 1) * FRAME_LEN];
        let mut burn_ref = [0u8; 32];
        burn_ref.copy_from_slice(&chunk[..32]);
        if chunk[32..] != tag_of(&burn_ref)[..] {
            return Err(ExitError::PersistFailed);
        }
        set.insert(burn_ref);
    }
    Ok((set, torn))
}

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
        if self.released.contains(&burn_ref) {
            return Ok(());
        }
        if self.released.len() >= MAX_LEDGER_ENTRIES as usize {
            return Err(ExitError::LedgerFull);
        }
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
        let (released, torn) = match store.load().map_err(|_| ExitError::PersistFailed)? {
            Some(bytes) => load_frames(&bytes)?,
            None => {
                store.save(&header()).map_err(|_| ExitError::PersistFailed)?;
                (BTreeSet::new(), false)
            }
        };
        let ledger = PersistentLedger { released, store };
        if torn {
            ledger.compact()?;
        }
        Ok(ledger)
    }

    pub fn store(&self) -> &ReplayStore {
        &self.store
    }

    fn compact(&self) -> Result<(), ExitError> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.released.len() * FRAME_LEN);
        out.extend_from_slice(&header());
        for burn_ref in &self.released {
            out.extend_from_slice(&frame_of(burn_ref));
        }
        self.store.save(&out).map_err(|_| ExitError::PersistFailed)
    }
}

impl ReplayLedger for PersistentLedger {
    fn is_released(&self, burn_ref: &[u8; 32]) -> bool {
        self.released.contains(burn_ref)
    }

    fn record(&mut self, burn_ref: [u8; 32]) -> Result<(), ExitError> {
        if self.released.contains(&burn_ref) {
            return Ok(());
        }
        if self.released.len() >= MAX_LEDGER_ENTRIES as usize {
            return Err(ExitError::LedgerFull);
        }
        match self.store.append(&frame_of(&burn_ref)) {
            Ok(()) => {
                self.released.insert(burn_ref);
                Ok(())
            }
            Err(_) => Err(ExitError::PersistFailed),
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

    #[test]
    fn a_torn_tail_frame_is_dropped_and_the_committed_prefix_survives() {
        let path = temp_path("torn");
        {
            let mut ledger = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
            ledger.record([0x01; 32]).unwrap();
            ledger.record([0x02; 32]).unwrap();
        }
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(&[0xab; 20]);
        std::fs::write(&path, &raw).unwrap();

        let reopened = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
        assert!(reopened.is_released(&[0x01; 32]), "a committed frame before the torn tail survives");
        assert!(reopened.is_released(&[0x02; 32]), "a committed frame before the torn tail survives");
        assert_eq!(reopened.len(), 2, "the torn partial frame is dropped, not counted");

        let compacted = std::fs::read(&path).unwrap();
        assert_eq!(compacted.len(), HEADER_LEN + 2 * FRAME_LEN, "open compacts the torn tail away");
        let again = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
        assert_eq!(again.len(), 2, "the compacted file reopens with exactly the committed set");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_complete_frame_with_a_bad_tag_fails_closed() {
        let path = temp_path("badtag");
        {
            let mut ledger = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
            ledger.record([0x07; 32]).unwrap();
        }
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(
            PersistentLedger::open(ReplayStore::new(path.clone())).err(),
            Some(ExitError::PersistFailed),
            "a corrupt complete frame refuses to open rather than silently dropping a released burn"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_reopened_append_lands_after_a_compacted_torn_tail() {
        let path = temp_path("append-after-torn");
        {
            let mut ledger = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
            ledger.record([0x01; 32]).unwrap();
        }
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(&[0xcd; 10]);
        std::fs::write(&path, &raw).unwrap();
        {
            let mut ledger = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
            ledger.record([0x02; 32]).unwrap();
        }
        let reopened = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
        assert!(reopened.is_released(&[0x01; 32]), "the pre-crash record survives");
        assert!(reopened.is_released(&[0x02; 32]), "the post-crash record is readable, not stranded behind orphan bytes");
        assert_eq!(reopened.len(), 2);
        std::fs::remove_file(&path).ok();
    }
}
