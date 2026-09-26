// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::errors::ExitError;
use crate::store::ReplayStore;

pub const JOURNAL_VERSION: u8 = 1;
pub const MAX_JOURNAL_ENTRIES: u32 = 8_000_000;

const MAGIC: [u8; 4] = *b"QXEJ";
const HEADER_LEN: usize = 5;
const BODY_LEN: usize = 177;
const FRAME_LEN: usize = 1 + 4 + BODY_LEN + 4;

const KIND_OPEN: u8 = 1;
const KIND_SETTLE: u8 = 2;
const KIND_SLASH: u8 = 3;
const KIND_DEAD: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournaledExit {
    pub version: u8,
    pub corridor: u32,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub holder: [u8; 32],
    pub destination: [u8; 32],
    pub burn_ref: [u8; 32],
    pub finalized_height: u64,
    pub vault_id: u32,
    pub locked: u128,
    pub issued_at: u64,
    pub deadline: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadReason {
    Unproven,
    Malformed,
    WrongDestination,
    UnservedAsset,
    AboveCeiling,
    UnknownVault,
    Refused,
}

impl DeadReason {
    pub fn of(error: &ExitError) -> DeadReason {
        match error {
            ExitError::HeaderDecode
            | ExitError::HeaderMismatch
            | ExitError::HeightMismatch
            | ExitError::NotFinalized
            | ExitError::BadInclusion => DeadReason::Unproven,
            ExitError::LeafDecode
            | ExitError::NotABurnLeaf
            | ExitError::BadVersion(_)
            | ExitError::ZeroAmount
            | ExitError::ZeroAsset
            | ExitError::ZeroBeneficiary
            | ExitError::ZeroBurnRef
            | ExitError::ZeroCorridor
            | ExitError::InvalidArtifact(_) => DeadReason::Malformed,
            ExitError::WrongDestination { .. } => DeadReason::WrongDestination,
            ExitError::UnservedAsset { .. } => DeadReason::UnservedAsset,
            ExitError::AmountAboveCeiling { .. } => DeadReason::AboveCeiling,
            ExitError::UnknownVault(_) => DeadReason::UnknownVault,
            _ => DeadReason::Refused,
        }
    }

    fn tag(self) -> u8 {
        match self {
            DeadReason::Unproven => 1,
            DeadReason::Malformed => 2,
            DeadReason::WrongDestination => 3,
            DeadReason::UnservedAsset => 4,
            DeadReason::AboveCeiling => 5,
            DeadReason::UnknownVault => 6,
            DeadReason::Refused => 7,
        }
    }

    fn from_tag(tag: u8) -> Option<DeadReason> {
        match tag {
            1 => Some(DeadReason::Unproven),
            2 => Some(DeadReason::Malformed),
            3 => Some(DeadReason::WrongDestination),
            4 => Some(DeadReason::UnservedAsset),
            5 => Some(DeadReason::AboveCeiling),
            6 => Some(DeadReason::UnknownVault),
            7 => Some(DeadReason::Refused),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadLetter {
    pub height: u64,
    pub leaf_digest: [u8; 32],
    pub burn_ref: [u8; 32],
    pub reason: DeadReason,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitEvent {
    Open { index: u32, exit: JournaledExit },
    Settle { index: u32, foreign_ref: [u8; 32] },
    Slash { index: u32 },
    DeadLetter { index: u32, letter: DeadLetter },
}

fn header() -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(&MAGIC);
    out[4] = JOURNAL_VERSION;
    out
}

fn tag_of(preimage: &[u8]) -> [u8; 4] {
    let digest = qtv_crypto::sha3::sha3_256(preimage);
    [digest[0], digest[1], digest[2], digest[3]]
}

fn frame_of(event: &ExitEvent) -> [u8; FRAME_LEN] {
    let mut out = [0u8; FRAME_LEN];
    match event {
        ExitEvent::Open { index, exit } => {
            out[0] = KIND_OPEN;
            out[1..5].copy_from_slice(&index.to_le_bytes());
            let b = &mut out[5..5 + BODY_LEN];
            b[0] = exit.version;
            b[1..5].copy_from_slice(&exit.corridor.to_le_bytes());
            b[5..21].copy_from_slice(&exit.asset_id);
            b[21..37].copy_from_slice(&exit.amount.to_le_bytes());
            b[37..69].copy_from_slice(&exit.holder);
            b[69..101].copy_from_slice(&exit.destination);
            b[101..133].copy_from_slice(&exit.burn_ref);
            b[133..141].copy_from_slice(&exit.finalized_height.to_le_bytes());
            b[141..145].copy_from_slice(&exit.vault_id.to_le_bytes());
            b[145..161].copy_from_slice(&exit.locked.to_le_bytes());
            b[161..169].copy_from_slice(&exit.issued_at.to_le_bytes());
            b[169..177].copy_from_slice(&exit.deadline.to_le_bytes());
        }
        ExitEvent::Settle { index, foreign_ref } => {
            out[0] = KIND_SETTLE;
            out[1..5].copy_from_slice(&index.to_le_bytes());
            out[5..37].copy_from_slice(foreign_ref);
        }
        ExitEvent::Slash { index } => {
            out[0] = KIND_SLASH;
            out[1..5].copy_from_slice(&index.to_le_bytes());
        }
        ExitEvent::DeadLetter { index, letter } => {
            out[0] = KIND_DEAD;
            out[1..5].copy_from_slice(&index.to_le_bytes());
            let b = &mut out[5..5 + BODY_LEN];
            b[0..8].copy_from_slice(&letter.height.to_le_bytes());
            b[8..40].copy_from_slice(&letter.leaf_digest);
            b[40..72].copy_from_slice(&letter.burn_ref);
            b[72] = letter.reason.tag();
            b[73..81].copy_from_slice(&letter.recorded_at.to_le_bytes());
        }
    }
    let tag = tag_of(&out[..1 + 4 + BODY_LEN]);
    out[1 + 4 + BODY_LEN..].copy_from_slice(&tag);
    out
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

fn u128_at(b: &[u8], off: usize) -> u128 {
    let mut w = [0u8; 16];
    w.copy_from_slice(&b[off..off + 16]);
    u128::from_le_bytes(w)
}

fn arr16(b: &[u8], off: usize) -> [u8; 16] {
    let mut w = [0u8; 16];
    w.copy_from_slice(&b[off..off + 16]);
    w
}

fn arr32(b: &[u8], off: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w.copy_from_slice(&b[off..off + 32]);
    w
}

fn decode_frame(frame: &[u8]) -> Result<ExitEvent, ExitError> {
    if frame[1 + 4 + BODY_LEN..] != tag_of(&frame[..1 + 4 + BODY_LEN])[..] {
        return Err(ExitError::PersistFailed);
    }
    let index = u32_at(frame, 1);
    let b = &frame[5..5 + BODY_LEN];
    match frame[0] {
        KIND_OPEN => Ok(ExitEvent::Open {
            index,
            exit: JournaledExit {
                version: b[0],
                corridor: u32_at(b, 1),
                asset_id: arr16(b, 5),
                amount: u128_at(b, 21),
                holder: arr32(b, 37),
                destination: arr32(b, 69),
                burn_ref: arr32(b, 101),
                finalized_height: u64_at(b, 133),
                vault_id: u32_at(b, 141),
                locked: u128_at(b, 145),
                issued_at: u64_at(b, 161),
                deadline: u64_at(b, 169),
            },
        }),
        KIND_SETTLE => Ok(ExitEvent::Settle {
            index,
            foreign_ref: arr32(b, 0),
        }),
        KIND_SLASH => Ok(ExitEvent::Slash { index }),
        KIND_DEAD => Ok(ExitEvent::DeadLetter {
            index,
            letter: DeadLetter {
                height: u64_at(b, 0),
                leaf_digest: arr32(b, 8),
                burn_ref: arr32(b, 40),
                reason: DeadReason::from_tag(b[72]).ok_or(ExitError::PersistFailed)?,
                recorded_at: u64_at(b, 73),
            },
        }),
        _ => Err(ExitError::PersistFailed),
    }
}

fn load_frames(bytes: &[u8]) -> Result<(Vec<ExitEvent>, bool), ExitError> {
    if bytes.len() < HEADER_LEN || bytes[..4] != MAGIC || bytes[4] != JOURNAL_VERSION {
        return Err(ExitError::PersistFailed);
    }
    let body = &bytes[HEADER_LEN..];
    let whole = body.len() / FRAME_LEN;
    let torn = body.len() % FRAME_LEN != 0;
    if whole as u64 > MAX_JOURNAL_ENTRIES as u64 {
        return Err(ExitError::PersistFailed);
    }
    let mut events = Vec::with_capacity(whole);
    for i in 0..whole {
        let frame = &body[i * FRAME_LEN..(i + 1) * FRAME_LEN];
        events.push(decode_frame(frame)?);
    }
    Ok((events, torn))
}

pub trait ExitJournal {
    fn append(&mut self, event: &ExitEvent) -> Result<(), ExitError>;
    fn events(&self) -> &[ExitEvent];
    fn len(&self) -> usize {
        self.events().len()
    }
    fn is_empty(&self) -> bool {
        self.events().is_empty()
    }
}

#[derive(Default)]
pub struct NullJournal;

impl NullJournal {
    pub fn new() -> NullJournal {
        NullJournal
    }
}

impl ExitJournal for NullJournal {
    fn append(&mut self, _event: &ExitEvent) -> Result<(), ExitError> {
        Ok(())
    }

    fn events(&self) -> &[ExitEvent] {
        &[]
    }
}

pub struct PersistentJournal {
    events: Vec<ExitEvent>,
    store: ReplayStore,
}

impl PersistentJournal {
    pub fn open(store: ReplayStore) -> Result<PersistentJournal, ExitError> {
        let (events, torn) = match store.load().map_err(|_| ExitError::PersistFailed)? {
            Some(bytes) => load_frames(&bytes)?,
            None => {
                store
                    .save(&header())
                    .map_err(|_| ExitError::PersistFailed)?;
                (Vec::new(), false)
            }
        };
        let journal = PersistentJournal { events, store };
        if torn {
            journal.compact()?;
        }
        Ok(journal)
    }

    fn compact(&self) -> Result<(), ExitError> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.events.len() * FRAME_LEN);
        out.extend_from_slice(&header());
        for event in &self.events {
            out.extend_from_slice(&frame_of(event));
        }
        self.store.save(&out).map_err(|_| ExitError::PersistFailed)
    }
}

impl ExitJournal for PersistentJournal {
    fn append(&mut self, event: &ExitEvent) -> Result<(), ExitError> {
        if self.events.len() >= MAX_JOURNAL_ENTRIES as usize {
            return Err(ExitError::LedgerFull);
        }
        match self.store.append_frame(&frame_of(event), HEADER_LEN as u64) {
            Ok(()) => {
                self.events.push(event.clone());
                Ok(())
            }
            Err(_) => Err(ExitError::PersistFailed),
        }
    }

    fn events(&self) -> &[ExitEvent] {
        &self.events
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
        path.push(format!(
            "q-oracle-journal-{tag}-{}-{nanos}.jrn",
            std::process::id()
        ));
        path
    }

    fn an_exit() -> JournaledExit {
        JournaledExit {
            version: 1,
            corridor: 7,
            asset_id: [0xa1; 16],
            amount: 1_000,
            holder: [0x33; 32],
            destination: [0x55; 32],
            burn_ref: [0x11; 32],
            finalized_height: 4_200_000,
            vault_id: 3,
            locked: 1_500,
            issued_at: 900,
            deadline: 87_300,
        }
    }

    #[test]
    fn every_event_round_trips_through_a_frame() {
        for event in [
            ExitEvent::Open {
                index: 0,
                exit: an_exit(),
            },
            ExitEvent::Settle {
                index: 4,
                foreign_ref: [0x77; 32],
            },
            ExitEvent::Slash { index: 9 },
            ExitEvent::DeadLetter {
                index: 2,
                letter: DeadLetter {
                    height: 4_200_000,
                    leaf_digest: [0x44; 32],
                    burn_ref: [0x11; 32],
                    reason: DeadReason::UnservedAsset,
                    recorded_at: 1_700,
                },
            },
        ] {
            let frame = frame_of(&event);
            assert_eq!(decode_frame(&frame).unwrap(), event);
        }
    }

    #[test]
    fn a_dead_letter_with_an_unknown_reason_fails_closed() {
        let mut frame = frame_of(&ExitEvent::DeadLetter {
            index: 0,
            letter: DeadLetter {
                height: 1,
                leaf_digest: [0x44; 32],
                burn_ref: [0x11; 32],
                reason: DeadReason::Refused,
                recorded_at: 1,
            },
        });
        frame[5 + 72] = 0xee;
        let tag = tag_of(&frame[..1 + 4 + BODY_LEN]);
        frame[1 + 4 + BODY_LEN..].copy_from_slice(&tag);
        assert_eq!(decode_frame(&frame), Err(ExitError::PersistFailed));
    }

    #[test]
    fn the_recorded_events_survive_a_reopen_in_order() {
        let path = temp_path("reopen");
        {
            let mut j = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
            j.append(&ExitEvent::Open {
                index: 0,
                exit: an_exit(),
            })
            .unwrap();
            j.append(&ExitEvent::Open {
                index: 1,
                exit: an_exit(),
            })
            .unwrap();
            j.append(&ExitEvent::Settle {
                index: 0,
                foreign_ref: [0x77; 32],
            })
            .unwrap();
        }
        let reopened = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
        assert_eq!(reopened.len(), 3);
        assert_eq!(
            reopened.events()[2],
            ExitEvent::Settle {
                index: 0,
                foreign_ref: [0x77; 32]
            }
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_torn_tail_frame_is_dropped_and_the_committed_prefix_survives() {
        let path = temp_path("torn");
        {
            let mut j = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
            j.append(&ExitEvent::Open {
                index: 0,
                exit: an_exit(),
            })
            .unwrap();
            j.append(&ExitEvent::Slash { index: 0 }).unwrap();
        }
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(&[0xab; 40]);
        std::fs::write(&path, &raw).unwrap();

        let reopened = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
        assert_eq!(
            reopened.len(),
            2,
            "the torn partial frame is dropped, not counted"
        );
        let compacted = std::fs::read(&path).unwrap();
        assert_eq!(
            compacted.len(),
            HEADER_LEN + 2 * FRAME_LEN,
            "open compacts the torn tail away"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_append_after_a_torn_write_keeps_every_later_frame_aligned() {
        let path = temp_path("tornappend");
        let mut j = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
        j.append(&ExitEvent::Open {
            index: 0,
            exit: an_exit(),
        })
        .unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(&[0xab; 40]);
        std::fs::write(&path, &raw).unwrap();
        j.append(&ExitEvent::Slash { index: 0 }).unwrap();
        drop(j);
        let reopened = PersistentJournal::open(ReplayStore::new(path.clone()))
            .expect("a torn write never misaligns the frames appended after it");
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.events()[1], ExitEvent::Slash { index: 0 });
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_complete_frame_with_a_bad_tag_fails_closed() {
        let path = temp_path("badtag");
        {
            let mut j = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
            j.append(&ExitEvent::Open {
                index: 0,
                exit: an_exit(),
            })
            .unwrap();
        }
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(
            PersistentJournal::open(ReplayStore::new(path.clone())).err(),
            Some(ExitError::PersistFailed),
            "a corrupt complete frame refuses to open rather than silently dropping an exit"
        );
        std::fs::remove_file(&path).ok();
    }
}
