// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use q_airlock::SignerSig;
use q_codec::{attest_context, BridgeFact};
use qtv_crypto::sha3::sha3_256;

use crate::signer::AttestationSigner;
use crate::translator::translate;
use crate::watcher::{CorridorContext, ObservedLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltReason {
    Divergence,
    Overload,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorState {
    Running,
    Halted(HaltReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorError {
    Halted(HaltReason),
    CorridorUnknown(u32),
    BelowFinality { got: u32, need: u32 },
    AlreadySigned,
    SignerUnavailable,
    JournalUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedObservation {
    pub fact: BridgeFact,
    pub sig: SignerSig,
}

fn divergence_digest(lock: &ObservedLock, ctx: &CorridorContext) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&lock.source_chain.to_le_bytes());
    buf.extend_from_slice(&lock.source_ref);
    buf.extend_from_slice(&lock.asset_id);
    buf.extend_from_slice(&lock.amount.to_le_bytes());
    buf.extend_from_slice(&lock.recipient);
    buf.extend_from_slice(&lock.observed_height.to_le_bytes());
    buf.extend_from_slice(&ctx.dest_chain.to_le_bytes());
    buf.extend_from_slice(&ctx.route_id.to_le_bytes());
    sha3_256(&buf)
}

pub struct Operator<S: AttestationSigner> {
    signer: S,
    corridors: BTreeMap<u32, CorridorContext>,
    signed_refs: BTreeMap<(u32, [u8; 32]), u64>,
    seen_facts: BTreeMap<(u32, [u8; 32]), ([u8; 32], u64)>,
    state: OperatorState,
    journal: Option<DivergenceJournal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceRecord {
    pub source_chain: u32,
    pub source_ref: [u8; 32],
    pub digest: [u8; 32],
    pub expiry_height: u64,
    pub signed_expiry: u64,
}

const JOURNAL_MAGIC: &[u8; 4] = b"QDIV";
const JOURNAL_VERSION: u8 = 1;
const JOURNAL_RECORD_LEN: usize = 4 + 32 + 32 + 8 + 8;
const JOURNAL_MAX_RECORDS: usize = 1 << 20;

pub struct DivergenceJournal {
    path: PathBuf,
}

impl DivergenceJournal {
    pub fn new<P: Into<PathBuf>>(path: P) -> DivergenceJournal {
        DivergenceJournal { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn encode(records: &[DivergenceRecord]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + records.len() * JOURNAL_RECORD_LEN + 32);
        out.extend_from_slice(JOURNAL_MAGIC);
        out.push(JOURNAL_VERSION);
        out.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for r in records {
            out.extend_from_slice(&r.source_chain.to_le_bytes());
            out.extend_from_slice(&r.source_ref);
            out.extend_from_slice(&r.digest);
            out.extend_from_slice(&r.expiry_height.to_le_bytes());
            out.extend_from_slice(&r.signed_expiry.to_le_bytes());
        }
        let check = sha3_256(&out);
        out.extend_from_slice(&check);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Vec<DivergenceRecord>> {
        let (body, check) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
        if sha3_256(body) != check || body.len() < 9 || &body[..4] != JOURNAL_MAGIC {
            return None;
        }
        if body[4] != JOURNAL_VERSION {
            return None;
        }
        let count = u32::from_le_bytes(body[5..9].try_into().ok()?) as usize;
        let rest = &body[9..];
        if count > JOURNAL_MAX_RECORDS || rest.len() != count.checked_mul(JOURNAL_RECORD_LEN)? {
            return None;
        }
        let mut records = Vec::with_capacity(count);
        for chunk in rest.as_chunks::<JOURNAL_RECORD_LEN>().0 {
            records.push(DivergenceRecord {
                source_chain: u32::from_le_bytes(chunk[0..4].try_into().ok()?),
                source_ref: chunk[4..36].try_into().ok()?,
                digest: chunk[36..68].try_into().ok()?,
                expiry_height: u64::from_le_bytes(chunk[68..76].try_into().ok()?),
                signed_expiry: u64::from_le_bytes(chunk[76..84].try_into().ok()?),
            });
        }
        Some(records)
    }

    pub fn load(&self) -> io::Result<Vec<DivergenceRecord>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => DivergenceJournal::decode(&bytes).ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "the divergence journal at {} is corrupt",
                        self.path.display()
                    ),
                )
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, records: &[DivergenceRecord]) -> io::Result<()> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut temp = self.path.clone().into_os_string();
        temp.push(format!(".tmp.{}.{nonce}", std::process::id()));
        let temp = PathBuf::from(temp);
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&temp)?;
            file.write_all(&DivergenceJournal::encode(records))?;
            file.sync_all()?;
        }
        std::fs::rename(&temp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    }
}

impl<S: AttestationSigner> Operator<S> {
    pub fn new(signer: S) -> Operator<S> {
        Operator {
            signer,
            corridors: BTreeMap::new(),
            signed_refs: BTreeMap::new(),
            seen_facts: BTreeMap::new(),
            state: OperatorState::Running,
            journal: None,
        }
    }

    pub fn with_journal(signer: S, journal: DivergenceJournal) -> io::Result<Operator<S>> {
        let records = journal.load()?;
        let mut operator = Operator::new(signer);
        operator.restore_divergence(&records);
        operator.journal = Some(journal);
        Ok(operator)
    }

    pub fn configure_corridor(&mut self, ctx: CorridorContext) {
        self.corridors.insert(ctx.source_chain, ctx);
    }

    pub fn state(&self) -> OperatorState {
        self.state
    }

    pub fn is_halted(&self) -> bool {
        matches!(self.state, OperatorState::Halted(_))
    }

    pub fn halt_manual(&mut self) {
        self.state = OperatorState::Halted(HaltReason::Manual);
    }

    pub fn note_load(&mut self, inflight: u32, budget: u32) {
        if inflight > budget {
            self.state = OperatorState::Halted(HaltReason::Overload);
        }
    }

    pub fn prune_expired(&mut self, dest_height: u64) {
        self.seen_facts
            .retain(|_, (_, expiry)| *expiry >= dest_height);
        self.signed_refs.retain(|_, expiry| *expiry >= dest_height);
    }

    pub fn export_divergence(&self) -> Vec<DivergenceRecord> {
        self.seen_facts
            .iter()
            .map(
                |(&(source_chain, source_ref), &(digest, expiry_height))| DivergenceRecord {
                    source_chain,
                    source_ref,
                    digest,
                    expiry_height,
                    signed_expiry: self
                        .signed_refs
                        .get(&(source_chain, source_ref))
                        .copied()
                        .unwrap_or(0),
                },
            )
            .collect()
    }

    pub fn restore_divergence(&mut self, records: &[DivergenceRecord]) {
        for r in records {
            let key = (r.source_chain, r.source_ref);
            self.seen_facts.insert(key, (r.digest, r.expiry_height));
            if r.signed_expiry != 0 {
                self.signed_refs.insert(key, r.signed_expiry);
            }
        }
    }

    pub fn observe_and_sign(
        &mut self,
        lock: &ObservedLock,
        dest_height: u64,
    ) -> Result<SignedObservation, OperatorError> {
        if let OperatorState::Halted(r) = self.state {
            return Err(OperatorError::Halted(r));
        }
        self.prune_expired(dest_height);
        let ctx = self
            .corridors
            .get(&lock.source_chain)
            .copied()
            .ok_or(OperatorError::CorridorUnknown(lock.source_chain))?;
        if lock.confirmations < ctx.required_confirmations {
            return Err(OperatorError::BelowFinality {
                got: lock.confirmations,
                need: ctx.required_confirmations,
            });
        }

        let key = (lock.source_chain, lock.source_ref);
        let fact = translate(lock, &ctx, dest_height);
        let digest = divergence_digest(lock, &ctx);

        match self.seen_facts.get(&key) {
            Some((prev, _)) if *prev != digest => {
                self.state = OperatorState::Halted(HaltReason::Divergence);
                return Err(OperatorError::Halted(HaltReason::Divergence));
            }
            _ => {}
        }

        if self.signed_refs.get(&key) == Some(&fact.expiry_height) {
            return Err(OperatorError::AlreadySigned);
        }

        let fresh_seen = !self.seen_facts.contains_key(&key);
        let previous_signed = self.signed_refs.get(&key).copied();
        self.seen_facts
            .entry(key)
            .or_insert((digest, fact.expiry_height));
        self.signed_refs.insert(key, fact.expiry_height);
        if let Some(journal) = &self.journal {
            if journal.save(&self.export_divergence()).is_err() {
                if fresh_seen {
                    self.seen_facts.remove(&key);
                }
                match previous_signed {
                    Some(expiry) => self.signed_refs.insert(key, expiry),
                    None => self.signed_refs.remove(&key),
                };
                return Err(OperatorError::JournalUnavailable);
            }
        }

        let message = fact.attest_preimage(ctx.dest_chain_id);
        let Some(signature) = self.signer.sign(&message, &attest_context(&ctx.era)) else {
            match previous_signed {
                Some(expiry) => self.signed_refs.insert(key, expiry),
                None => self.signed_refs.remove(&key),
            };
            return Err(OperatorError::SignerUnavailable);
        };

        Ok(SignedObservation {
            fact,
            sig: SignerSig {
                operator_id: self.signer.operator_id(),
                signature: signature.to_vec(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{AttestationSigner, SoftSigner};
    use qtv_crypto::ml_dsa::{self, SIGNATURE_BYTES};

    const DEST_ID: u64 = 0x0000_002a_0000_2328;

    fn ctx() -> CorridorContext {
        CorridorContext {
            source_chain: 1,
            dest_chain: 9000,
            dest_chain_id: DEST_ID,
            route_id: 7,
            required_confirmations: 6,
            era: [0x11u8; 32],
        }
    }

    fn lock() -> ObservedLock {
        ObservedLock {
            source_chain: 1,
            source_ref: [0x44u8; 32],
            asset_id: [0x22u8; 16],
            amount: 500,
            recipient: [0x33u8; 32],
            observed_height: 800_001,
            confirmations: 6,
        }
    }

    fn op() -> Operator<SoftSigner> {
        let seed = [0x09u8; 32];
        let mut o = Operator::new(SoftSigner::from_seed(0, &seed));
        o.configure_corridor(ctx());
        o
    }

    #[test]
    fn signed_observation_verifies_over_the_attest_preimage() {
        let mut operator = op();
        let pk = SoftSigner::from_seed(0, &[0x09u8; 32]).public_key();
        let signed = operator
            .observe_and_sign(&lock(), 900_000)
            .expect("final lock signs");

        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&signed.sig.signature);
        let preimage = signed.fact.attest_preimage(DEST_ID);
        assert!(ml_dsa::verify(
            &pk,
            &preimage,
            &sig,
            &attest_context(&[0x11u8; 32])
        ));
    }

    #[test]
    fn signature_is_bound_to_the_attest_context() {
        let mut operator = op();
        let pk = SoftSigner::from_seed(0, &[0x09u8; 32]).public_key();
        let signed = operator
            .observe_and_sign(&lock(), 900_000)
            .expect("final lock signs");

        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&signed.sig.signature);
        let preimage = signed.fact.attest_preimage(DEST_ID);
        assert!(!ml_dsa::verify(
            &pk,
            &preimage,
            &sig,
            b"QUANTOVA/Q-ORACLE/REORG/v1"
        ));
    }

    #[test]
    fn re_observing_the_same_finalized_lock_does_not_halt() {
        let mut operator = op();
        operator
            .observe_and_sign(&lock(), 900_000)
            .expect("first observation signs");
        assert_eq!(
            operator.observe_and_sign(&lock(), 900_000),
            Err(OperatorError::AlreadySigned)
        );
        assert_eq!(operator.state(), OperatorState::Running);
        assert!(!operator.is_halted());
    }

    #[test]
    fn re_observing_with_a_moved_dest_clock_does_not_halt() {
        let mut operator = op();
        operator
            .observe_and_sign(&lock(), 900_000)
            .expect("first observation signs");
        assert_eq!(
            operator.observe_and_sign(&lock(), 900_500),
            Err(OperatorError::AlreadySigned)
        );
        assert_eq!(operator.state(), OperatorState::Running);
    }

    #[test]
    fn an_operator_across_the_window_boundary_can_join_the_later_expiry() {
        let mut operator = op();
        let early = operator
            .observe_and_sign(&lock(), 907_199)
            .expect("first observation signs");
        let late = operator
            .observe_and_sign(&lock(), 907_200)
            .expect("a later expiry window can be signed so operators converge");
        assert!(late.fact.expiry_height > early.fact.expiry_height);
        assert_eq!(
            operator.observe_and_sign(&lock(), 907_300),
            Err(OperatorError::AlreadySigned)
        );
        assert!(!operator.is_halted());
    }

    #[test]
    fn re_observing_with_grown_confirmations_does_not_halt() {
        let mut operator = op();
        operator
            .observe_and_sign(&lock(), 900_000)
            .expect("first observation signs");
        let mut deeper = lock();
        deeper.confirmations = 40;
        assert_eq!(
            operator.observe_and_sign(&deeper, 900_000),
            Err(OperatorError::AlreadySigned)
        );
        assert!(!operator.is_halted());
    }

    #[test]
    fn the_same_source_ref_on_two_corridors_is_signed_not_read_as_divergence() {
        let seed = [0x09u8; 32];
        let mut operator = Operator::new(SoftSigner::from_seed(0, &seed));
        operator.configure_corridor(ctx());
        let mut ctx2 = ctx();
        ctx2.source_chain = 2;
        operator.configure_corridor(ctx2);

        operator
            .observe_and_sign(&lock(), 900_000)
            .expect("the corridor 1 lock signs");

        let mut cross = lock();
        cross.source_chain = 2;
        operator
            .observe_and_sign(&cross, 900_000)
            .expect("the same reference on another corridor is a fresh fact and signs");
        assert_eq!(operator.state(), OperatorState::Running);
        assert!(!operator.is_halted());
    }

    #[test]
    fn a_conflicting_re_observation_of_a_signed_reference_halts_the_operator() {
        let mut operator = op();
        operator
            .observe_and_sign(&lock(), 900_000)
            .expect("the first final lock signs");
        let mut conflicting = lock();
        conflicting.amount = 999;
        assert_eq!(
            operator.observe_and_sign(&conflicting, 900_000),
            Err(OperatorError::Halted(HaltReason::Divergence))
        );
        assert_eq!(
            operator.state(),
            OperatorState::Halted(HaltReason::Divergence)
        );
        assert!(operator.is_halted());
    }
}
