use std::collections::{BTreeMap, BTreeSet};

use q_airlock::SignerSig;
use q_codec::{BridgeFact, ATTEST_DOMAIN};
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedObservation {
    pub fact: BridgeFact,
    pub sig: SignerSig,
}

pub struct Operator<S: AttestationSigner> {
    signer: S,
    corridors: BTreeMap<u32, CorridorContext>,
    signed_refs: BTreeSet<[u8; 32]>,
    seen_facts: BTreeMap<[u8; 32], [u8; 32]>,
    state: OperatorState,
}

impl<S: AttestationSigner> Operator<S> {
    pub fn new(signer: S) -> Operator<S> {
        Operator {
            signer,
            corridors: BTreeMap::new(),
            signed_refs: BTreeSet::new(),
            seen_facts: BTreeMap::new(),
            state: OperatorState::Running,
        }
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

    pub fn observe_and_sign(
        &mut self,
        lock: &ObservedLock,
    ) -> Result<SignedObservation, OperatorError> {
        if let OperatorState::Halted(r) = self.state {
            return Err(OperatorError::Halted(r));
        }
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

        let fact = translate(lock, &ctx);
        let digest = sha3_256(&fact.encode());

        match self.seen_facts.get(&lock.source_ref) {
            Some(prev) if *prev != digest => {
                self.state = OperatorState::Halted(HaltReason::Divergence);
                return Err(OperatorError::Halted(HaltReason::Divergence));
            }
            Some(_) => {}
            None => {
                self.seen_facts.insert(lock.source_ref, digest);
            }
        }

        if self.signed_refs.contains(&lock.source_ref) {
            return Err(OperatorError::AlreadySigned);
        }

        let message = fact.encode();
        let signature = self.signer.sign(&message, ATTEST_DOMAIN);
        self.signed_refs.insert(lock.source_ref);

        Ok(SignedObservation {
            fact,
            sig: SignerSig {
                operator_id: self.signer.operator_id(),
                signature: signature.to_vec(),
            },
        })
    }
}
