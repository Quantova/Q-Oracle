// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

fn divergence_digest(lock: &ObservedLock, ctx: &CorridorContext) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&lock.source_chain.to_le_bytes());
    buf.extend_from_slice(&lock.source_ref);
    buf.extend_from_slice(&lock.asset_id);
    buf.extend_from_slice(&lock.amount.to_le_bytes());
    buf.extend_from_slice(&lock.recipient);
    buf.extend_from_slice(&lock.observed_height.to_le_bytes());
    buf.extend_from_slice(&lock.confirmations.to_le_bytes());
    buf.extend_from_slice(&ctx.dest_chain.to_le_bytes());
    buf.extend_from_slice(&ctx.route_id.to_le_bytes());
    sha3_256(&buf)
}

pub struct Operator<S: AttestationSigner> {
    signer: S,
    corridors: BTreeMap<u32, CorridorContext>,
    signed_refs: BTreeSet<(u32, [u8; 32])>,
    seen_facts: BTreeMap<(u32, [u8; 32]), [u8; 32]>,
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
        dest_height: u64,
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

        let key = (lock.source_chain, lock.source_ref);
        if self.signed_refs.contains(&key) {
            return Err(OperatorError::AlreadySigned);
        }

        let fact = translate(lock, &ctx, dest_height);
        let digest = divergence_digest(lock, &ctx);

        match self.seen_facts.get(&key) {
            Some(prev) if *prev != digest => {
                self.state = OperatorState::Halted(HaltReason::Divergence);
                return Err(OperatorError::Halted(HaltReason::Divergence));
            }
            Some(_) => {}
            None => {
                self.seen_facts.insert(key, digest);
            }
        }

        let message = fact.attest_preimage(ctx.dest_chain_id);
        let signature = self.signer.sign(&message, ATTEST_DOMAIN);
        self.signed_refs.insert(key);

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
        let signed = operator.observe_and_sign(&lock(), 900_000).expect("final lock signs");

        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&signed.sig.signature);
        let preimage = signed.fact.attest_preimage(DEST_ID);
        assert!(ml_dsa::verify(&pk, &preimage, &sig, ATTEST_DOMAIN));
    }

    #[test]
    fn signature_is_bound_to_the_attest_context() {
        let mut operator = op();
        let pk = SoftSigner::from_seed(0, &[0x09u8; 32]).public_key();
        let signed = operator.observe_and_sign(&lock(), 900_000).expect("final lock signs");

        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&signed.sig.signature);
        let preimage = signed.fact.attest_preimage(DEST_ID);
        assert!(!ml_dsa::verify(&pk, &preimage, &sig, b"QUANTOVA/Q-ORACLE/REORG/v1"));
    }

    #[test]
    fn re_observing_the_same_finalized_lock_does_not_halt() {
        let mut operator = op();
        operator.observe_and_sign(&lock(), 900_000).expect("first observation signs");
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
        operator.observe_and_sign(&lock(), 900_000).expect("first observation signs");
        assert_eq!(
            operator.observe_and_sign(&lock(), 900_500),
            Err(OperatorError::AlreadySigned)
        );
        assert_eq!(operator.state(), OperatorState::Running);
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
    fn a_conflicting_re_observation_of_a_signed_reference_does_not_halt() {
        let mut operator = op();
        operator.observe_and_sign(&lock(), 900_000).expect("the first final lock signs");
        let mut conflicting = lock();
        conflicting.amount = 999;
        assert_eq!(
            operator.observe_and_sign(&conflicting, 900_000),
            Err(OperatorError::AlreadySigned)
        );
        assert_eq!(operator.state(), OperatorState::Running);
        assert!(!operator.is_halted());
    }
}
