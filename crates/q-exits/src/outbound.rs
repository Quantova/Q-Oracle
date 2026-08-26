// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use qtv_crypto::ml_dsa::{self, PublicKey, SECRET_KEY_BYTES, SIGNATURE_BYTES};

use crate::exits::ExitStatement;

pub const EXIT_ACK_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-ACK/v1";

// Binds an exit acknowledgement to the chain era it was raised for, so an exit proof from one launch
// of a reused chain name cannot be replayed on the next. The era is the dest chain genesis hash.
pub fn exit_ack_context(era: &[u8; 32]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(EXIT_ACK_DOMAIN.len() + 32);
    ctx.extend_from_slice(EXIT_ACK_DOMAIN);
    ctx.extend_from_slice(era);
    ctx
}
pub const EXIT_FACT_VERSION: u8 = 1;
pub const EXIT_FACT_ENCODED_LEN: usize = 106;
pub const ARTIFACT_EXIT_ACK: u8 = 0x03;
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitOutcome {
    Settle,
    Slash,
}

impl ExitOutcome {
    pub fn tag(self) -> u8 {
        match self {
            ExitOutcome::Settle => 1,
            ExitOutcome::Slash => 2,
        }
    }

    pub fn from_tag(tag: u8) -> Option<ExitOutcome> {
        match tag {
            1 => Some(ExitOutcome::Settle),
            2 => Some(ExitOutcome::Slash),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDecision {
    pub version: u8,
    pub corridor: u32,
    pub dest_chain: u32,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
    pub outcome: ExitOutcome,
}

impl ExitDecision {
    pub fn settle(statement: &ExitStatement, dest_chain: u32) -> ExitDecision {
        ExitDecision {
            version: EXIT_FACT_VERSION,
            corridor: statement.corridor,
            dest_chain,
            asset_id: statement.asset_id,
            amount: statement.amount,
            beneficiary: statement.beneficiary,
            burn_ref: statement.burn_ref,
            outcome: ExitOutcome::Settle,
        }
    }

    pub fn slash(statement: &ExitStatement, payout: u128, dest_chain: u32) -> ExitDecision {
        ExitDecision {
            version: EXIT_FACT_VERSION,
            corridor: statement.corridor,
            dest_chain,
            asset_id: statement.asset_id,
            amount: payout,
            beneficiary: statement.beneficiary,
            burn_ref: statement.burn_ref,
            outcome: ExitOutcome::Slash,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXIT_FACT_ENCODED_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.corridor.to_le_bytes());
        out.extend_from_slice(&self.dest_chain.to_le_bytes());
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.beneficiary);
        out.extend_from_slice(&self.burn_ref);
        out.push(self.outcome.tag());
        out
    }

    pub fn ack_preimage(&self, chain_id: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN + 8);
        out.extend_from_slice(EXIT_ACK_DOMAIN);
        out.extend_from_slice(&self.encode());
        out.extend_from_slice(&chain_id.to_le_bytes());
        out
    }

    pub fn well_formed(&self) -> bool {
        self.version == EXIT_FACT_VERSION
            && self.corridor != 0
            && self.dest_chain != 0
            && self.amount != 0
            && self.asset_id != [0u8; 16]
            && self.beneficiary != [0u8; 32]
            && self.burn_ref != [0u8; 32]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSig {
    pub operator_id: u32,
    pub signature: Vec<u8>,
}

// one operator signs the decision; the quorum of these is the only artifact that crosses
pub fn sign_decision(
    secret: &[u8; SECRET_KEY_BYTES],
    decision: &ExitDecision,
    chain_id: u64,
    era: &[u8; 32],
) -> Option<Vec<u8>> {
    ml_dsa::sign(secret, &decision.ack_preimage(chain_id), &exit_ack_context(era), &[0u8; 32])
        .map(|signature| signature.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitEnvelope {
    pub decision: ExitDecision,
    pub signatures: Vec<SignerSig>,
}

impl ExitEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ARTIFACT_EXIT_ACK);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.decision.encode());
        out.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for signer in &self.signatures {
            out.extend_from_slice(&signer.operator_id.to_le_bytes());
            out.extend_from_slice(&(signer.signature.len() as u16).to_le_bytes());
            out.extend_from_slice(&signer.signature);
        }
        out
    }
}

pub const EXIT_ACK_QUORUM_MIN: usize = 2;

#[derive(Debug, Clone)]
pub struct AckOperator {
    pub operator_id: u32,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitAckError {
    ThinThreshold { threshold: usize, floor: usize },
    Malformed,
    BelowThreshold { got: usize, need: usize },
}

pub fn verify_ack_quorum(
    envelope: &ExitEnvelope,
    operators: &[AckOperator],
    chain_id: u64,
    era: &[u8; 32],
    threshold: usize,
) -> Result<usize, ExitAckError> {
    let floor = EXIT_ACK_QUORUM_MIN.max(operators.len().saturating_mul(2).div_ceil(3));
    if threshold < floor {
        return Err(ExitAckError::ThinThreshold { threshold, floor });
    }
    if !envelope.decision.well_formed() {
        return Err(ExitAckError::Malformed);
    }
    let preimage = envelope.decision.ack_preimage(chain_id);
    let mut distinct = BTreeSet::new();
    for signer in &envelope.signatures {
        let operator = match operators.iter().find(|o| o.operator_id == signer.operator_id) {
            Some(operator) => operator,
            None => continue,
        };
        let signature: &[u8; SIGNATURE_BYTES] = match signer.signature.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if ml_dsa::verify(&operator.public_key, &preimage, signature, &exit_ack_context(era)) {
            distinct.insert(signer.operator_id);
        }
    }
    if distinct.len() < threshold {
        return Err(ExitAckError::BelowThreshold {
            got: distinct.len(),
            need: threshold,
        });
    }
    Ok(distinct.len())
}

#[cfg(test)]
mod tests {
    const TEST_ERA: [u8; 32] = [0x11u8; 32];
    use super::*;
    use crate::exits::EXIT_STATEMENT_VERSION;

    fn statement() -> ExitStatement {
        ExitStatement {
            version: EXIT_STATEMENT_VERSION,
            corridor: 1,
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
            finalized_height: 4_200_000,
        }
    }

    #[test]
    fn a_settle_decision_carries_the_statement_value() {
        let d = ExitDecision::settle(&statement(), 9000);
        assert_eq!(d.outcome, ExitOutcome::Settle);
        assert_eq!(d.amount, 500);
        assert_eq!(d.burn_ref, [0x11; 32]);
        assert_eq!(d.dest_chain, 9000);
        assert!(d.well_formed());
    }

    #[test]
    fn a_slash_decision_carries_the_premium_payout() {
        let d = ExitDecision::slash(&statement(), 550, 9000);
        assert_eq!(d.outcome, ExitOutcome::Slash);
        assert_eq!(d.amount, 550, "the slash decision pays the premium above the burned value");
        assert!(d.well_formed());
    }

    #[test]
    fn a_decision_encodes_to_the_fixed_length() {
        assert_eq!(ExitDecision::settle(&statement(), 9000).encode().len(), EXIT_FACT_ENCODED_LEN);
    }

    #[test]
    fn the_outcome_tag_moves_the_encoding() {
        let settle = ExitDecision::settle(&statement(), 9000).encode();
        let slash = ExitDecision::slash(&statement(), 500, 9000).encode();
        assert_ne!(settle, slash, "the settle and slash outcomes encode to distinct bytes");
        assert_eq!(settle[EXIT_FACT_ENCODED_LEN - 1], 1);
        assert_eq!(slash[EXIT_FACT_ENCODED_LEN - 1], 2);
    }

    // pins the wire layout the chain verifier must match
    #[test]
    fn the_ack_preimage_matches_the_pinned_cross_repo_vector() {
        let decision = ExitDecision {
            version: EXIT_FACT_VERSION,
            corridor: 1,
            dest_chain: 9000,
            asset_id: [0x3; 16],
            amount: 1_100_000,
            beneficiary: [0x5; 32],
            burn_ref: [0x9; 32],
            outcome: ExitOutcome::Slash,
        };
        let preimage = decision.ack_preimage(0x0123_4567_89AB_CDEF);
        assert_eq!(preimage.len(), EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN + 8);
        assert!(preimage.starts_with(EXIT_ACK_DOMAIN));
        assert_eq!(
            &preimage[EXIT_ACK_DOMAIN.len()..EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN],
            decision.encode().as_slice()
        );
        assert_eq!(
            &preimage[EXIT_ACK_DOMAIN.len() + EXIT_FACT_ENCODED_LEN..],
            0x0123_4567_89AB_CDEFu64.to_le_bytes()
        );
    }

    #[test]
    fn a_signed_decision_verifies_under_the_signer_key() {
        let mut seed = [0u8; 32];
        seed[0] = 7;
        let (pk, sk) = ml_dsa::keygen(&seed);
        let decision = ExitDecision::slash(&statement(), 550, 9000);
        let chain_id = 0x0123_4567_89AB_CDEFu64;
        let signature = sign_decision(&sk, &decision, chain_id, &TEST_ERA).expect("a well formed decision signs");
        let sig: &[u8; qtv_crypto::ml_dsa::SIGNATURE_BYTES] =
            signature.as_slice().try_into().expect("the signature is the fixed length");
        assert!(ml_dsa::verify(&pk, &decision.ack_preimage(chain_id), sig, &exit_ack_context(&TEST_ERA)));
        let mut tampered = decision.clone();
        tampered.amount += 1;
        assert!(
            !ml_dsa::verify(&pk, &tampered.ack_preimage(chain_id), sig, &exit_ack_context(&TEST_ERA)),
            "a signature does not carry to a tampered decision"
        );
    }

    #[test]
    fn the_exit_fact_commits_to_the_burn_it_names() {
        // a fact for burn A cannot be reused to settle a different burn B
        let mut seed = [0u8; 32];
        seed[0] = 9;
        let (pk, sk) = ml_dsa::keygen(&seed);
        let chain_id = 0x0123_4567_89AB_CDEFu64;

        let mut burn_a = statement();
        burn_a.burn_ref = [0xa1; 32];
        let mut burn_b = statement();
        burn_b.burn_ref = [0xb2; 32];

        let fact_a = ExitDecision::settle(&burn_a, 9000);
        let fact_b = ExitDecision::settle(&burn_b, 9000);
        assert_ne!(
            fact_a.ack_preimage(chain_id),
            fact_b.ack_preimage(chain_id),
            "the burn reference moves the signed preimage"
        );

        let signature = sign_decision(&sk, &fact_a, chain_id, &TEST_ERA).unwrap();
        let sig: &[u8; SIGNATURE_BYTES] = signature.as_slice().try_into().unwrap();
        assert!(
            ml_dsa::verify(&pk, &fact_a.ack_preimage(chain_id), sig, &exit_ack_context(&TEST_ERA)),
            "the fact verifies against the burn it names"
        );
        assert!(
            !ml_dsa::verify(&pk, &fact_b.ack_preimage(chain_id), sig, &exit_ack_context(&TEST_ERA)),
            "the same signature cannot settle a burn the fact does not name"
        );
    }

    #[test]
    fn an_envelope_carries_the_operator_signatures() {
        let mut seed = [0u8; 32];
        seed[0] = 8;
        let (_pk, sk) = ml_dsa::keygen(&seed);
        let decision = ExitDecision::settle(&statement(), 9000);
        let envelope = ExitEnvelope {
            decision: decision.clone(),
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: sign_decision(&sk, &decision, 9000, &TEST_ERA).unwrap(),
            }],
        };
        let bytes = envelope.encode();
        assert_eq!(bytes[0], ARTIFACT_EXIT_ACK);
        assert_eq!(bytes[1], ENVELOPE_VERSION);
    }

    fn operator(seed_byte: u8) -> (AckOperator, [u8; SECRET_KEY_BYTES]) {
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        let (public_key, sk) = ml_dsa::keygen(&seed);
        (
            AckOperator {
                operator_id: seed_byte as u32,
                public_key,
            },
            sk,
        )
    }

    fn envelope_signed_by(
        decision: &ExitDecision,
        chain_id: u64,
        signers: &[(AckOperator, [u8; SECRET_KEY_BYTES])],
    ) -> ExitEnvelope {
        ExitEnvelope {
            decision: decision.clone(),
            signatures: signers
                .iter()
                .map(|(op, sk)| SignerSig {
                    operator_id: op.operator_id,
                    signature: sign_decision(sk, decision, chain_id, &TEST_ERA).unwrap(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_distinct_signer_quorum_over_the_ack_verifies() {
        let chain_id = 0x0123_4567_89AB_CDEFu64;
        let decision = ExitDecision::settle(&statement(), 9000);
        let signers: Vec<_> = (1..=3).map(operator).collect();
        let operators: Vec<AckOperator> = signers.iter().map(|(op, _)| op.clone()).collect();
        let envelope = envelope_signed_by(&decision, chain_id, &signers);
        assert_eq!(verify_ack_quorum(&envelope, &operators, chain_id, &TEST_ERA, 2), Ok(3));
    }

    #[test]
    fn a_signature_relabeled_under_another_operator_is_not_counted() {
        let chain_id = 9000;
        let decision = ExitDecision::settle(&statement(), 9000);
        let (op_a, sk_a) = operator(1);
        let (op_b, _sk_b) = operator(2);
        let envelope = ExitEnvelope {
            decision: decision.clone(),
            signatures: vec![SignerSig {
                operator_id: op_b.operator_id,
                signature: sign_decision(&sk_a, &decision, chain_id, &TEST_ERA).unwrap(),
            }],
        };
        let operators = vec![op_a, op_b];
        assert_eq!(
            verify_ack_quorum(&envelope, &operators, chain_id, &TEST_ERA, 2),
            Err(ExitAckError::BelowThreshold { got: 0, need: 2 })
        );
    }

    #[test]
    fn a_threshold_below_the_floor_fails_closed() {
        let chain_id = 9000;
        let decision = ExitDecision::settle(&statement(), 9000);
        let signers: Vec<_> = (1..=3).map(operator).collect();
        let operators: Vec<AckOperator> = signers.iter().map(|(op, _)| op.clone()).collect();
        let envelope = envelope_signed_by(&decision, chain_id, &signers);
        assert_eq!(
            verify_ack_quorum(&envelope, &operators, chain_id, &TEST_ERA, 1),
            Err(ExitAckError::ThinThreshold { threshold: 1, floor: 2 })
        );
    }

    #[test]
    fn a_threshold_below_two_thirds_of_the_operator_set_is_refused() {
        let chain_id = 9000;
        let decision = ExitDecision::settle(&statement(), 9000);
        let signers: Vec<_> = (1..=6).map(operator).collect();
        let operators: Vec<AckOperator> = signers.iter().map(|(op, _)| op.clone()).collect();
        let envelope = envelope_signed_by(&decision, chain_id, &signers);
        assert_eq!(
            verify_ack_quorum(&envelope, &operators, chain_id, &TEST_ERA, 2),
            Err(ExitAckError::ThinThreshold { threshold: 2, floor: 4 }),
            "two acks cannot settle against a six operator set"
        );
        assert_eq!(verify_ack_quorum(&envelope, &operators, chain_id, &TEST_ERA, 4), Ok(6));
    }

    #[test]
    fn a_quorum_short_of_the_threshold_is_rejected() {
        let chain_id = 9000;
        let decision = ExitDecision::settle(&statement(), 9000);
        let signers: Vec<_> = (1..=3).map(operator).collect();
        let operators: Vec<AckOperator> = signers.iter().map(|(op, _)| op.clone()).collect();
        let envelope = envelope_signed_by(&decision, chain_id, &signers[0..1]);
        assert_eq!(
            verify_ack_quorum(&envelope, &operators, chain_id, &TEST_ERA, 2),
            Err(ExitAckError::BelowThreshold { got: 1, need: 2 })
        );
    }
}
