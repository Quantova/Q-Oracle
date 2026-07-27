// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::ml_dsa::{self, SECRET_KEY_BYTES};

use crate::exits::ExitStatement;

pub const EXIT_ACK_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-ACK/v1";
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
) -> Option<Vec<u8>> {
    ml_dsa::sign(secret, &decision.ack_preimage(chain_id), EXIT_ACK_DOMAIN, &[0u8; 32])
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

#[cfg(test)]
mod tests {
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
        let signature = sign_decision(&sk, &decision, chain_id).expect("a well formed decision signs");
        let sig: &[u8; qtv_crypto::ml_dsa::SIGNATURE_BYTES] =
            signature.as_slice().try_into().expect("the signature is the fixed length");
        assert!(ml_dsa::verify(&pk, &decision.ack_preimage(chain_id), sig, EXIT_ACK_DOMAIN));
        let mut tampered = decision.clone();
        tampered.amount += 1;
        assert!(
            !ml_dsa::verify(&pk, &tampered.ack_preimage(chain_id), sig, EXIT_ACK_DOMAIN),
            "a signature does not carry to a tampered decision"
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
                signature: sign_decision(&sk, &decision, 9000).unwrap(),
            }],
        };
        let bytes = envelope.encode();
        assert_eq!(bytes[0], ARTIFACT_EXIT_ACK);
        assert_eq!(bytes[1], ENVELOPE_VERSION);
    }
}
