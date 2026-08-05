// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::StarkEnvelope;
use qtv_stark::codec::{decode_proof, encode_proof};
use qtv_stark::sponge::{absorb_air, absorb_output, absorb_trace, SHAKE256_RATE};
use qtv_stark::stark::{prove_with_domain, verify_with_domain, StarkParams};

use crate::statement::{CorridorStatement, STATEMENT_DIGEST_LEN};

pub const BRIDGE_BLOWUP: usize = 128;
pub const BRIDGE_QUERIES: usize = 43;

fn params() -> StarkParams {
    StarkParams {
        lde_blowup: BRIDGE_BLOWUP,
        num_queries: BRIDGE_QUERIES,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentProof {
    pub digest: [u8; STATEMENT_DIGEST_LEN],
    pub proof: Vec<u8>,
}

pub fn prove_statement(statement: &CorridorStatement) -> CommitmentProof {
    let preimage = statement.preimage();
    let context = statement.domain_context();
    let instance = absorb_trace(SHAKE256_RATE, &preimage);
    let proof = prove_with_domain(&instance.air, &instance.trace, &params(), &context);
    let mut digest = [0u8; STATEMENT_DIGEST_LEN];
    digest.copy_from_slice(&instance.output[..STATEMENT_DIGEST_LEN]);
    CommitmentProof {
        digest,
        proof: encode_proof(&proof),
    }
}

pub fn verify_statement(statement: &CorridorStatement, commitment: &CommitmentProof) -> bool {
    let preimage = statement.preimage();
    let squeeze = absorb_output(SHAKE256_RATE, &preimage);
    if commitment.digest[..] != squeeze[..STATEMENT_DIGEST_LEN] {
        return false;
    }
    let proof = match decode_proof(&commitment.proof) {
        Some(proof) => proof,
        None => return false,
    };
    let context = statement.domain_context();
    let air = absorb_air(SHAKE256_RATE, &preimage, &squeeze);
    verify_with_domain(&air, &params(), &proof, &context)
}

impl CommitmentProof {
    pub fn to_envelope(&self) -> StarkEnvelope {
        StarkEnvelope {
            statement_digest: self.digest,
            proof: self.proof.clone(),
        }
    }

    pub fn from_envelope(envelope: &StarkEnvelope) -> CommitmentProof {
        CommitmentProof {
            digest: envelope.statement_digest,
            proof: envelope.proof.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::CorridorStatement;
    use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION};

    fn fact() -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            direction: Direction::Deposit,
            nonce: 42,
            source_ref: SourceRef([9u8; 32]),
            asset_id: AssetId([3u8; 16]),
            amount: 1_000_000,
            recipient: Recipient([5u8; 32]),
            finality_depth: 12,
            observed_height: 880_000,
            expiry_height: 900_000,
        }
    }

    fn statement() -> CorridorStatement {
        CorridorStatement::new(4, fact())
    }

    #[test]
    fn a_statement_proves_and_verifies() {
        let s = statement();
        let commitment = prove_statement(&s);
        assert_eq!(commitment.digest, s.digest());
        assert!(verify_statement(&s, &commitment));
    }

    #[test]
    fn the_proof_is_a_native_hash_based_stark() {
        let commitment = prove_statement(&statement());
        assert!(decode_proof(&commitment.proof).is_some());
    }

    #[test]
    fn a_proof_for_another_statement_does_not_verify() {
        let s = statement();
        let mut other = statement();
        other.fact.amount = 1_000_001;
        let commitment = prove_statement(&other);
        assert!(!verify_statement(&s, &commitment));
    }

    #[test]
    fn a_proof_for_one_destination_chain_does_not_verify_for_another() {
        let s = statement();
        let commitment = prove_statement(&s);
        assert!(verify_statement(&s, &commitment));
        let mut other = statement();
        other.fact.dest_chain = 9001;
        assert!(!verify_statement(&other, &commitment));
    }

    #[test]
    fn a_proof_at_one_nonce_does_not_verify_at_a_replayed_nonce() {
        let s = statement();
        let commitment = prove_statement(&s);
        let mut replay = statement();
        replay.fact.nonce += 1;
        assert!(!verify_statement(&replay, &commitment));
    }

    #[test]
    fn a_tampered_digest_does_not_verify() {
        let s = statement();
        let mut commitment = prove_statement(&s);
        commitment.digest[0] ^= 1;
        assert!(!verify_statement(&s, &commitment));
    }

    #[test]
    fn a_tampered_proof_byte_does_not_verify() {
        let s = statement();
        let mut commitment = prove_statement(&s);
        let last = commitment.proof.len() - 1;
        commitment.proof[last] ^= 1;
        assert!(!verify_statement(&s, &commitment));
    }

    #[test]
    fn a_foreign_signature_is_not_a_valid_proof() {
        let s = statement();
        let der = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd, 0xef, 0x02, 0x20, 0x11, 0x22, 0x33,
        ];
        let commitment = CommitmentProof {
            digest: s.digest(),
            proof: der,
        };
        assert!(!verify_statement(&s, &commitment));
    }

    #[test]
    fn the_commitment_round_trips_through_the_airlock_envelope() {
        let s = statement();
        let commitment = prove_statement(&s);
        let envelope = commitment.to_envelope();
        assert_eq!(envelope.statement_digest, commitment.digest);
        let bytes = envelope.encode();
        let parsed = match q_airlock::parse(&bytes).unwrap() {
            q_airlock::Artifact::Stark(env) => env,
            _ => panic!("wrong variant"),
        };
        let restored = CommitmentProof::from_envelope(&parsed);
        assert!(verify_statement(&s, &restored));
    }
}
