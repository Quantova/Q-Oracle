// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{Artifact, StarkEnvelope};
use q_attestor::watcher::{CorridorContext, ObservedLock};
use q_attestor::{Aggregator, Operator, SoftSigner};
use q_exits::{ExitProver, ExitStatement, HashStark, EXIT_STATEMENT_VERSION};
use q_isolation::{admit, PqArtifact};
use qtv_crypto::ml_dsa::SIGNATURE_BYTES;

fn real_attestation() -> q_airlock::AttestationEnvelope {
    let ctx = CorridorContext {
        source_chain: 1,
        dest_chain: 9000,
        route_id: 7,
        required_confirmations: 6,
    };
    let lock = ObservedLock {
        source_chain: 1,
        source_ref: [0x44u8; 32],
        asset_id: [0x22u8; 16],
        amount: 500,
        recipient: [0x33u8; 32],
        observed_height: 800_001,
        confirmations: 6,
    };
    let mut op = Operator::new(SoftSigner::from_seed(0, &[0x09u8; 32]));
    op.configure_corridor(ctx);
    let observation = op.observe_and_sign(&lock, 900_000).expect("a final lock signs");
    let mut agg = Aggregator::new(1);
    agg.add(&observation.fact, observation.sig).expect("first signature seeds the fact");
    agg.try_finalize().expect("threshold of one finalizes")
}

fn real_stark() -> StarkEnvelope {
    let statement = ExitStatement {
        version: EXIT_STATEMENT_VERSION,
        home_chain: 9000,
        corridor: 1,
        asset_id: [0xa1u8; 16],
        amount: 500,
        beneficiary: [0x55u8; 32],
        burn_ref: [0x11u8; 32],
        finalized_height: 4_200_000,
    };
    StarkEnvelope {
        statement_digest: statement.digest(),
        proof: HashStark.prove(&statement),
    }
}

#[test]
fn a_real_ml_dsa_attestation_crosses() {
    let env = real_attestation();
    assert_eq!(env.signatures.len(), 1);
    assert_eq!(env.signatures[0].signature.len(), SIGNATURE_BYTES);

    let crossing = admit(&env.encode()).expect("the attestation crosses");
    assert_eq!(crossing.kind, PqArtifact::MlDsaAttestation);
    assert_eq!(crossing.artifact, Artifact::Attestation(env));
}

#[test]
fn a_real_hash_stark_crosses() {
    let env = real_stark();
    let crossing = admit(&env.encode()).expect("the stark crosses");
    assert_eq!(crossing.kind, PqArtifact::HashStark);
    assert_eq!(crossing.artifact, Artifact::Stark(env));
}

#[test]
fn both_post_quantum_artifacts_cross_and_nothing_between_them() {
    let crossed: Vec<PqArtifact> = vec![
        admit(&real_attestation().encode()).unwrap().kind,
        admit(&real_stark().encode()).unwrap().kind,
    ];
    assert_eq!(crossed, vec![PqArtifact::MlDsaAttestation, PqArtifact::HashStark]);
}

#[test]
fn a_crossed_artifact_re_encodes_to_the_same_crossing() {
    for original in [real_attestation().encode(), real_stark().encode()] {
        let first = admit(&original).expect("crosses once");
        let reencoded = match &first.artifact {
            Artifact::Attestation(a) => a.encode(),
            Artifact::Stark(s) => s.encode(),
        };
        let second = admit(&reencoded).expect("crosses again");
        assert_eq!(first, second);
        assert_eq!(reencoded, original);
    }
}
