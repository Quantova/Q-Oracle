// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{Artifact, AttestationEnvelope, StarkEnvelope};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION};
use q_isolation::{admit, PqArtifact, ATTESTATION_TAG, STARK_TAG};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn tail(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            for b in self.next().to_le_bytes() {
                if v.len() < len {
                    v.push(b);
                }
            }
        }
        v
    }
}

fn valid_fact() -> BridgeFact {
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

fn valid_attestation_bytes() -> Vec<u8> {
    AttestationEnvelope {
        fact: valid_fact(),
        signatures: Vec::new(),
    }
    .encode()
}

fn valid_stark_bytes() -> Vec<u8> {
    StarkEnvelope {
        statement_digest: [7u8; 32],
        proof: vec![0xabu8; 64],
    }
    .encode()
}

#[test]
fn only_the_two_tags_can_ever_cross() {
    let mut rng = Rng(0x0BAD_F00D_D15E_A5ED);
    for tag in 0u16..=255 {
        let tag = tag as u8;
        if tag == ATTESTATION_TAG || tag == STARK_TAG {
            continue;
        }
        for len in 0..40usize {
            for _ in 0..8 {
                let mut input = vec![tag];
                input.extend_from_slice(&rng.tail(len));
                assert!(
                    admit(&input).is_err(),
                    "a leading tag outside the two must never cross"
                );
            }
        }
    }
}

#[test]
fn the_two_tags_do_carry_a_crossing() {
    assert_eq!(
        admit(&valid_attestation_bytes()).unwrap().kind,
        PqArtifact::MlDsaAttestation
    );
    assert_eq!(
        admit(&valid_stark_bytes()).unwrap().kind,
        PqArtifact::HashStark
    );
}

#[test]
fn the_success_codomain_is_exactly_the_two_kinds() {
    let mut reached = [false; 2];
    for bytes in [valid_attestation_bytes(), valid_stark_bytes()] {
        let kind = admit(&bytes).unwrap().kind;
        reached[kind.index()] = true;
    }
    assert_eq!(reached, [true, true]);
}

#[test]
fn the_translation_is_idempotent_on_what_crosses() {
    for bytes in [valid_attestation_bytes(), valid_stark_bytes()] {
        let first = admit(&bytes).unwrap();
        let canonical = match &first.artifact {
            Artifact::Attestation(a) => a.encode(),
            Artifact::Stark(s) => s.encode(),
        };
        assert_eq!(canonical, bytes);
        assert_eq!(admit(&canonical).unwrap(), first);
    }
}

#[test]
fn a_foreign_root_only_crosses_stamped_as_our_own_stark() {
    let foreign_root = [0x9au8; 32];

    let bare = foreign_root.to_vec();
    assert!(admit(&bare).is_err());

    let mut mislabeled = vec![ATTESTATION_TAG];
    mislabeled.extend_from_slice(&foreign_root);
    assert!(admit(&mislabeled).is_err());

    let stamped = StarkEnvelope {
        statement_digest: foreign_root,
        proof: vec![0x00u8; 32],
    };
    let crossing = admit(&stamped.encode()).expect("a well formed stark crosses");
    assert_eq!(crossing.kind, PqArtifact::HashStark);
    match crossing.artifact {
        Artifact::Stark(s) => {
            assert_eq!(s.statement_digest, foreign_root);
            assert_eq!(s.encode()[0], STARK_TAG);
        }
        _ => panic!("a stark envelope classifies as a stark"),
    }
}
