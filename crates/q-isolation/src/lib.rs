#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{parse, AirlockError, Artifact, ARTIFACT_ATTESTATION, ARTIFACT_STARK};

pub const ATTESTATION_TAG: u8 = ARTIFACT_ATTESTATION;
pub const STARK_TAG: u8 = ARTIFACT_STARK;
pub const CROSSING_KIND_COUNT: usize = 2;

const _: () = assert!(ATTESTATION_TAG == 0x01);
const _: () = assert!(STARK_TAG == 0x02);
const _: () = assert!(ATTESTATION_TAG != STARK_TAG);
const _: () = assert!(CROSSING_KIND_COUNT == 2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqArtifact {
    MlDsaAttestation,
    HashStark,
}

impl PqArtifact {
    pub fn tag(self) -> u8 {
        match self {
            PqArtifact::MlDsaAttestation => ATTESTATION_TAG,
            PqArtifact::HashStark => STARK_TAG,
        }
    }

    pub fn index(self) -> usize {
        match self {
            PqArtifact::MlDsaAttestation => 0,
            PqArtifact::HashStark => 1,
        }
    }
}

pub const ALL_CROSSINGS: [PqArtifact; CROSSING_KIND_COUNT] =
    [PqArtifact::MlDsaAttestation, PqArtifact::HashStark];

pub fn classify(artifact: &Artifact) -> PqArtifact {
    match artifact {
        Artifact::Attestation(_) => PqArtifact::MlDsaAttestation,
        Artifact::Stark(_) => PqArtifact::HashStark,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    Foreign,
    Malformed,
}

impl From<AirlockError> for Refused {
    fn from(e: AirlockError) -> Refused {
        match e {
            AirlockError::Unparseable => Refused::Foreign,
            AirlockError::BadVersion => Refused::Malformed,
            AirlockError::NonCanonical => Refused::Malformed,
            AirlockError::Codec(_) => Refused::Malformed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crossing {
    pub kind: PqArtifact,
    pub artifact: Artifact,
}

pub fn admit(bytes: &[u8]) -> Result<Crossing, Refused> {
    let artifact = parse(bytes)?;
    let kind = classify(&artifact);
    Ok(Crossing { kind, artifact })
}

pub fn admit_artifact(artifact: &Artifact) -> Result<Crossing, Refused> {
    let bytes = match artifact {
        Artifact::Attestation(envelope) => envelope.encode(),
        Artifact::Stark(envelope) => envelope.encode(),
    };
    admit(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_airlock::{AttestationEnvelope, SignerSig, StarkEnvelope};
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

    fn attestation() -> AttestationEnvelope {
        AttestationEnvelope {
            fact: fact(),
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: vec![7u8; 3309],
            }],
        }
    }

    fn stark() -> StarkEnvelope {
        StarkEnvelope {
            statement_digest: [4u8; 32],
            proof: vec![0xabu8; 32],
        }
    }

    #[test]
    fn the_boundary_admits_exactly_two_kinds() {
        assert_eq!(CROSSING_KIND_COUNT, 2);
        assert_eq!(ALL_CROSSINGS.len(), CROSSING_KIND_COUNT);
        assert_eq!(ALL_CROSSINGS[0], PqArtifact::MlDsaAttestation);
        assert_eq!(ALL_CROSSINGS[1], PqArtifact::HashStark);
    }

    #[test]
    fn the_two_kinds_carry_the_two_tags() {
        assert_eq!(PqArtifact::MlDsaAttestation.tag(), 0x01);
        assert_eq!(PqArtifact::HashStark.tag(), 0x02);
        assert_ne!(
            PqArtifact::MlDsaAttestation.tag(),
            PqArtifact::HashStark.tag()
        );
    }

    #[test]
    fn the_index_is_a_bijection_over_the_two_kinds() {
        let mut seen = [false; CROSSING_KIND_COUNT];
        for kind in ALL_CROSSINGS {
            seen[kind.index()] = true;
        }
        assert_eq!(seen, [true, true]);
    }

    #[test]
    fn classify_maps_each_variant_to_its_kind() {
        assert_eq!(
            classify(&Artifact::Attestation(attestation())),
            PqArtifact::MlDsaAttestation
        );
        assert_eq!(classify(&Artifact::Stark(stark())), PqArtifact::HashStark);
    }

    #[test]
    fn an_attestation_crosses_and_round_trips() {
        let env = attestation();
        let crossing = admit(&env.encode()).unwrap();
        assert_eq!(crossing.kind, PqArtifact::MlDsaAttestation);
        assert_eq!(crossing.artifact, Artifact::Attestation(env));
    }

    #[test]
    fn a_stark_crosses_and_round_trips() {
        let env = stark();
        let crossing = admit(&env.encode()).unwrap();
        assert_eq!(crossing.kind, PqArtifact::HashStark);
        assert_eq!(crossing.artifact, Artifact::Stark(env));
    }

    #[test]
    fn an_unknown_tag_is_refused_as_foreign() {
        assert_eq!(admit(&[0x00]), Err(Refused::Foreign));
        assert_eq!(admit(&[0x03, 0x03, 0x03]), Err(Refused::Foreign));
        assert_eq!(admit(&[]), Err(Refused::Foreign));
    }

    #[test]
    fn admit_artifact_routes_each_variant_through_the_door() {
        let crossed = admit_artifact(&Artifact::Attestation(attestation())).unwrap();
        assert_eq!(crossed.kind, PqArtifact::MlDsaAttestation);
        let crossed = admit_artifact(&Artifact::Stark(stark())).unwrap();
        assert_eq!(crossed.kind, PqArtifact::HashStark);
    }
}
