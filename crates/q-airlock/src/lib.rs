#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use q_codec::{BridgeFact, CodecError, Reader, Writer, FACT_ENCODED_LEN};

pub const ARTIFACT_ATTESTATION: u8 = 0x01;
pub const ARTIFACT_STARK: u8 = 0x02;
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSig {
    pub operator_id: u32,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEnvelope {
    pub fact: BridgeFact,
    pub signatures: Vec<SignerSig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkEnvelope {
    pub statement_digest: [u8; 32],
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Artifact {
    Attestation(AttestationEnvelope),
    Stark(StarkEnvelope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AirlockError {
    Unparseable,
    BadVersion,
    NonCanonical,
    Codec(CodecError),
}

impl From<CodecError> for AirlockError {
    fn from(e: CodecError) -> AirlockError {
        AirlockError::Codec(e)
    }
}

impl AttestationEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(ARTIFACT_ATTESTATION);
        w.u8(ENVELOPE_VERSION);
        w.fixed(&self.fact.encode());
        let mut sigs: Vec<&SignerSig> = self.signatures.iter().collect();
        sigs.sort_by_key(|s| s.operator_id);
        w.u32(sigs.len() as u32);
        for s in sigs {
            w.u32(s.operator_id);
            w.bytes_u16(&s.signature);
        }
        w.finish()
    }
}

impl StarkEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(ARTIFACT_STARK);
        w.fixed(&self.statement_digest);
        w.bytes_u32(&self.proof);
        w.finish()
    }
}

pub fn parse(input: &[u8]) -> Result<Artifact, AirlockError> {
    let mut r = Reader::new(input);
    let tag = r.u8().map_err(|_| AirlockError::Unparseable)?;
    match tag {
        ARTIFACT_ATTESTATION => parse_attestation(&mut r).map(Artifact::Attestation),
        ARTIFACT_STARK => parse_stark(&mut r).map(Artifact::Stark),
        _ => Err(AirlockError::Unparseable),
    }
}

fn parse_attestation(r: &mut Reader) -> Result<AttestationEnvelope, AirlockError> {
    let version = r.u8()?;
    if version != ENVELOPE_VERSION {
        return Err(AirlockError::BadVersion);
    }
    let fact_bytes = r.fixed(FACT_ENCODED_LEN)?;
    let fact = BridgeFact::decode(fact_bytes)?;
    let count = r.u32()?;
    if count == 0 {
        return Err(AirlockError::NonCanonical);
    }
    let mut signatures = Vec::new();
    let mut last_id: Option<u32> = None;
    for _ in 0..count {
        let operator_id = r.u32()?;
        if let Some(prev) = last_id {
            if operator_id <= prev {
                return Err(AirlockError::NonCanonical);
            }
        }
        last_id = Some(operator_id);
        let signature = r.bytes_u16()?.to_vec();
        signatures.push(SignerSig {
            operator_id,
            signature,
        });
    }
    r.finish_ref()?;
    Ok(AttestationEnvelope { fact, signatures })
}

fn parse_stark(r: &mut Reader) -> Result<StarkEnvelope, AirlockError> {
    let statement_digest = r.array32()?;
    let proof = r.bytes_u32()?.to_vec();
    r.finish_ref()?;
    Ok(StarkEnvelope {
        statement_digest,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_codec::{AssetId, Direction, Recipient, SourceRef, FACT_VERSION};

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

    #[test]
    fn attestation_round_trips() {
        let env = AttestationEnvelope {
            fact: fact(),
            signatures: vec![
                SignerSig {
                    operator_id: 0,
                    signature: vec![1, 2, 3],
                },
                SignerSig {
                    operator_id: 4,
                    signature: vec![9; 3309],
                },
            ],
        };
        let bytes = env.encode();
        match parse(&bytes).unwrap() {
            Artifact::Attestation(got) => assert_eq!(got, env),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn stark_round_trips() {
        let env = StarkEnvelope {
            statement_digest: [7u8; 32],
            proof: vec![0xab; 4096],
        };
        let bytes = env.encode();
        match parse(&bytes).unwrap() {
            Artifact::Stark(got) => assert_eq!(got, env),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn foreign_secp256k1_der_signature_is_unparseable() {
        let der = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd, 0xef, 0x02, 0x20, 0x11, 0x22, 0x33,
        ];
        assert_eq!(parse(&der), Err(AirlockError::Unparseable));
    }

    #[test]
    fn foreign_uncompressed_secp256k1_pubkey_is_unparseable() {
        let mut pk = vec![0x04u8];
        pk.extend_from_slice(&[0x7fu8; 64]);
        assert_eq!(parse(&pk), Err(AirlockError::Unparseable));
    }

    #[test]
    fn foreign_ethereum_rlp_header_is_unparseable() {
        let mut rlp = vec![0xf9u8, 0x02, 0x1a];
        rlp.extend_from_slice(&[0x88u8; 500]);
        assert_eq!(parse(&rlp), Err(AirlockError::Unparseable));
    }

    #[test]
    fn foreign_bls12_381_g1_point_is_unparseable() {
        let mut g1 = vec![0xa0u8];
        g1.extend_from_slice(&[0x33u8; 47]);
        assert_eq!(parse(&g1), Err(AirlockError::Unparseable));
    }

    #[test]
    fn empty_input_is_unparseable() {
        assert_eq!(parse(&[]), Err(AirlockError::Unparseable));
    }

    #[test]
    fn attestation_tag_over_foreign_body_is_still_rejected() {
        let mut spoof = vec![ARTIFACT_ATTESTATION];
        spoof.extend_from_slice(&[0x99u8; 64]);
        assert!(parse(&spoof).is_err());
    }

    #[test]
    fn trailing_bytes_after_attestation_are_rejected() {
        let env = AttestationEnvelope {
            fact: fact(),
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: vec![1u8; 8],
            }],
        };
        let mut bytes = env.encode();
        bytes.push(0);
        assert!(matches!(
            parse(&bytes),
            Err(AirlockError::Codec(CodecError::TrailingBytes))
        ));
    }

    #[test]
    fn an_attestation_encoding_is_canonical_by_operator_id() {
        let sig = |id: u32| SignerSig {
            operator_id: id,
            signature: vec![1u8; 8],
        };

        let canonical = AttestationEnvelope {
            fact: fact(),
            signatures: vec![sig(0), sig(4)],
        };
        assert!(parse(&canonical.encode()).is_ok());

        let unsorted = AttestationEnvelope {
            fact: fact(),
            signatures: vec![sig(4), sig(0)],
        };
        assert_eq!(unsorted.encode(), canonical.encode());

        let duplicate = AttestationEnvelope {
            fact: fact(),
            signatures: vec![sig(2), sig(2)],
        };
        assert!(matches!(
            parse(&duplicate.encode()),
            Err(AirlockError::NonCanonical)
        ));

        let empty = AttestationEnvelope {
            fact: fact(),
            signatures: vec![],
        };
        assert!(matches!(parse(&empty.encode()), Err(AirlockError::NonCanonical)));
    }
}
