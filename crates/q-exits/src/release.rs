// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{BTreeMap, BTreeSet};

use q_codec::{Reader, Writer};
use qtv_crypto::ml_dsa::{self, PublicKey, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

use crate::burn_proof::AuthenticatedBurn;
use crate::errors::ExitError;

pub const RELEASE_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-RELEASE/v1";
pub const RELEASE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTerms {
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
}

impl ReleaseTerms {
    pub fn from_burn(burn: &AuthenticatedBurn) -> ReleaseTerms {
        ReleaseTerms {
            asset_id: burn.asset_id,
            amount: burn.amount,
            beneficiary: burn.beneficiary,
            burn_ref: burn.burn_ref,
        }
    }

    pub fn preimage(&self, vault: &[u8; 32], dest_chain: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(RELEASE_VERSION);
        w.u32(dest_chain);
        w.fixed(vault);
        w.fixed(&self.asset_id);
        w.u128(self.amount);
        w.fixed(&self.beneficiary);
        w.fixed(&self.burn_ref);
        w.finish()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.asset_id);
        w.u128(self.amount);
        w.fixed(&self.beneficiary);
        w.fixed(&self.burn_ref);
        w.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSig {
    pub operator_id: u32,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAuthorization {
    pub terms: ReleaseTerms,
    pub signatures: Vec<OperatorSig>,
}

impl ReleaseAuthorization {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(RELEASE_VERSION);
        w.fixed(&self.terms.encode());
        w.u32(self.signatures.len() as u32);
        for sig in &self.signatures {
            w.u32(sig.operator_id);
            w.bytes_u16(&sig.signature);
        }
        w.finish()
    }

    pub fn decode(input: &[u8]) -> Result<ReleaseAuthorization, ExitError> {
        let mut r = Reader::new(input);
        let version = r.u8().map_err(|_| ExitError::LeafDecode)?;
        if version != RELEASE_VERSION {
            return Err(ExitError::LeafDecode);
        }
        let asset_id = r.fixed(16).map_err(|_| ExitError::LeafDecode)?.to_vec();
        let amount = r.u128().map_err(|_| ExitError::LeafDecode)?;
        let beneficiary = r.fixed(32).map_err(|_| ExitError::LeafDecode)?.to_vec();
        let burn_ref = r.fixed(32).map_err(|_| ExitError::LeafDecode)?.to_vec();
        let count = r.u32().map_err(|_| ExitError::LeafDecode)?;
        let mut signatures = Vec::new();
        for _ in 0..count {
            let operator_id = r.u32().map_err(|_| ExitError::LeafDecode)?;
            let signature = r.bytes_u16().map_err(|_| ExitError::LeafDecode)?.to_vec();
            signatures.push(OperatorSig {
                operator_id,
                signature,
            });
        }
        r.finish_ref().map_err(|_| ExitError::LeafDecode)?;
        Ok(ReleaseAuthorization {
            terms: ReleaseTerms {
                asset_id: <[u8; 16]>::try_from(asset_id.as_slice())
                    .map_err(|_| ExitError::LeafDecode)?,
                amount,
                beneficiary: <[u8; 32]>::try_from(beneficiary.as_slice())
                    .map_err(|_| ExitError::LeafDecode)?,
                burn_ref: <[u8; 32]>::try_from(burn_ref.as_slice())
                    .map_err(|_| ExitError::LeafDecode)?,
            },
            signatures,
        })
    }
}

pub struct OperatorQuorum {
    operators: BTreeMap<u32, PublicKey>,
    threshold: usize,
}

impl OperatorQuorum {
    pub fn from_config(
        operators: Vec<(u32, Vec<u8>)>,
        threshold: usize,
    ) -> Result<OperatorQuorum, ExitError> {
        if threshold == 0 {
            return Err(ExitError::ZeroThreshold);
        }
        if operators.is_empty() {
            return Err(ExitError::UnsetCustody);
        }
        let mut map: BTreeMap<u32, PublicKey> = BTreeMap::new();
        for (id, pk_bytes) in operators {
            if pk_bytes.len() != PUBLIC_KEY_BYTES {
                return Err(ExitError::BadPublicKeyLen);
            }
            let mut pk = [0u8; PUBLIC_KEY_BYTES];
            pk.copy_from_slice(&pk_bytes);
            map.insert(id, pk);
        }
        if threshold > map.len() {
            return Err(ExitError::ThresholdAboveRoster);
        }
        Ok(OperatorQuorum {
            operators: map,
            threshold,
        })
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn len(&self) -> usize {
        self.operators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }

    pub fn verify(&self, preimage: &[u8], signatures: &[OperatorSig]) -> Result<(), ExitError> {
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for sig in signatures {
            let pk = self
                .operators
                .get(&sig.operator_id)
                .ok_or(ExitError::UnknownOperator(sig.operator_id))?;
            if sig.signature.len() != SIGNATURE_BYTES {
                return Err(ExitError::BadSignature(sig.operator_id));
            }
            let mut bytes = [0u8; SIGNATURE_BYTES];
            bytes.copy_from_slice(&sig.signature);
            if !ml_dsa::verify(pk, preimage, &bytes, RELEASE_DOMAIN) {
                return Err(ExitError::BadSignature(sig.operator_id));
            }
            seen.insert(sig.operator_id);
        }
        if seen.len() < self.threshold {
            return Err(ExitError::BelowThreshold {
                have: seen.len(),
                need: self.threshold,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_crypto::ml_dsa::{keygen, sign, SEED_BYTES};

    fn terms() -> ReleaseTerms {
        ReleaseTerms {
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
        }
    }

    fn operator(id: u8) -> (u32, [u8; SEED_BYTES], Vec<u8>) {
        let seed = [id; SEED_BYTES];
        let (pk, _sk) = keygen(&seed);
        (id as u32, seed, pk.to_vec())
    }

    fn sign_terms(seed: &[u8; SEED_BYTES], preimage: &[u8]) -> Vec<u8> {
        let (_pk, sk) = keygen(seed);
        let rnd = [0u8; 32];
        sign(&sk, preimage, RELEASE_DOMAIN, &rnd)
            .expect("ml-dsa signs the release preimage")
            .to_vec()
    }

    #[test]
    fn a_zero_threshold_is_refused() {
        let (id, _seed, pk) = operator(1);
        assert_eq!(
            OperatorQuorum::from_config(vec![(id, pk)], 0).err(),
            Some(ExitError::ZeroThreshold)
        );
    }

    #[test]
    fn an_empty_roster_is_refused() {
        assert_eq!(
            OperatorQuorum::from_config(Vec::new(), 1).err(),
            Some(ExitError::UnsetCustody)
        );
    }

    #[test]
    fn a_threshold_above_the_roster_is_refused() {
        let (id, _seed, pk) = operator(1);
        assert_eq!(
            OperatorQuorum::from_config(vec![(id, pk)], 2).err(),
            Some(ExitError::ThresholdAboveRoster)
        );
    }

    #[test]
    fn a_two_of_three_quorum_verifies_over_the_bound_preimage() {
        let vault = [0x99; 32];
        let a = operator(1);
        let b = operator(2);
        let c = operator(3);
        let quorum = OperatorQuorum::from_config(
            vec![(a.0, a.2.clone()), (b.0, b.2.clone()), (c.0, c.2.clone())],
            2,
        )
        .unwrap();
        let preimage = terms().preimage(&vault, 9000);
        let sigs = vec![
            OperatorSig {
                operator_id: a.0,
                signature: sign_terms(&a.1, &preimage),
            },
            OperatorSig {
                operator_id: b.0,
                signature: sign_terms(&b.1, &preimage),
            },
        ];
        assert_eq!(quorum.verify(&preimage, &sigs), Ok(()));
    }

    #[test]
    fn one_signature_under_a_two_of_three_quorum_is_refused() {
        let vault = [0x99; 32];
        let a = operator(1);
        let b = operator(2);
        let c = operator(3);
        let quorum =
            OperatorQuorum::from_config(vec![(a.0, a.2), (b.0, b.2), (c.0, c.2)], 2).unwrap();
        let preimage = terms().preimage(&vault, 9000);
        let sigs = vec![OperatorSig {
            operator_id: a.0,
            signature: sign_terms(&a.1, &preimage),
        }];
        assert_eq!(
            quorum.verify(&preimage, &sigs),
            Err(ExitError::BelowThreshold { have: 1, need: 2 })
        );
    }

    #[test]
    fn a_signature_over_a_different_preimage_does_not_count() {
        let vault = [0x99; 32];
        let a = operator(1);
        let b = operator(2);
        let quorum = OperatorQuorum::from_config(vec![(a.0, a.2), (b.0, b.2)], 2).unwrap();
        let preimage = terms().preimage(&vault, 9000);
        let mut other = terms();
        other.amount = 501;
        let other_preimage = other.preimage(&vault, 9000);
        let sigs = vec![
            OperatorSig {
                operator_id: a.0,
                signature: sign_terms(&a.1, &preimage),
            },
            OperatorSig {
                operator_id: b.0,
                signature: sign_terms(&b.1, &other_preimage),
            },
        ];
        assert_eq!(quorum.verify(&preimage, &sigs), Err(ExitError::BadSignature(2)));
    }

    #[test]
    fn an_unknown_operator_signature_is_refused() {
        let vault = [0x99; 32];
        let a = operator(1);
        let stranger = operator(7);
        let quorum = OperatorQuorum::from_config(vec![(a.0, a.2)], 1).unwrap();
        let preimage = terms().preimage(&vault, 9000);
        let sigs = vec![OperatorSig {
            operator_id: stranger.0,
            signature: sign_terms(&stranger.1, &preimage),
        }];
        assert_eq!(quorum.verify(&preimage, &sigs), Err(ExitError::UnknownOperator(7)));
    }

    #[test]
    fn a_duplicated_operator_counts_once() {
        let vault = [0x99; 32];
        let a = operator(1);
        let b = operator(2);
        let quorum = OperatorQuorum::from_config(vec![(a.0, a.2), (b.0, b.2)], 2).unwrap();
        let preimage = terms().preimage(&vault, 9000);
        let sig = sign_terms(&a.1, &preimage);
        let sigs = vec![
            OperatorSig {
                operator_id: a.0,
                signature: sig.clone(),
            },
            OperatorSig {
                operator_id: a.0,
                signature: sig,
            },
        ];
        assert_eq!(
            quorum.verify(&preimage, &sigs),
            Err(ExitError::BelowThreshold { have: 1, need: 2 })
        );
    }

    #[test]
    fn the_authorization_round_trips_through_its_codec() {
        let auth = ReleaseAuthorization {
            terms: terms(),
            signatures: vec![OperatorSig {
                operator_id: 3,
                signature: vec![0xab; SIGNATURE_BYTES],
            }],
        };
        let bytes = auth.encode();
        assert_eq!(ReleaseAuthorization::decode(&bytes).unwrap(), auth);
    }
}
