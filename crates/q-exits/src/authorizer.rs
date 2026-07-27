// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::sync::atomic::{compiler_fence, Ordering};
use std::collections::BTreeMap;

use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey, Signature, SEED_BYTES};

use crate::anchor::QuantovaAnchor;
use crate::burn_proof::ProofOfBurn;
use crate::errors::ExitError;
use crate::ledger::ReplayLedger;
use crate::release::{OperatorSig, ReleaseAuthorization, ReleaseTerms, RELEASE_DOMAIN};

fn secure_wipe(bytes: &mut [u8]) {
    for slot in bytes.iter_mut() {
        *slot = 0;
    }
    compiler_fence(Ordering::SeqCst);
    let _ = core::hint::black_box(&*bytes);
}

struct ZeroizingSecretKey {
    bytes: SecretKey,
}

impl ZeroizingSecretKey {
    fn new(bytes: SecretKey) -> ZeroizingSecretKey {
        ZeroizingSecretKey { bytes }
    }

    fn expose(&self) -> &SecretKey {
        &self.bytes
    }
}

impl Drop for ZeroizingSecretKey {
    fn drop(&mut self) {
        secure_wipe(&mut self.bytes);
    }
}

pub trait ReleaseSigner {
    fn operator_id(&self) -> u32;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, preimage: &[u8]) -> Signature;
}

pub struct SoftReleaseSigner {
    operator_id: u32,
    public_key: PublicKey,
    secret_key: ZeroizingSecretKey,
}

impl SoftReleaseSigner {
    pub fn from_seed(operator_id: u32, seed: &[u8; SEED_BYTES]) -> SoftReleaseSigner {
        let (public_key, secret_key) = ml_dsa::keygen(seed);
        SoftReleaseSigner {
            operator_id,
            public_key,
            secret_key: ZeroizingSecretKey::new(secret_key),
        }
    }
}

impl ReleaseSigner for SoftReleaseSigner {
    fn operator_id(&self) -> u32 {
        self.operator_id
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, preimage: &[u8]) -> Signature {
        let rnd = [0u8; 32];
        ml_dsa::sign(self.secret_key.expose(), preimage, RELEASE_DOMAIN, &rnd)
            .expect("ml-dsa signs the release preimage")
    }
}

pub struct OperatorAuthorizer<S: ReleaseSigner> {
    anchor: QuantovaAnchor,
    signer: S,
    vault: [u8; 32],
    dest_chain: u32,
}

impl<S: ReleaseSigner> OperatorAuthorizer<S> {
    pub fn new(
        anchor: QuantovaAnchor,
        signer: S,
        vault: [u8; 32],
        dest_chain: u32,
    ) -> Result<OperatorAuthorizer<S>, ExitError> {
        if vault == [0u8; 32] || dest_chain == 0 {
            return Err(ExitError::UnsetCustody);
        }
        Ok(OperatorAuthorizer {
            anchor,
            signer,
            vault,
            dest_chain,
        })
    }

    pub fn operator_id(&self) -> u32 {
        self.signer.operator_id()
    }

    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    pub fn authorize(
        &self,
        proof: &ProofOfBurn,
        ledger: &dyn ReplayLedger,
    ) -> Result<(ReleaseTerms, OperatorSig), ExitError> {
        let burn = proof.verify(&self.anchor)?;
        if ledger.is_released(&burn.burn_ref) {
            return Err(ExitError::ReplayedBurn);
        }
        let terms = ReleaseTerms::from_burn(&burn);
        let preimage = terms.preimage(&self.vault, self.dest_chain);
        let signature = self.signer.sign(&preimage).to_vec();
        Ok((
            terms,
            OperatorSig {
                operator_id: self.signer.operator_id(),
                signature,
            },
        ))
    }
}

pub struct ReleaseAggregator {
    threshold: usize,
    terms: Option<ReleaseTerms>,
    signatures: BTreeMap<u32, OperatorSig>,
}

impl ReleaseAggregator {
    pub fn new(threshold: usize) -> ReleaseAggregator {
        ReleaseAggregator {
            threshold,
            terms: None,
            signatures: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, terms: &ReleaseTerms, sig: OperatorSig) -> Result<(), ExitError> {
        match &self.terms {
            None => self.terms = Some(terms.clone()),
            Some(existing) => {
                if existing != terms {
                    return Err(ExitError::TermsMismatch);
                }
            }
        }
        self.signatures.insert(sig.operator_id, sig);
        Ok(())
    }

    pub fn distinct(&self) -> usize {
        self.signatures.len()
    }

    pub fn ready(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    pub fn try_finalize(&self) -> Option<ReleaseAuthorization> {
        if !self.ready() {
            return None;
        }
        let terms = self.terms.clone()?;
        Some(ReleaseAuthorization {
            terms,
            signatures: self.signatures.values().cloned().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> ReleaseTerms {
        ReleaseTerms {
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
        }
    }

    fn sig(id: u32) -> OperatorSig {
        OperatorSig {
            operator_id: id,
            signature: vec![0xab; 8],
        }
    }

    #[test]
    fn the_soft_signer_signs_a_verifiable_release_preimage() {
        let signer = SoftReleaseSigner::from_seed(3, &[0x22u8; SEED_BYTES]);
        let pk = signer.public_key();
        let preimage = terms().preimage(&[0x99; 32], 42);
        let signature = signer.sign(&preimage);
        assert_eq!(signer.operator_id(), 3);
        assert!(ml_dsa::verify(&pk, &preimage, &signature, RELEASE_DOMAIN));
    }

    #[test]
    fn an_unset_vault_is_refused() {
        let anchor =
            QuantovaAnchor::from_config(9000, 1, 0, 100, [0x5a; 32], vec![member()]).unwrap();
        let signer = SoftReleaseSigner::from_seed(1, &[0x01u8; SEED_BYTES]);
        assert_eq!(
            OperatorAuthorizer::new(anchor, signer, [0u8; 32], 42).err(),
            Some(ExitError::UnsetCustody)
        );
    }

    fn member() -> crate::anchor::MemberConfig {
        crate::anchor::MemberConfig {
            id: 1,
            weight: 100,
            root_digest: [0x11; 32],
            root_slots: 64,
            attest_pk: vec![0u8; crate::anchor::ATTEST_PK_BYTES],
        }
    }

    #[test]
    fn the_aggregator_authorizes_at_threshold_and_refuses_below_it() {
        let mut agg = ReleaseAggregator::new(2);
        assert!(!agg.ready());
        agg.add(&terms(), sig(1)).unwrap();
        assert!(!agg.ready());
        assert!(agg.try_finalize().is_none());
        agg.add(&terms(), sig(2)).unwrap();
        assert!(agg.ready());
        let auth = agg.try_finalize().expect("threshold reached");
        assert_eq!(auth.terms, terms());
        assert_eq!(auth.signatures.len(), 2);
    }

    #[test]
    fn a_duplicate_operator_counts_once_in_the_aggregator() {
        let mut agg = ReleaseAggregator::new(2);
        agg.add(&terms(), sig(1)).unwrap();
        agg.add(&terms(), sig(1)).unwrap();
        assert_eq!(agg.distinct(), 1);
        assert!(!agg.ready());
    }

    #[test]
    fn a_divergent_terms_signature_is_refused_by_the_aggregator() {
        let mut agg = ReleaseAggregator::new(2);
        agg.add(&terms(), sig(1)).unwrap();
        let mut other = terms();
        other.amount = 501;
        assert_eq!(agg.add(&other, sig(2)), Err(ExitError::TermsMismatch));
    }
}
