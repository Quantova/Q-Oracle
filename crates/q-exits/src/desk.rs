// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use crate::anchor::QuantovaAnchor;
use crate::burn_proof::ProofOfBurn;
use crate::errors::ExitError;
use crate::release::{OperatorQuorum, ReleaseAuthorization, ReleaseTerms};

pub struct CustodyConfig {
    vault: [u8; 32],
    dest_chain: u32,
    quorum: OperatorQuorum,
}

impl CustodyConfig {
    pub fn new(
        vault: [u8; 32],
        dest_chain: u32,
        quorum: OperatorQuorum,
    ) -> Result<CustodyConfig, ExitError> {
        if vault == [0u8; 32] || dest_chain == 0 {
            return Err(ExitError::UnsetCustody);
        }
        Ok(CustodyConfig {
            vault,
            dest_chain,
            quorum,
        })
    }

    pub fn vault(&self) -> &[u8; 32] {
        &self.vault
    }

    pub fn dest_chain(&self) -> u32 {
        self.dest_chain
    }

    pub fn threshold(&self) -> usize {
        self.quorum.threshold()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub vault: [u8; 32],
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
    pub finalized_height: u64,
}

pub struct ReleaseDesk {
    anchor: QuantovaAnchor,
    custody: CustodyConfig,
    released: BTreeSet<[u8; 32]>,
}

impl ReleaseDesk {
    pub fn new(anchor: QuantovaAnchor, custody: CustodyConfig) -> ReleaseDesk {
        ReleaseDesk {
            anchor,
            custody,
            released: BTreeSet::new(),
        }
    }

    pub fn is_released(&self, burn_ref: &[u8; 32]) -> bool {
        self.released.contains(burn_ref)
    }

    pub fn authorize_release(
        &mut self,
        proof: &ProofOfBurn,
        authorization: &ReleaseAuthorization,
    ) -> Result<Release, ExitError> {
        let burn = proof.verify(&self.anchor)?;

        if burn.amount == 0 {
            return Err(ExitError::ZeroAmount);
        }
        if burn.asset_id == [0u8; 16] {
            return Err(ExitError::ZeroAsset);
        }
        if burn.beneficiary == [0u8; 32] {
            return Err(ExitError::ZeroBeneficiary);
        }
        if burn.burn_ref == [0u8; 32] {
            return Err(ExitError::ZeroBurnRef);
        }

        let terms = ReleaseTerms::from_burn(&burn);
        if authorization.terms != terms {
            return Err(ExitError::BurnMismatch);
        }

        if self.released.contains(&burn.burn_ref) {
            return Err(ExitError::ReplayedBurn);
        }

        let preimage = terms.preimage(self.custody.vault(), self.custody.dest_chain());
        self.custody
            .quorum
            .verify(&preimage, &authorization.signatures)?;

        self.released.insert(burn.burn_ref);
        Ok(Release {
            vault: *self.custody.vault(),
            asset_id: burn.asset_id,
            amount: burn.amount,
            beneficiary: burn.beneficiary,
            burn_ref: burn.burn_ref,
            finalized_height: burn.finalized_height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::OperatorQuorum;
    use qtv_crypto::ml_dsa::keygen;

    #[test]
    fn a_zero_vault_is_refused() {
        let (_pk, _sk) = keygen(&[1u8; 32]);
        let quorum =
            OperatorQuorum::from_config(vec![(1u32, keygen(&[1u8; 32]).0.to_vec())], 1).unwrap();
        assert_eq!(
            CustodyConfig::new([0u8; 32], 9000, quorum).err(),
            Some(ExitError::UnsetCustody)
        );
    }

    #[test]
    fn a_zero_dest_chain_is_refused() {
        let quorum =
            OperatorQuorum::from_config(vec![(1u32, keygen(&[1u8; 32]).0.to_vec())], 1).unwrap();
        assert_eq!(
            CustodyConfig::new([0x99u8; 32], 0, quorum).err(),
            Some(ExitError::UnsetCustody)
        );
    }
}
