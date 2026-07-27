// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::desk::Release;
use crate::errors::ExitError;
use crate::release::ReleaseAuthorization;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutReceipt {
    pub burn_ref: [u8; 32],
    pub dest_chain: u32,
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub foreign_ref: [u8; 32],
}

pub trait PayoutExecutor {
    fn execute(
        &self,
        release: &Release,
        authorization: &ReleaseAuthorization,
    ) -> Result<PayoutReceipt, ExitError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayoutCustody {
    pub endpoint_set: bool,
    pub signing_key_set: bool,
    pub vault_set: bool,
}

impl PayoutCustody {
    pub fn unset() -> PayoutCustody {
        PayoutCustody {
            endpoint_set: false,
            signing_key_set: false,
            vault_set: false,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.endpoint_set && self.signing_key_set && self.vault_set
    }
}

impl Default for PayoutCustody {
    fn default() -> PayoutCustody {
        PayoutCustody::unset()
    }
}

#[derive(Default)]
pub struct FailClosedPayout {
    custody: PayoutCustody,
}

impl FailClosedPayout {
    pub fn new() -> FailClosedPayout {
        FailClosedPayout {
            custody: PayoutCustody::unset(),
        }
    }

    pub fn custody(&self) -> PayoutCustody {
        self.custody
    }
}

impl PayoutExecutor for FailClosedPayout {
    fn execute(
        &self,
        _release: &Release,
        _authorization: &ReleaseAuthorization,
    ) -> Result<PayoutReceipt, ExitError> {
        if !self.custody.is_configured() {
            return Err(ExitError::PayoutUnconfigured);
        }
        Err(ExitError::PayoutUnconfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> Release {
        Release {
            vault: [0x99; 32],
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
            finalized_height: 4_200_000,
        }
    }

    fn authorization() -> ReleaseAuthorization {
        ReleaseAuthorization {
            terms: crate::release::ReleaseTerms {
                asset_id: [0xa1; 16],
                amount: 500,
                beneficiary: [0x55; 32],
                burn_ref: [0x11; 32],
            },
            signatures: Vec::new(),
        }
    }

    #[test]
    fn the_default_executor_holds_no_custody() {
        assert!(!FailClosedPayout::new().custody().is_configured());
    }

    #[test]
    fn the_fail_closed_executor_refuses_when_custody_is_unset() {
        let executor = FailClosedPayout::new();
        assert_eq!(
            executor.execute(&release(), &authorization()),
            Err(ExitError::PayoutUnconfigured)
        );
    }
}
