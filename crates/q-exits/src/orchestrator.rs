// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::burn_proof::ProofOfBurn;
use crate::desk::ReleaseDesk;
use crate::errors::ExitError;
use crate::payout::{PayoutExecutor, PayoutReceipt};
use crate::release::ReleaseAuthorization;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitConfig {
    pub enabled: bool,
}

impl Default for ExitConfig {
    fn default() -> ExitConfig {
        ExitConfig { enabled: false }
    }
}

impl ExitConfig {
    pub fn disabled() -> ExitConfig {
        ExitConfig { enabled: false }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

pub struct ReleasePipeline<E: PayoutExecutor> {
    desk: ReleaseDesk,
    executor: E,
    enabled: bool,
}

impl<E: PayoutExecutor> ReleasePipeline<E> {
    pub fn new(desk: ReleaseDesk, executor: E, config: ExitConfig) -> ReleasePipeline<E> {
        ReleasePipeline {
            desk,
            executor,
            enabled: config.enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_released(&self, burn_ref: &[u8; 32]) -> bool {
        self.desk.is_released(burn_ref)
    }

    pub fn settle(
        &mut self,
        proof: &ProofOfBurn,
        authorization: &ReleaseAuthorization,
    ) -> Result<PayoutReceipt, ExitError> {
        if !self.enabled {
            return Err(ExitError::PayoutUnconfigured);
        }
        let release = self.desk.authorize_release(proof, authorization)?;
        self.executor.execute(&release, authorization)
    }
}
