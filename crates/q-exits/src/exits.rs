// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::anchor::QuantovaAnchor;
use crate::burn_proof::ProofOfBurn;
use crate::errors::ExitError;
use crate::ledger::{MemoryLedger, ReplayLedger};
use crate::payout::PayoutAttestation;
use crate::vault::VaultBook;

pub const BPS_DEN: u128 = 10_000;
pub const EXIT_STATEMENT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatement {
    pub version: u8,
    pub corridor: u32,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
    pub finalized_height: u64,
}

impl ExitStatement {
    pub fn validate(&self) -> Result<(), ExitError> {
        if self.version != EXIT_STATEMENT_VERSION {
            return Err(ExitError::BadVersion(self.version));
        }
        if self.corridor == 0 {
            return Err(ExitError::ZeroCorridor);
        }
        if self.amount == 0 {
            return Err(ExitError::ZeroAmount);
        }
        if self.asset_id == [0u8; 16] {
            return Err(ExitError::ZeroAsset);
        }
        if self.beneficiary == [0u8; 32] {
            return Err(ExitError::ZeroBeneficiary);
        }
        if self.burn_ref == [0u8; 32] {
            return Err(ExitError::ZeroBurnRef);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeskConfig {
    pub corridor: u32,
    pub secure_bps: u32,
    pub premium_bps: u32,
    pub window: u64,
}

pub const SECURE_RATIO_BPS: u32 = 15_000;
pub const SLASH_PREMIUM_BPS: u32 = 11_000;
pub const REDEEM_WINDOW_MS: u64 = 86_400_000;

impl DeskConfig {
    pub fn aligned(corridor: u32) -> DeskConfig {
        DeskConfig {
            corridor,
            secure_bps: SECURE_RATIO_BPS,
            premium_bps: SLASH_PREMIUM_BPS,
            window: REDEEM_WINDOW_MS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitState {
    Pending,
    Settled,
    Slashed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub statement: ExitStatement,
    pub vault_id: u32,
    pub locked: u128,
    pub issued_at: u64,
    pub deadline: u64,
    pub state: ExitState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    pub vault_id: u32,
    pub released: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashOutcome {
    pub vault_id: u32,
    pub beneficiary: [u8; 32],
    pub user_payout: u128,
    pub remainder: u128,
}

pub struct ExitDesk {
    cfg: DeskConfig,
    anchor: QuantovaAnchor,
    vaults: VaultBook,
    exits: Vec<Exit>,
    consumed: Box<dyn ReplayLedger>,
}

impl ExitDesk {
    pub fn new(cfg: DeskConfig, anchor: QuantovaAnchor) -> Result<ExitDesk, ExitError> {
        ExitDesk::with_ledger(cfg, anchor, Box::new(MemoryLedger::new()))
    }

    pub fn with_ledger(
        cfg: DeskConfig,
        anchor: QuantovaAnchor,
        consumed: Box<dyn ReplayLedger>,
    ) -> Result<ExitDesk, ExitError> {
        if cfg.corridor == 0
            || cfg.secure_bps <= BPS_DEN as u32
            || cfg.premium_bps < BPS_DEN as u32
            || cfg.premium_bps > cfg.secure_bps
        {
            return Err(ExitError::UnsafeParams);
        }
        Ok(ExitDesk {
            cfg,
            anchor,
            vaults: VaultBook::new(),
            exits: Vec::new(),
            consumed,
        })
    }

    pub fn corridor(&self) -> u32 {
        self.cfg.corridor
    }

    pub fn register_vault(&mut self, vault_id: u32, collateral: u128) {
        self.vaults.register(vault_id, collateral);
    }

    pub fn free_collateral(&self, vault_id: u32) -> u128 {
        self.vaults.free_of(vault_id)
    }

    pub fn locked_collateral(&self, vault_id: u32) -> u128 {
        self.vaults.locked_of(vault_id)
    }

    pub fn required_collateral(&self, amount: u128) -> Result<u128, ExitError> {
        amount
            .checked_mul(self.cfg.secure_bps as u128)
            .map(|scaled| scaled / BPS_DEN)
            .ok_or(ExitError::Overflow)
    }

    pub fn user_premium(&self, amount: u128) -> Result<u128, ExitError> {
        amount
            .checked_mul(self.cfg.premium_bps as u128)
            .map(|scaled| scaled / BPS_DEN)
            .ok_or(ExitError::Overflow)
    }

    pub fn is_consumed(&self, burn_ref: &[u8; 32]) -> bool {
        self.consumed.is_released(burn_ref)
    }

    pub fn exit(&self, id: ExitId) -> Option<&Exit> {
        self.exits.get(id.0)
    }

    pub fn open_exit(
        &mut self,
        proof: &ProofOfBurn,
        vault_id: u32,
        now: u64,
    ) -> Result<ExitId, ExitError> {
        let burn = proof.verify(&self.anchor)?;
        let statement = ExitStatement {
            version: EXIT_STATEMENT_VERSION,
            corridor: self.cfg.corridor,
            asset_id: burn.asset_id,
            amount: burn.amount,
            beneficiary: burn.beneficiary,
            burn_ref: burn.burn_ref,
            finalized_height: burn.finalized_height,
        };
        statement.validate()?;
        if self.consumed.is_released(&statement.burn_ref) {
            return Err(ExitError::ReplayedExit);
        }
        let required = self.required_collateral(statement.amount)?;
        self.vaults.lock(vault_id, required)?;
        if let Err(e) = self.consumed.record(statement.burn_ref) {
            self.vaults.release(vault_id, required)?;
            return Err(e);
        }
        let exit = Exit {
            statement,
            vault_id,
            locked: required,
            issued_at: now,
            deadline: now.saturating_add(self.cfg.window),
            state: ExitState::Pending,
        };
        self.exits.push(exit);
        Ok(ExitId(self.exits.len() - 1))
    }

    pub fn settle(
        &mut self,
        id: ExitId,
        attestation: &PayoutAttestation,
        now: u64,
    ) -> Result<Release, ExitError> {
        let exit = self.exits.get_mut(id.0).ok_or(ExitError::UnknownExit)?;
        if exit.state != ExitState::Pending {
            return Err(ExitError::NotPending);
        }
        if now > exit.deadline {
            return Err(ExitError::WindowExpired {
                now,
                deadline: exit.deadline,
            });
        }
        attestation.validate()?;
        if !attestation.covers(&exit.statement) {
            return Err(ExitError::PayoutMismatch);
        }
        let vault_id = exit.vault_id;
        let released = exit.locked;
        exit.state = ExitState::Settled;
        self.vaults.release(vault_id, released)?;
        Ok(Release { vault_id, released })
    }

    pub fn slash(&mut self, id: ExitId, now: u64) -> Result<SlashOutcome, ExitError> {
        let exit = self.exits.get(id.0).ok_or(ExitError::UnknownExit)?;
        if exit.state != ExitState::Pending {
            return Err(ExitError::NotPending);
        }
        if now <= exit.deadline {
            return Err(ExitError::WindowOpen {
                now,
                deadline: exit.deadline,
            });
        }
        let vault_id = exit.vault_id;
        let beneficiary = exit.statement.beneficiary;
        let locked = exit.locked;
        let amount = exit.statement.amount;
        let user_payout = self.user_premium(amount)?;
        let remainder = locked.checked_sub(user_payout).ok_or(ExitError::Overflow)?;
        self.exits[id.0].state = ExitState::Slashed;
        self.vaults.seize(vault_id, locked)?;
        Ok(SlashOutcome {
            vault_id,
            beneficiary,
            user_payout,
            remainder,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DeskConfig {
        DeskConfig {
            corridor: 1,
            secure_bps: 15_000,
            premium_bps: 11_000,
            window: 100,
        }
    }

    #[test]
    fn the_aligned_config_matches_the_old_bridge() {
        let c = DeskConfig::aligned(1);
        assert_eq!(c.secure_bps, 15_000);
        assert_eq!(c.premium_bps, 11_000);
        assert_eq!(c.window, 86_400_000);
        assert!(c.premium_bps > BPS_DEN as u32 && c.premium_bps <= c.secure_bps);
    }

    fn statement() -> ExitStatement {
        ExitStatement {
            version: EXIT_STATEMENT_VERSION,
            corridor: 1,
            asset_id: [0xa1; 16],
            amount: 1_000,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
            finalized_height: 4_200_000,
        }
    }

    fn anchor() -> QuantovaAnchor {
        QuantovaAnchor::from_config(
            9000,
            1,
            0,
            100,
            [0x5a; 32],
            vec![crate::anchor::MemberConfig {
                id: 1,
                weight: 100,
                root_digest: [0x11; 32],
                root_slots: 64,
                attest_pk: vec![0u8; crate::anchor::ATTEST_PK_BYTES],
            }],
        )
        .unwrap()
    }

    fn desk() -> ExitDesk {
        ExitDesk::new(cfg(), anchor()).unwrap()
    }

    #[test]
    fn an_undercollateralized_config_is_refused() {
        let mut c = cfg();
        c.secure_bps = 10_000;
        assert_eq!(ExitDesk::new(c, anchor()).err(), Some(ExitError::UnsafeParams));
    }

    #[test]
    fn a_premium_above_the_secure_ratio_is_refused() {
        let mut c = cfg();
        c.premium_bps = 16_000;
        assert_eq!(ExitDesk::new(c, anchor()).err(), Some(ExitError::UnsafeParams));
    }

    #[test]
    fn a_premium_below_par_is_refused() {
        let mut c = cfg();
        c.premium_bps = 9_000;
        assert_eq!(ExitDesk::new(c, anchor()).err(), Some(ExitError::UnsafeParams));
    }

    #[test]
    fn a_zero_corridor_config_is_refused() {
        let mut c = cfg();
        c.corridor = 0;
        assert_eq!(ExitDesk::new(c, anchor()).err(), Some(ExitError::UnsafeParams));
    }

    #[test]
    fn required_collateral_sits_above_the_value() {
        let d = desk();
        assert_eq!(d.required_collateral(1_000).unwrap(), 1_500);
    }

    #[test]
    fn the_user_premium_sits_above_the_value() {
        let d = desk();
        assert_eq!(d.user_premium(1_000).unwrap(), 1_100);
    }

    #[test]
    fn a_statement_with_a_zero_amount_is_refused() {
        let mut s = statement();
        s.amount = 0;
        assert_eq!(s.validate(), Err(ExitError::ZeroAmount));
    }

    #[test]
    fn a_statement_with_a_zero_burn_ref_is_refused() {
        let mut s = statement();
        s.burn_ref = [0u8; 32];
        assert_eq!(s.validate(), Err(ExitError::ZeroBurnRef));
    }
}
