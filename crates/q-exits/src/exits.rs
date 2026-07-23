use std::collections::BTreeSet;

use crate::certificate::{ExitCertificate, ExitStatement, ExitVerifier};
use crate::errors::ExitError;
use crate::payout::PayoutAttestation;
use crate::vault::VaultBook;

pub const BPS_DEN: u128 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeskConfig {
    pub home_chain: u32,
    pub secure_bps: u32,
    pub premium_bps: u32,
    pub window: u64,
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

pub struct ExitDesk<V: ExitVerifier> {
    cfg: DeskConfig,
    verifier: V,
    vaults: VaultBook,
    exits: Vec<Exit>,
    consumed: BTreeSet<[u8; 32]>,
}

impl<V: ExitVerifier> ExitDesk<V> {
    pub fn new(cfg: DeskConfig, verifier: V) -> Result<ExitDesk<V>, ExitError> {
        if cfg.secure_bps <= BPS_DEN as u32
            || cfg.premium_bps < BPS_DEN as u32
            || cfg.premium_bps > cfg.secure_bps
        {
            return Err(ExitError::UnsafeParams);
        }
        Ok(ExitDesk {
            cfg,
            verifier,
            vaults: VaultBook::new(),
            exits: Vec::new(),
            consumed: BTreeSet::new(),
        })
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
        self.consumed.contains(burn_ref)
    }

    pub fn exit(&self, id: ExitId) -> Option<&Exit> {
        self.exits.get(id.0)
    }

    pub fn open_exit(
        &mut self,
        cert: &ExitCertificate,
        vault_id: u32,
        now: u64,
    ) -> Result<ExitId, ExitError> {
        cert.verify(&self.verifier)?;
        let statement = &cert.statement;
        if statement.home_chain != self.cfg.home_chain {
            return Err(ExitError::WrongHome {
                got: statement.home_chain,
                expected: self.cfg.home_chain,
            });
        }
        if self.consumed.contains(&statement.burn_ref) {
            return Err(ExitError::ReplayedExit);
        }
        let required = self.required_collateral(statement.amount)?;
        self.vaults.lock(vault_id, required)?;
        self.consumed.insert(statement.burn_ref);
        let exit = Exit {
            statement: statement.clone(),
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
    use crate::certificate::{ExitProver, ExitStatement, HashStark, EXIT_STATEMENT_VERSION};
    use crate::payout::{PayoutAttestation, PAYOUT_VERSION};

    fn cfg() -> DeskConfig {
        DeskConfig {
            home_chain: 9000,
            secure_bps: 15_000,
            premium_bps: 11_000,
            window: 100,
        }
    }

    fn statement(burn: u8) -> ExitStatement {
        ExitStatement {
            version: EXIT_STATEMENT_VERSION,
            home_chain: 9000,
            corridor: 1,
            asset_id: [0xa1; 16],
            amount: 1_000,
            beneficiary: [0x55; 32],
            burn_ref: [burn; 32],
            finalized_height: 4_200_000,
        }
    }

    fn cert(burn: u8) -> ExitCertificate {
        let s = statement(burn);
        let proof = HashStark.prove(&s);
        ExitCertificate {
            statement: s,
            proof,
        }
    }

    fn attestation(burn: u8) -> PayoutAttestation {
        PayoutAttestation {
            version: PAYOUT_VERSION,
            corridor: 1,
            asset_id: [0xa1; 16],
            amount: 1_000,
            beneficiary: [0x55; 32],
            burn_ref: [burn; 32],
            foreign_ref: [0x77; 32],
            proof_height: 880_100,
        }
    }

    fn desk() -> ExitDesk<HashStark> {
        ExitDesk::new(cfg(), HashStark).unwrap()
    }

    #[test]
    fn an_undercollateralized_config_is_refused() {
        let mut c = cfg();
        c.secure_bps = 10_000;
        assert_eq!(ExitDesk::new(c, HashStark).err(), Some(ExitError::UnsafeParams));
    }

    #[test]
    fn a_premium_above_the_secure_ratio_is_refused() {
        let mut c = cfg();
        c.premium_bps = 16_000;
        assert_eq!(ExitDesk::new(c, HashStark).err(), Some(ExitError::UnsafeParams));
    }

    #[test]
    fn required_collateral_sits_above_the_value() {
        let d = desk();
        assert_eq!(d.required_collateral(1_000).unwrap(), 1_500);
    }

    #[test]
    fn opening_an_exit_locks_the_required_collateral() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        assert_eq!(d.locked_collateral(1), 1_500);
        assert_eq!(d.free_collateral(1), 500);
        assert_eq!(d.exit(id).unwrap().state, ExitState::Pending);
    }

    #[test]
    fn a_thin_vault_is_rejected_at_issuance() {
        let mut d = desk();
        d.register_vault(1, 1_499);
        assert_eq!(
            d.open_exit(&cert(0x11), 1, 10),
            Err(ExitError::ThinVault {
                have: 1_499,
                need: 1_500
            })
        );
        assert!(!d.is_consumed(&[0x11; 32]));
    }

    #[test]
    fn a_replayed_certificate_is_refused() {
        let mut d = desk();
        d.register_vault(1, 5_000);
        d.open_exit(&cert(0x11), 1, 10).unwrap();
        assert_eq!(d.open_exit(&cert(0x11), 1, 10), Err(ExitError::ReplayedExit));
        assert_eq!(d.locked_collateral(1), 1_500);
    }

    #[test]
    fn a_foreign_home_chain_is_refused() {
        let mut d = desk();
        d.register_vault(1, 5_000);
        let mut s = statement(0x11);
        s.home_chain = 5;
        let c = ExitCertificate {
            proof: HashStark.prove(&s),
            statement: s,
        };
        assert_eq!(
            d.open_exit(&c, 1, 10),
            Err(ExitError::WrongHome {
                got: 5,
                expected: 9000
            })
        );
    }

    #[test]
    fn settling_within_the_window_releases_the_collateral() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        let release = d.settle(id, &attestation(0x11), 50).unwrap();
        assert_eq!(release.released, 1_500);
        assert_eq!(d.locked_collateral(1), 0);
        assert_eq!(d.free_collateral(1), 2_000);
        assert_eq!(d.exit(id).unwrap().state, ExitState::Settled);
    }

    #[test]
    fn settling_after_the_window_is_refused() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        assert_eq!(
            d.settle(id, &attestation(0x11), 200),
            Err(ExitError::WindowExpired {
                now: 200,
                deadline: 110
            })
        );
    }

    #[test]
    fn a_mismatched_payout_does_not_settle() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        let mut a = attestation(0x11);
        a.beneficiary = [0x66; 32];
        assert_eq!(d.settle(id, &a, 50), Err(ExitError::PayoutMismatch));
        assert_eq!(d.locked_collateral(1), 1_500);
    }

    #[test]
    fn slashing_before_the_deadline_is_refused() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        assert_eq!(
            d.slash(id, 100),
            Err(ExitError::WindowOpen {
                now: 100,
                deadline: 110
            })
        );
    }

    #[test]
    fn slashing_after_the_deadline_pays_the_user_a_premium() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        let outcome = d.slash(id, 200).unwrap();
        assert_eq!(outcome.user_payout, 1_100);
        assert!(outcome.user_payout > 1_000);
        assert_eq!(outcome.remainder, 400);
        assert_eq!(outcome.beneficiary, [0x55; 32]);
        assert_eq!(d.locked_collateral(1), 0);
        assert_eq!(d.free_collateral(1), 500);
        assert_eq!(d.exit(id).unwrap().state, ExitState::Slashed);
    }

    #[test]
    fn a_settled_exit_cannot_be_slashed() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        d.settle(id, &attestation(0x11), 50).unwrap();
        assert_eq!(d.slash(id, 200), Err(ExitError::NotPending));
    }

    #[test]
    fn a_slashed_exit_cannot_be_settled() {
        let mut d = desk();
        d.register_vault(1, 2_000);
        let id = d.open_exit(&cert(0x11), 1, 10).unwrap();
        d.slash(id, 200).unwrap();
        assert_eq!(d.settle(id, &attestation(0x11), 250), Err(ExitError::NotPending));
    }
}
