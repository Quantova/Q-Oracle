// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    DeskConfig, ExitCertificate, ExitDesk, ExitError, ExitProver, ExitState, ExitStatement,
    HashStark, PayoutAttestation, PayoutWatcher, EXIT_STATEMENT_VERSION, PAYOUT_VERSION,
};

const HOME: u32 = 9000;
const CORRIDOR: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 1_000;

fn config() -> DeskConfig {
    DeskConfig {
        home_chain: HOME,
        secure_bps: 15_000,
        premium_bps: 11_000,
        window: 100,
    }
}

fn finalized_burn(burn_ref: [u8; 32]) -> ExitStatement {
    ExitStatement {
        version: EXIT_STATEMENT_VERSION,
        home_chain: HOME,
        corridor: CORRIDOR,
        asset_id: ASSET,
        amount: AMOUNT,
        beneficiary: BENEFICIARY,
        burn_ref,
        finalized_height: 4_200_000,
    }
}

fn certificate(burn_ref: [u8; 32]) -> ExitCertificate {
    let statement = finalized_burn(burn_ref);
    let proof = HashStark.prove(&statement);
    ExitCertificate { statement, proof }
}

struct HonestWatcher {
    foreign_ref: [u8; 32],
    proof_height: u64,
}

impl PayoutWatcher for HonestWatcher {
    fn corridor(&self) -> u32 {
        CORRIDOR
    }

    fn confirm(&self, statement: &ExitStatement) -> Option<PayoutAttestation> {
        Some(PayoutAttestation {
            version: PAYOUT_VERSION,
            corridor: statement.corridor,
            asset_id: statement.asset_id,
            amount: statement.amount,
            beneficiary: statement.beneficiary,
            burn_ref: statement.burn_ref,
            foreign_ref: self.foreign_ref,
            proof_height: self.proof_height,
        })
    }
}

#[test]
fn a_burn_produces_a_certificate_bound_to_the_finalized_burn() {
    let statement = finalized_burn([0x11; 32]);
    let cert = ExitCertificate {
        statement: statement.clone(),
        proof: HashStark.prove(&statement),
    };
    assert_eq!(cert.verify(&HashStark), Ok(()));

    let mut moved = cert.clone();
    moved.statement.amount = AMOUNT + 1;
    assert_eq!(moved.verify(&HashStark), Err(ExitError::UnboundProof));

    let mut reburned = cert;
    reburned.statement.burn_ref = [0x22; 32];
    assert_eq!(reburned.verify(&HashStark), Err(ExitError::UnboundProof));
}

#[test]
fn a_vault_that_proves_the_payout_within_the_window_is_released() {
    let mut desk = ExitDesk::new(config(), HashStark).unwrap();
    desk.register_vault(1, 2_000);
    let id = desk.open_exit(&certificate([0x11; 32]), 1, 10).unwrap();
    assert_eq!(desk.locked_collateral(1), 1_500);

    let watcher = HonestWatcher {
        foreign_ref: [0x77; 32],
        proof_height: 880_100,
    };
    let attestation = watcher
        .confirm(&finalized_burn([0x11; 32]))
        .expect("the off-chain watcher confirms the foreign payout");

    let release = desk.settle(id, &attestation, 60).unwrap();
    assert_eq!(release.released, 1_500);
    assert_eq!(desk.locked_collateral(1), 0);
    assert_eq!(desk.free_collateral(1), 2_000);
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Settled);
}

#[test]
fn a_vault_that_fails_to_prove_within_the_window_is_slashed_and_the_user_is_paid_a_premium() {
    let mut desk = ExitDesk::new(config(), HashStark).unwrap();
    desk.register_vault(1, 2_000);
    let id = desk.open_exit(&certificate([0x11; 32]), 1, 10).unwrap();

    assert_eq!(
        desk.slash(id, 100),
        Err(ExitError::WindowOpen {
            now: 100,
            deadline: 110
        })
    );

    let outcome = desk.slash(id, 111).unwrap();
    assert_eq!(outcome.beneficiary, BENEFICIARY);
    assert_eq!(outcome.user_payout, 1_100);
    assert!(outcome.user_payout > AMOUNT);
    assert!(outcome.user_payout <= 1_500);
    assert_eq!(outcome.remainder, 400);
    assert_eq!(desk.locked_collateral(1), 0);
    assert_eq!(desk.free_collateral(1), 500);
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Slashed);
}

#[test]
fn the_collateral_ratio_is_enforced_at_issuance_and_a_thin_vault_is_rejected() {
    let mut desk = ExitDesk::new(config(), HashStark).unwrap();
    desk.register_vault(7, 1_499);
    assert_eq!(
        desk.open_exit(&certificate([0x11; 32]), 7, 10),
        Err(ExitError::ThinVault {
            have: 1_499,
            need: 1_500
        })
    );
    assert!(!desk.is_consumed(&[0x11; 32]));

    desk.register_vault(8, 1_500);
    let id = desk.open_exit(&certificate([0x11; 32]), 8, 10).unwrap();
    assert_eq!(desk.locked_collateral(8), 1_500);
    assert_eq!(desk.free_collateral(8), 0);
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Pending);
}

#[test]
fn a_replayed_exit_certificate_cannot_double_spend() {
    let mut desk = ExitDesk::new(config(), HashStark).unwrap();
    desk.register_vault(1, 10_000);
    let first = desk.open_exit(&certificate([0x11; 32]), 1, 10).unwrap();
    assert_eq!(desk.locked_collateral(1), 1_500);

    assert_eq!(
        desk.open_exit(&certificate([0x11; 32]), 1, 10),
        Err(ExitError::ReplayedExit)
    );

    desk.settle(
        first,
        &HonestWatcher {
            foreign_ref: [0x77; 32],
            proof_height: 880_100,
        }
        .confirm(&finalized_burn([0x11; 32]))
        .unwrap(),
        60,
    )
    .unwrap();

    assert_eq!(
        desk.open_exit(&certificate([0x11; 32]), 1, 70),
        Err(ExitError::ReplayedExit)
    );
    assert_eq!(desk.locked_collateral(1), 0);
    assert_eq!(desk.free_collateral(1), 10_000);

    let fresh = desk.open_exit(&certificate([0x33; 32]), 1, 80).unwrap();
    assert_ne!(fresh, first);
    assert_eq!(desk.locked_collateral(1), 1_500);
}
