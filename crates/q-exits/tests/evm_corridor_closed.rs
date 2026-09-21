// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    EvmPayoutWatcher, EvmReleaseProof, ExitStatement, PayoutProofError, PayoutWatcher,
    EXIT_STATEMENT_VERSION,
};

const CORRIDOR: u32 = 7;

fn statement() -> ExitStatement {
    ExitStatement {
        version: EXIT_STATEMENT_VERSION,
        corridor: CORRIDOR,
        asset_id: [0xa1; 16],
        amount: 1_000,
        holder: [0x33; 32],
        destination: [0x55; 32],
        burn_ref: [0x11; 32],
        finalized_height: 4_200_000,
    }
}

fn release() -> EvmReleaseProof {
    EvmReleaseProof {
        receipts_root: [0x22; 32],
        receipt_index: 0,
        receipt_proof: vec![vec![0u8; 32]],
        block_number: 1,
        release_contract: [0x44; 20],
    }
}

#[test]
fn an_evm_release_proof_never_verifies_while_the_corridor_is_closed() {
    assert_eq!(
        release().verify(),
        Err(PayoutProofError::EvmCorridorDisabled)
    );
}

#[test]
fn the_evm_watcher_can_attest_nothing_however_many_releases_it_holds() {
    let watcher = EvmPayoutWatcher::new(CORRIDOR, vec![release(), release(), release()]);
    assert_eq!(
        watcher.attest(&statement()),
        Err(PayoutProofError::EvmCorridorDisabled),
        "a closed corridor must not produce a payout attestation, or an exit could settle against \
         an EVM release that was never proved"
    );
    assert!(
        watcher.confirm(&statement()).is_none(),
        "the watcher trait seam must be closed too, it is the one the exit desk calls"
    );
}

#[test]
fn an_empty_evm_watcher_attests_nothing_either() {
    let watcher = EvmPayoutWatcher::new(CORRIDOR, Vec::new());
    assert!(watcher.attest(&statement()).is_err());
    assert!(watcher.confirm(&statement()).is_none());
}
