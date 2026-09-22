// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_gateway::{Gateway, GatewayError, OperatorSet};

const CHAIN_ID: u32 = 9000;
const DEST_ID: u64 = 0x0000_002a_0000_2328;
const SOURCE: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];

fn gateway() -> Gateway {
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, OperatorSet::new(0), 1_000_000_000);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, 1_000_000_000);
    gw.advance_to(10_000);
    gw
}

fn admit(gw: &mut Gateway, tag: u8, amount: u128) -> Result<(), GatewayError> {
    gw.admit_trustless(ASSET, [tag; 32], amount, SOURCE)
}

#[test]
fn minting_stops_at_the_declared_escrow() {
    let mut gw = gateway();
    gw.set_escrow(ASSET, 1_000);
    assert!(admit(&mut gw, 1, 600).is_ok());
    assert!(admit(&mut gw, 2, 400).is_ok());
    assert!(matches!(
        admit(&mut gw, 3, 1),
        Err(GatewayError::EscrowExceeded {
            minted: 1_000,
            escrowed: 1_000,
            add: 1,
        })
    ));
    assert_eq!(gw.minted_of_asset(&ASSET), 1_000);
}

#[test]
fn a_single_oversized_mint_is_refused_whole() {
    let mut gw = gateway();
    gw.set_escrow(ASSET, 1_000);
    assert!(matches!(
        admit(&mut gw, 1, 1_001),
        Err(GatewayError::EscrowExceeded { .. })
    ));
    assert_eq!(gw.minted_of_asset(&ASSET), 0);
}

#[test]
fn escrow_overflow_is_refused_not_wrapped() {
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, OperatorSet::new(0), u128::MAX);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, u128::MAX);
    gw.advance_to(10_000);
    gw.set_escrow(ASSET, u128::MAX);
    assert!(admit(&mut gw, 1, u128::MAX).is_ok());
    assert!(admit(&mut gw, 2, 1).is_err());
    assert_eq!(gw.minted_of_asset(&ASSET), u128::MAX);
}

#[test]
fn an_asset_with_no_declared_escrow_keeps_the_cap_behaviour() {
    let mut gw = gateway();
    assert_eq!(gw.escrow_of(&ASSET), None);
    assert!(admit(&mut gw, 1, 900_000_000).is_ok());
    assert_eq!(gw.minted_of_asset(&ASSET), 900_000_000);
}
