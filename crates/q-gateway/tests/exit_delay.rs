// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, CodecError, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const CHAIN_ID: u32 = 9000;
const SOURCE: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];
const DEST: [u8; 32] = [0x77; 32];

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0x3E;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn deposit(source_ref: [u8; 32], amount: u128) -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: SOURCE,
        dest_chain: CHAIN_ID,
        route_id: 1,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(source_ref),
        asset_id: AssetId(ASSET),
        amount,
        recipient: Recipient([0x55; 32]),
        finality_depth: 6,
        observed_height: 800_000,
        expiry_height: 900_000,
    }
}

fn attest(ops: &[&Op], fact: &BridgeFact) -> AttestationEnvelope {
    AttestationEnvelope {
        fact: fact.clone(),
        signatures: ops
            .iter()
            .map(|op| {
                let sig = ml_dsa::sign(&op.sk, &fact.attest_preimage(DEST_ID), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
                SignerSig {
                    operator_id: op.id,
                    signature: sig.to_vec(),
                }
            })
            .collect(),
    }
}

fn gateway_with_mint(ops: &[Op], exit_delay: u64) -> Gateway {
    let mut set = OperatorSet::new(3);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, 1_000);
    gw.set_exit_delay(exit_delay);
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &deposit([0x11; 32], 800)))
        .expect("seed a minted balance to exit");
    gw
}

#[test]
fn an_exit_burns_the_origin_asset_and_waits_out_the_delay() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway_with_mint(&ops, 100);
    gw.advance_to(1_000);
    assert_eq!(gw.minted_of_asset(&ASSET), 800);

    let ticket = gw.request_exit(ASSET, 300, DEST).expect("exit request burns the bridged units");
    assert_eq!(ticket.amount, 300);
    assert_eq!(ticket.unlock_height, 1_100);
    assert_eq!(gw.minted_of_asset(&ASSET), 500);

    assert_eq!(
        gw.finalize_exit(ticket.exit_id),
        Err(GatewayError::ExitNotReady { now: 1_000, unlock: 1_100 })
    );

    gw.advance_to(1_099);
    assert_eq!(
        gw.finalize_exit(ticket.exit_id),
        Err(GatewayError::ExitNotReady { now: 1_099, unlock: 1_100 })
    );

    gw.advance_to(1_100);
    let released = gw.finalize_exit(ticket.exit_id).expect("the exit clears once the delay elapses");
    assert_eq!(released.amount, 300);
    assert_eq!(released.destination, DEST);
}

#[test]
fn an_exit_larger_than_the_minted_balance_is_rejected() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway_with_mint(&ops, 100);
    assert_eq!(
        gw.request_exit(ASSET, 801, DEST),
        Err(GatewayError::ExitExceedsMinted { minted: 800, amount: 801 })
    );
    assert_eq!(gw.minted_of_asset(&ASSET), 800);
}

#[test]
fn a_zero_exit_is_rejected() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway_with_mint(&ops, 100);
    assert_eq!(
        gw.request_exit(ASSET, 0, DEST),
        Err(GatewayError::InvalidFact(CodecError::ZeroAmount))
    );
}

#[test]
fn a_zero_delay_exit_clears_at_once() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway_with_mint(&ops, 0);
    gw.advance_to(500);
    let ticket = gw.request_exit(ASSET, 100, DEST).expect("exit request");
    assert_eq!(ticket.unlock_height, 500);
    let released = gw.finalize_exit(ticket.exit_id).expect("no delay to wait");
    assert_eq!(released.amount, 100);
}

#[test]
fn an_unknown_exit_ticket_is_rejected() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway_with_mint(&ops, 100);
    assert_eq!(gw.finalize_exit(41), Err(GatewayError::UnknownExit(41)));
}
