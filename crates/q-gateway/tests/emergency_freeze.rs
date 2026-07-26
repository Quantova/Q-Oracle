// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, Writer, ATTEST_DOMAIN, FACT_VERSION};
use q_gateway::gateway::{FREEZE_DOMAIN, WATCHDOG_DOMAIN, WATCHDOG_MAX_WINDOW};
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const CHAIN_ID: u32 = 9000;
const SOURCE: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0xF2;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn sign_ctx(op: &Op, message: &[u8], context: &[u8]) -> SignerSig {
    let sig = ml_dsa::sign(&op.sk, message, context, &[0u8; 32]).unwrap();
    SignerSig {
        operator_id: op.id,
        signature: sig.to_vec(),
    }
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
            .map(|op| sign_ctx(op, &fact.attest_preimage(DEST_ID), ATTEST_DOMAIN))
            .collect(),
    }
}

fn until_message(until: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(until);
    w.finish()
}

fn gateway(ops: &[Op]) -> Gateway {
    let mut set = OperatorSet::new(3);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, 1_000);
    gw
}

#[test]
fn an_operator_quorum_freeze_halts_mints_then_auto_expires() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.advance_to(1_000);

    let sigs: Vec<SignerSig> = ops[0..3]
        .iter()
        .map(|op| sign_ctx(op, &until_message(1_100), FREEZE_DOMAIN))
        .collect();
    gw.emergency_freeze(1_100, &sigs).expect("bonded quorum freezes the gateway");
    assert!(gw.is_frozen());

    let held = gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &deposit([0x11; 32], 500)));
    assert_eq!(held, Err(GatewayError::Frozen { until: 1_100 }));
    assert_eq!(gw.minted_of_asset(&ASSET), 0);

    gw.advance_to(1_099);
    assert!(gw.is_frozen());
    let still_held = gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &deposit([0x12; 32], 500)));
    assert_eq!(still_held, Err(GatewayError::Frozen { until: 1_100 }));

    gw.advance_to(1_100);
    assert!(!gw.is_frozen());
    let minted = gw
        .process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &deposit([0x13; 32], 500)))
        .expect("the mint path reopens after the freeze expires");
    assert_eq!(minted.amount, 500);
    assert_eq!(gw.minted_of_asset(&ASSET), 500);
}

#[test]
fn a_short_freeze_quorum_does_not_freeze() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.advance_to(1_000);

    let two: Vec<SignerSig> = ops[0..2]
        .iter()
        .map(|op| sign_ctx(op, &until_message(1_100), FREEZE_DOMAIN))
        .collect();
    assert_eq!(
        gw.emergency_freeze(1_100, &two),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
    assert!(!gw.is_frozen());
}

#[test]
fn one_honest_watchdog_can_pause_within_a_bounded_window() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.advance_to(1_000);

    let until = 1_000 + WATCHDOG_MAX_WINDOW;
    let alarm = sign_ctx(&ops[3], &until_message(until), WATCHDOG_DOMAIN);
    gw.watchdog_freeze(until, &alarm).expect("a single honest watcher pauses the gateway");
    assert!(gw.is_frozen());

    let held = gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &deposit([0x21; 32], 500)));
    assert_eq!(held, Err(GatewayError::Frozen { until }));

    gw.advance_to(until);
    assert!(!gw.is_frozen());
    let minted = gw
        .process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &deposit([0x22; 32], 500)))
        .expect("the watchdog pause expires on its own");
    assert_eq!(minted.amount, 500);
}

#[test]
fn a_watchdog_cannot_pause_beyond_the_bounded_window() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.advance_to(1_000);

    let too_far = 1_000 + WATCHDOG_MAX_WINDOW + 1;
    let alarm = sign_ctx(&ops[3], &until_message(too_far), WATCHDOG_DOMAIN);
    assert_eq!(
        gw.watchdog_freeze(too_far, &alarm),
        Err(GatewayError::WatchdogWindowTooWide {
            until: too_far,
            max: 1_000 + WATCHDOG_MAX_WINDOW
        })
    );
    assert!(!gw.is_frozen());
}

#[test]
fn a_stranger_alarm_is_not_a_watchdog() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.advance_to(1_000);

    let outsider = mk(99);
    let until = 1_050;
    let alarm = sign_ctx(&outsider, &until_message(until), WATCHDOG_DOMAIN);
    assert_eq!(
        gw.watchdog_freeze(until, &alarm),
        Err(GatewayError::UnknownOperator(99))
    );
    assert!(!gw.is_frozen());
}
