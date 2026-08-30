// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::SignerSig;
use q_codec::Writer;
use q_gateway::gateway::BATCH_DOMAIN;
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const CHAIN_ID: u32 = 9000;
const SOURCE: u32 = 4;

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0x8D;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn batch_message(source: u32, index: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(source);
    w.u64(index);
    w.u64(DEST_ID);
    w.finish()
}

fn sign_batch(op: &Op, source: u32, index: u64) -> SignerSig {
    let sig = ml_dsa::sign(
        &op.sk,
        &batch_message(source, index),
        BATCH_DOMAIN,
        &[0u8; 32],
    )
    .unwrap();
    SignerSig {
        operator_id: op.id,
        signature: sig.to_vec(),
    }
}

fn quorum(ops: &[Op], source: u32, index: u64) -> Vec<SignerSig> {
    ops[0..3]
        .iter()
        .map(|op| sign_batch(op, source, index))
        .collect()
}

fn gateway(ops: &[Op]) -> Gateway {
    let mut set = OperatorSet::new(3);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    gw
}

#[test]
fn the_cursor_advances_one_batch_at_a_time() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    assert_eq!(gw.corridor_cursor(SOURCE), 0);

    gw.accept_batch(SOURCE, 0, &quorum(&ops, SOURCE, 0))
        .expect("batch zero is in order");
    assert_eq!(gw.corridor_cursor(SOURCE), 1);

    gw.accept_batch(SOURCE, 1, &quorum(&ops, SOURCE, 1))
        .expect("batch one follows");
    assert_eq!(gw.corridor_cursor(SOURCE), 2);
}

#[test]
fn a_replayed_batch_index_is_rejected() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.accept_batch(SOURCE, 0, &quorum(&ops, SOURCE, 0))
        .expect("batch zero");

    assert_eq!(
        gw.accept_batch(SOURCE, 0, &quorum(&ops, SOURCE, 0)),
        Err(GatewayError::StaleBatch {
            got: 0,
            expected: 1
        })
    );
    assert_eq!(gw.corridor_cursor(SOURCE), 1);
}

#[test]
fn an_out_of_order_batch_is_rejected() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.accept_batch(SOURCE, 0, &quorum(&ops, SOURCE, 0))
        .expect("batch zero");

    assert_eq!(
        gw.accept_batch(SOURCE, 5, &quorum(&ops, SOURCE, 5)),
        Err(GatewayError::StaleBatch {
            got: 5,
            expected: 1
        })
    );
}

#[test]
fn a_batch_below_quorum_does_not_advance_the_cursor() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    let two: Vec<SignerSig> = ops[0..2]
        .iter()
        .map(|op| sign_batch(op, SOURCE, 0))
        .collect();
    assert_eq!(
        gw.accept_batch(SOURCE, 0, &two),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
    assert_eq!(gw.corridor_cursor(SOURCE), 0);
}

#[test]
fn a_batch_on_an_unopened_corridor_is_rejected() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    assert_eq!(
        gw.accept_batch(7, 0, &quorum(&ops, 7, 0)),
        Err(GatewayError::CorridorNotOpen(7))
    );
}

#[test]
fn each_corridor_keeps_its_own_cursor() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops);
    gw.register_corridor(9, 6);

    gw.accept_batch(SOURCE, 0, &quorum(&ops, SOURCE, 0))
        .expect("source four batch zero");
    gw.accept_batch(SOURCE, 1, &quorum(&ops, SOURCE, 1))
        .expect("source four batch one");
    gw.accept_batch(9, 0, &quorum(&ops, 9, 0))
        .expect("source nine batch zero");

    assert_eq!(gw.corridor_cursor(SOURCE), 2);
    assert_eq!(gw.corridor_cursor(9), 1);
}
