// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
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
    seed[31] = 0x9e;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn gateway(ops: &[Op], threshold: usize) -> Gateway {
    let mut set = OperatorSet::new(threshold);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, 1_000_000);
    gw
}

fn fact(source_ref: [u8; 32], route_id: u32, nonce: u64, expiry_height: u64, amount: u128) -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: SOURCE,
        dest_chain: CHAIN_ID,
        route_id,
        direction: Direction::Deposit,
        nonce,
        source_ref: SourceRef(source_ref),
        asset_id: AssetId(ASSET),
        amount,
        recipient: Recipient([0x55; 32]),
        finality_depth: 6,
        observed_height: 800_000,
        expiry_height,
    }
}

fn attest(ops: &[&Op], f: &BridgeFact) -> AttestationEnvelope {
    AttestationEnvelope {
        fact: f.clone(),
        signatures: ops
            .iter()
            .map(|op| {
                let sig = ml_dsa::sign(&op.sk, &f.attest_preimage(DEST_ID), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
                SignerSig {
                    operator_id: op.id,
                    signature: sig.to_vec(),
                }
            })
            .collect(),
    }
}

#[test]
fn a_deposit_past_its_signed_deadline_is_rejected_and_the_deadline_block_still_admits() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    gw.advance_to(2_000);

    let expired = fact([0x41; 32], 1, 10, 1_999, 500);
    assert_eq!(
        gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &expired)),
        Err(GatewayError::MessageExpired { now: 2_000, expiry: 1_999 })
    );
    assert_eq!(gw.minted_of_asset(&ASSET), 0);

    let on_time = fact([0x42; 32], 1, 11, 2_000, 500);
    let receipt = gw
        .process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &on_time))
        .expect("a deposit admitted on its deadline block still mints");
    assert_eq!(receipt.amount, 500);
}

#[test]
fn a_non_advancing_nonce_with_a_fresh_reference_still_admits() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);

    let first = fact([0x11; 32], 1, 5, 900_000, 500);
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &first))
        .expect("the first deposit mints");

    let equal_nonce = fact([0x12; 32], 1, 5, 900_000, 500);
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &equal_nonce))
        .expect("an equal-nonce deposit with a fresh reference is not wedged");

    let lower_nonce = fact([0x13; 32], 1, 3, 900_000, 500);
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &lower_nonce))
        .expect("a lower-nonce deposit with a fresh reference is not wedged");

    let replay = fact([0x11; 32], 1, 42, 900_000, 500);
    assert_eq!(
        gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &replay)),
        Err(GatewayError::ReplayedReference)
    );

    assert_eq!(gw.minted_of_asset(&ASSET), 1_500);
}

#[test]
fn a_strictly_increasing_nonce_sequence_admits() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);

    for (i, nonce) in [5u64, 6, 7, 100].iter().enumerate() {
        let f = fact([0x20 + i as u8; 32], 1, *nonce, 900_000, 100);
        gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &f))
            .unwrap_or_else(|e| panic!("advancing nonce {} admits, got {:?}", nonce, e));
    }

    assert_eq!(gw.minted_of_asset(&ASSET), 400);
}

#[test]
fn deposits_on_different_routes_each_mint() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);

    let route_one = fact([0x31; 32], 1, 9, 900_000, 500);
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &route_one))
        .expect("route 1 admits");

    let route_two = fact([0x32; 32], 2, 9, 900_000, 500);
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &route_two))
        .expect("route 2 admits independently");

    assert_eq!(gw.minted_of_asset(&ASSET), 1_000);
}
