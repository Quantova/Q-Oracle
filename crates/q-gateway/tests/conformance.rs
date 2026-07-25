// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
use q_gateway::gateway::REORG_DOMAIN;
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

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
    seed[31] = 0xc3;
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

fn attest(op: &Op, fact: &BridgeFact) -> SignerSig {
    sign_ctx(op, &fact.attest_preimage(), ATTEST_DOMAIN)
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

fn gateway(ops: &[Op], threshold: usize) -> Gateway {
    let mut set = OperatorSet::new(threshold);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, set, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, 1_000);
    gw
}

#[test]
fn vector_prove_nothing_message_fails() {
    let ops: Vec<Op> = (0..5).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let zero = BridgeFact {
        version: 0,
        source_chain: 0,
        dest_chain: 0,
        route_id: 0,
        direction: Direction::Deposit,
        nonce: 0,
        source_ref: SourceRef([0; 32]),
        asset_id: AssetId([0; 16]),
        amount: 0,
        recipient: Recipient([0; 32]),
        finality_depth: 0,
        observed_height: 0,
        expiry_height: 0,
    };
    let env = AttestationEnvelope {
        fact: zero.clone(),
        signatures: (0..3).map(|i| attest(&ops[i], &zero)).collect(),
    };
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::ProveNothing));
    assert_eq!(gw.minted_of_asset(&ASSET), 0);
}

#[test]
fn vector_off_by_one_quorum_fails() {
    let ops: Vec<Op> = (0..5).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let f = deposit([0x12; 32], 500);

    let one_short = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![attest(&ops[0], &f), attest(&ops[1], &f)],
    };
    assert_eq!(
        gw.process_deposit(&one_short),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
    assert_eq!(gw.minted_of_asset(&ASSET), 0);

    let exact = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![attest(&ops[0], &f), attest(&ops[1], &f), attest(&ops[2], &f)],
    };
    assert_eq!(gw.process_deposit(&exact).expect("exact quorum mints").amount, 500);
}

#[test]
fn vector_duplicate_signer_fails() {
    let ops: Vec<Op> = (0..5).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let f = deposit([0x13; 32], 500);
    let s0 = attest(&ops[0], &f);
    let s1 = attest(&ops[1], &f);
    let env = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![s0.clone(), s0, s1],
    };
    assert_eq!(
        gw.process_deposit(&env),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
    assert_eq!(gw.minted_of_asset(&ASSET), 0);
}

#[test]
fn vector_signature_under_a_foreign_context_does_not_count() {
    let ops: Vec<Op> = (0..3).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let f = deposit([0x14; 32], 500);
    let env = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![
            attest(&ops[0], &f),
            attest(&ops[1], &f),
            sign_ctx(&ops[2], &f.attest_preimage(), REORG_DOMAIN),
        ],
    };
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::BadSignature(2)));
    assert_eq!(gw.minted_of_asset(&ASSET), 0);
}

#[test]
fn vector_signature_over_a_reshaped_fact_does_not_count() {
    let ops: Vec<Op> = (0..3).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let f = deposit([0x15; 32], 500);
    let reshaped = deposit([0x15; 32], 999);
    let env = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![
            attest(&ops[0], &f),
            attest(&ops[1], &f),
            attest(&ops[2], &reshaped),
        ],
    };
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::BadSignature(2)));
    assert_eq!(gw.minted_of_asset(&ASSET), 0);
}

#[test]
fn vector_reference_is_consumed_before_any_second_mint() {
    let ops: Vec<Op> = (0..5).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let f = deposit([0x16; 32], 500);
    gw.process_deposit(&AttestationEnvelope {
        fact: f.clone(),
        signatures: (0..3).map(|i| attest(&ops[i], &f)).collect(),
    })
    .expect("first mint consumes the reference");

    let reshaped = deposit([0x16; 32], 400);
    let replay = AttestationEnvelope {
        fact: reshaped.clone(),
        signatures: (2..5).map(|i| attest(&ops[i], &reshaped)).collect(),
    };
    assert_eq!(gw.process_deposit(&replay), Err(GatewayError::ReplayedReference));
    assert_eq!(gw.minted_of_asset(&ASSET), 500);
}
