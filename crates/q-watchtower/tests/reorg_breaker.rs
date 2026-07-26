// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
use q_gateway::{Gateway, GatewayError, OperatorSet};
use q_watchtower::{CorridorReorgPolicy, ReorgVerdict, ReorgWatcher, WatchtowerId};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const CHAIN_ID: u32 = 9000;
const SOURCE: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk_op(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0x5a;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn sign(op: &Op, fact: &BridgeFact) -> SignerSig {
    let sig = ml_dsa::sign(&op.sk, &fact.attest_preimage(), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
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
        recipient: Recipient([0x66; 32]),
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

fn reorg_watcher(id: u32, max_depth: u32) -> ReorgWatcher {
    let mut policy = CorridorReorgPolicy::new();
    policy.set(SOURCE, max_depth);
    ReorgWatcher::new(WatchtowerId(id), policy)
}

#[test]
fn a_single_watchtower_pauses_a_corridor_and_a_paused_corridor_rejects_mints() {
    let ops: Vec<Op> = (0..4).map(mk_op).collect();
    let mut gw = gateway(&ops, 3);
    let watcher = reorg_watcher(1, 6);

    let verdict = watcher.observe(&mut gw, SOURCE, 7);
    assert_eq!(
        verdict,
        ReorgVerdict::Paused {
            watchtower: WatchtowerId(1),
            source_chain: SOURCE,
            fork_depth: 7,
        }
    );
    assert!(gw.is_source_paused(SOURCE));

    let fact = deposit([0x71; 32], 500);
    let env = AttestationEnvelope {
        fact: fact.clone(),
        signatures: vec![sign(&ops[0], &fact), sign(&ops[1], &fact), sign(&ops[2], &fact)],
    };
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::SourcePaused(SOURCE)));
    assert_eq!(gw.minted_of_asset(&ASSET), 0);
}

#[test]
fn a_reorg_past_the_configured_depth_pauses_the_route_a_shallow_one_does_not() {
    let ops: Vec<Op> = (0..3).map(mk_op).collect();
    let mut gw = gateway(&ops, 2);
    let watcher = reorg_watcher(2, 6);

    let shallow = watcher.observe(&mut gw, SOURCE, 6);
    assert_eq!(shallow, ReorgVerdict::WithinDepth);
    assert!(!gw.is_source_paused(SOURCE));

    let deep = watcher.observe(&mut gw, SOURCE, 9);
    assert_eq!(
        deep,
        ReorgVerdict::Paused {
            watchtower: WatchtowerId(2),
            source_chain: SOURCE,
            fork_depth: 9,
        }
    );
    assert!(gw.is_source_paused(SOURCE));
}

#[test]
fn an_independent_watchtower_pause_is_honored_when_the_oracle_set_stays_silent() {
    let ops: Vec<Op> = (0..4).map(mk_op).collect();
    let mut gw = gateway(&ops, 3);
    let watcher = reorg_watcher(3, 6);

    watcher.observe(&mut gw, SOURCE, 20);
    assert!(gw.is_source_paused(SOURCE));

    let fact = deposit([0x72; 32], 500);
    let silent = AttestationEnvelope {
        fact,
        signatures: Vec::new(),
    };
    assert_eq!(gw.process_deposit(&silent), Err(GatewayError::SourcePaused(SOURCE)));
}

#[test]
fn a_resume_is_required_to_unpause_and_is_not_automatic() {
    let ops: Vec<Op> = (0..4).map(mk_op).collect();
    let mut gw = gateway(&ops, 3);
    let watcher = reorg_watcher(4, 6);

    watcher.observe(&mut gw, SOURCE, 10);
    assert!(gw.is_source_paused(SOURCE));

    watcher.observe(&mut gw, SOURCE, 2);
    assert!(gw.is_source_paused(SOURCE));

    let fact = deposit([0x73; 32], 500);
    let env = AttestationEnvelope {
        fact: fact.clone(),
        signatures: vec![sign(&ops[0], &fact), sign(&ops[1], &fact), sign(&ops[2], &fact)],
    };
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::SourcePaused(SOURCE)));

    gw.unpause_source(SOURCE);
    assert!(!gw.is_source_paused(SOURCE));

    let receipt = gw.process_deposit(&env).expect("resume lets the corridor mint again");
    assert_eq!(receipt.amount, 500);
    assert_eq!(gw.minted_of_asset(&ASSET), 500);
}

#[test]
fn one_honest_watchtower_is_enough_even_if_another_stays_silent() {
    let ops: Vec<Op> = (0..4).map(mk_op).collect();
    let mut gw = gateway(&ops, 3);

    let honest = reorg_watcher(5, 6);
    let _silent = reorg_watcher(6, 6);

    honest.observe(&mut gw, SOURCE, 12);
    assert!(gw.is_source_paused(SOURCE));

    let fact = deposit([0x74; 32], 500);
    let env = AttestationEnvelope {
        fact: fact.clone(),
        signatures: vec![sign(&ops[0], &fact), sign(&ops[1], &fact), sign(&ops[2], &fact)],
    };
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::SourcePaused(SOURCE)));
}
