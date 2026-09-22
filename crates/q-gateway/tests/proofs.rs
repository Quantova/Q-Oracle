// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{attest_context, AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION};
use q_gateway::gateway::REORG_DOMAIN;
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const CHAIN_ID: u32 = 9000;
const SOURCE_BTC: u32 = 1;
const ASSET_A: [u8; 16] = [0xa1; 16];
const ASSET_B: [u8; 16] = [0xb2; 16];

struct TestOp {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk_op(id: u32) -> TestOp {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[1] = (id >> 8) as u8;
    seed[31] = 0xAA;
    let (pk, sk) = ml_dsa::keygen(&seed);
    TestOp { id, pk, sk }
}

fn sign_over(op: &TestOp, message: &[u8], context: &[u8]) -> SignerSig {
    let sig = ml_dsa::sign(&op.sk, message, context, &[0u8; 32]).unwrap();
    SignerSig {
        operator_id: op.id,
        signature: sig.to_vec(),
    }
}

fn sign_fact(op: &TestOp, fact: &BridgeFact) -> SignerSig {
    sign_over(
        op,
        &fact.attest_preimage(DEST_ID),
        &attest_context(&[0u8; 32]),
    )
}

fn deposit_fact(source_ref: [u8; 32], asset: [u8; 16], amount: u128) -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: SOURCE_BTC,
        dest_chain: CHAIN_ID,
        route_id: 1,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(source_ref),
        asset_id: AssetId(asset),
        amount,
        recipient: Recipient([0x55; 32]),
        finality_depth: 6,
        observed_height: 800_000,
        expiry_height: 900_000,
    }
}

fn build_gateway(ops: &[TestOp], threshold: usize, epoch_cap: u128) -> Gateway {
    let mut set = OperatorSet::new(threshold);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, epoch_cap);
    gw.register_corridor(SOURCE_BTC, 6);
    gw.register_asset_cap(ASSET_A, 1_000);
    gw.register_asset_cap(ASSET_B, 1_000);
    gw
}

fn attest(ops: &[&TestOp], fact: &BridgeFact) -> AttestationEnvelope {
    AttestationEnvelope {
        fact: fact.clone(),
        signatures: ops.iter().map(|op| sign_fact(op, fact)).collect(),
    }
}

#[test]
fn valid_quorum_mints_exactly_once() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let fact = deposit_fact([0x11; 32], ASSET_A, 500);
    let env = attest(&[&ops[0], &ops[1], &ops[2]], &fact);

    let receipt = gw.process_deposit(&env).expect("first mint succeeds");
    assert_eq!(receipt.amount, 500);
    assert_eq!(receipt.asset_id, ASSET_A);
    assert_eq!(gw.minted_of_asset(&ASSET_A), 500);

    let again = gw.process_deposit(&env);
    assert_eq!(again, Err(GatewayError::ReplayedReference));
    assert_eq!(gw.minted_of_asset(&ASSET_A), 500);
}

#[test]
fn prove_nothing_message_is_rejected() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
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
    let env = attest(&[&ops[0], &ops[1], &ops[2]], &zero);
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::ProveNothing));
}

#[test]
fn under_quorum_is_rejected() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let fact = deposit_fact([0x12; 32], ASSET_A, 500);
    let env = attest(&[&ops[0], &ops[1]], &fact);
    assert_eq!(
        gw.process_deposit(&env),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
    assert_eq!(gw.minted_of_asset(&ASSET_A), 0);
}

#[test]
fn duplicate_signer_cannot_inflate_the_count() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let fact = deposit_fact([0x13; 32], ASSET_A, 500);
    let s0 = sign_fact(&ops[0], &fact);
    let s1 = sign_fact(&ops[1], &fact);
    let env = AttestationEnvelope {
        fact: fact.clone(),
        signatures: vec![s0.clone(), s0, s1],
    };
    assert_eq!(
        gw.process_deposit(&env),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
    assert_eq!(gw.minted_of_asset(&ASSET_A), 0);
}

#[test]
fn unknown_operator_is_rejected() {
    let ops: Vec<TestOp> = (0..3).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let outsider = mk_op(99);
    let fact = deposit_fact([0x14; 32], ASSET_A, 500);
    let env = attest(&[&ops[0], &ops[1], &outsider], &fact);
    assert_eq!(
        gw.process_deposit(&env),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let fact = deposit_fact([0x15; 32], ASSET_A, 500);
    let mut env = attest(&[&ops[0], &ops[1], &ops[2]], &fact);
    let last = env.signatures[2].signature.len() - 1;
    env.signatures[2].signature[last] ^= 0x01;
    assert_eq!(
        gw.process_deposit(&env),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
}

#[test]
fn replay_of_used_reference_is_rejected_even_with_a_fresh_quorum() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let source_ref = [0x16; 32];
    let fact = deposit_fact(source_ref, ASSET_A, 500);

    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &fact))
        .expect("first mint");

    let replay = attest(&[&ops[1], &ops[2], &ops[3]], &fact);
    assert_eq!(
        gw.process_deposit(&replay),
        Err(GatewayError::ReplayedReference)
    );
}

#[test]
fn per_asset_cap_blocks_over_limit_mint() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);

    gw.process_deposit(&attest(
        &[&ops[0], &ops[1], &ops[2]],
        &deposit_fact([0x21; 32], ASSET_A, 600),
    ))
    .expect("first mint under cap");

    let over = gw.process_deposit(&attest(
        &[&ops[0], &ops[1], &ops[2]],
        &deposit_fact([0x22; 32], ASSET_A, 600),
    ));
    assert_eq!(
        over,
        Err(GatewayError::AssetCapExceeded {
            minted: 600,
            cap: 1_000,
            add: 600
        })
    );
    assert_eq!(gw.minted_of_asset(&ASSET_A), 600);
}

#[test]
fn per_epoch_cap_blocks_over_limit_mint_and_resets_next_epoch() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000);

    gw.process_deposit(&attest(
        &[&ops[0], &ops[1], &ops[2]],
        &deposit_fact([0x31; 32], ASSET_A, 600),
    ))
    .expect("first mint within epoch cap");

    let over = gw.process_deposit(&attest(
        &[&ops[0], &ops[1], &ops[2]],
        &deposit_fact([0x32; 32], ASSET_B, 600),
    ));
    assert_eq!(
        over,
        Err(GatewayError::EpochCapExceeded {
            minted: 600,
            cap: 1_000,
            add: 600
        })
    );

    gw.advance_epoch();
    let mut next = deposit_fact([0x33; 32], ASSET_B, 600);
    next.nonce = 2;
    gw.process_deposit(&attest(&[&ops[0], &ops[1], &ops[2]], &next))
        .expect("mint allowed in fresh epoch");
    assert_eq!(gw.minted_of_asset(&ASSET_B), 600);
}

#[test]
fn insufficient_finality_is_rejected() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    let mut fact = deposit_fact([0x41; 32], ASSET_A, 500);
    fact.finality_depth = 5;
    let env = attest(&[&ops[0], &ops[1], &ops[2]], &fact);
    assert_eq!(
        gw.process_deposit(&env),
        Err(GatewayError::InsufficientFinality { got: 5, need: 6 })
    );
}

#[test]
fn source_reorg_auto_pauses_the_route() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);

    let reorg_msg = q_gateway::gateway::reorg_message(SOURCE_BTC, 3, 0, DEST_ID, &[0u8; 32]);
    let sigs: Vec<SignerSig> = ops[0..3]
        .iter()
        .map(|op| sign_over(op, &reorg_msg, REORG_DOMAIN))
        .collect();
    gw.report_reorg(SOURCE_BTC, 3, 0, &sigs)
        .expect("reorg pauses source");
    assert!(gw.is_source_paused(SOURCE_BTC));

    let after = gw.process_deposit(&attest(
        &[&ops[0], &ops[1], &ops[2]],
        &deposit_fact([0x51; 32], ASSET_A, 500),
    ));
    assert_eq!(after, Err(GatewayError::SourcePaused(SOURCE_BTC)));
}

fn pause_at(gw: &mut Gateway, ops: &[TestOp], height: u64) {
    gw.advance_to(height);
    let sigs = reorg_sigs(ops, height);
    gw.report_reorg(SOURCE_BTC, 3, height, &sigs)
        .expect("paused");
}

fn reorg_sigs(ops: &[TestOp], at: u64) -> Vec<SignerSig> {
    let reorg_msg = q_gateway::gateway::reorg_message(SOURCE_BTC, 3, at, DEST_ID, &[0u8; 32]);
    ops[0..3]
        .iter()
        .map(|op| sign_over(op, &reorg_msg, REORG_DOMAIN))
        .collect()
}

#[test]
fn a_reorg_report_cannot_be_replayed_after_the_resume_it_preceded() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    pause_at(&mut gw, &ops, 100);
    let replayed = reorg_sigs(&ops, 100);
    gw.advance_to(101);
    gw.resume_source(SOURCE_BTC, 101, &resume_sigs(&ops, 101))
        .expect("a quorum resumes");
    assert!(matches!(
        gw.report_reorg(SOURCE_BTC, 3, 100, &replayed),
        Err(GatewayError::ResumeOutOfWindow { .. })
    ));
    assert!(!gw.is_source_paused(SOURCE_BTC));
    gw.advance_to(102 + q_gateway::gateway::RESUME_WINDOW + 1);
    assert!(matches!(
        gw.report_reorg(SOURCE_BTC, 3, 102, &reorg_sigs(&ops, 102)),
        Err(GatewayError::ResumeOutOfWindow { .. })
    ));
}

fn resume_sigs(ops: &[TestOp], at: u64) -> Vec<SignerSig> {
    let msg = q_gateway::gateway::resume_message(SOURCE_BTC, at, DEST_ID, &[0u8; 32]);
    ops[0..3]
        .iter()
        .map(|op| sign_over(op, &msg, q_gateway::gateway::RESUME_DOMAIN))
        .collect()
}

#[test]
fn a_quorum_resume_lifts_a_reorg_pause_and_nothing_older_can() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    pause_at(&mut gw, &ops, 100);

    // Signed for a height before the pause: it cannot have been meant for this pause.
    assert!(matches!(
        gw.resume_source(SOURCE_BTC, 90, &resume_sigs(&ops, 90)),
        Err(GatewayError::ResumeOutOfWindow { .. })
    ));
    let fresh = resume_sigs(&ops, 101);
    gw.resume_source(SOURCE_BTC, 101, &fresh)
        .expect("a quorum resumes");
    assert!(!gw.is_source_paused(SOURCE_BTC));

    // Paused again: the resume that lifted the first pause does not lift this one.
    pause_at(&mut gw, &ops, 150);
    assert!(matches!(
        gw.resume_source(SOURCE_BTC, 101, &fresh),
        Err(GatewayError::ResumeOutOfWindow { .. })
    ));
    assert!(gw.is_source_paused(SOURCE_BTC));

    // Nor does a resume long since signed.
    let later = resume_sigs(&ops, 150);
    gw.advance_to(150 + q_gateway::gateway::RESUME_WINDOW + 1);
    assert!(matches!(
        gw.resume_source(SOURCE_BTC, 150, &later),
        Err(GatewayError::ResumeOutOfWindow { .. })
    ));

    // Two operators are not a quorum.
    let now = gw.current_height();
    let short: Vec<SignerSig> = resume_sigs(&ops, now).into_iter().take(2).collect();
    assert!(matches!(
        gw.resume_source(SOURCE_BTC, now, &short),
        Err(GatewayError::BelowThreshold { .. })
    ));
    assert!(gw.is_source_paused(SOURCE_BTC));
}

#[test]
fn a_reorg_report_signed_under_another_era_pauses_nothing() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    gw.set_era([7u8; 32]);
    let old_era = q_gateway::gateway::reorg_message(SOURCE_BTC, 3, 0, DEST_ID, &[0u8; 32]);
    let sigs: Vec<SignerSig> = ops[0..3]
        .iter()
        .map(|op| sign_over(op, &old_era, REORG_DOMAIN))
        .collect();
    assert!(matches!(
        gw.report_reorg(SOURCE_BTC, 3, 0, &sigs),
        Err(GatewayError::BelowThreshold { .. })
    ));
    assert!(!gw.is_source_paused(SOURCE_BTC));
}

#[test]
fn global_pause_reaches_every_route() {
    let ops: Vec<TestOp> = (0..4).map(mk_op).collect();
    let mut gw = build_gateway(&ops, 3, 1_000_000);
    gw.pause_all();
    let env = attest(
        &[&ops[0], &ops[1], &ops[2]],
        &deposit_fact([0x61; 32], ASSET_A, 500),
    );
    assert_eq!(gw.process_deposit(&env), Err(GatewayError::GlobalPause));
}
