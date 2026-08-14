// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::SignerSig;
use q_codec::Writer;
use q_gateway::gateway::TIER_DOMAIN;
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const CHAIN_ID: u32 = 9000;
const SOURCE: u32 = 1;

struct Signer {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32, salt: u8) -> Signer {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = salt;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Signer { id, pk, sk }
}

fn tier_message(source: u32, proposed: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(source);
    w.u8(proposed);
    w.u64(DEST_ID);
    w.finish()
}

fn sign_tier(op: &Signer, source: u32, proposed: u8) -> SignerSig {
    let sig = ml_dsa::sign(&op.sk, &tier_message(source, proposed), TIER_DOMAIN, &[0u8; 32]).unwrap();
    SignerSig {
        operator_id: op.id,
        signature: sig.to_vec(),
    }
}

fn build(operators: &[Signer], governance: &[Signer], gov_threshold: usize) -> Gateway {
    let mut ops = OperatorSet::new(3);
    for op in operators {
        ops.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, ops, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    let mut gov = OperatorSet::new(gov_threshold);
    for g in governance {
        gov.register(g.id, g.pk);
    }
    gw.set_governance(gov);
    gw
}

#[test]
fn governance_quorum_upgrades_the_tier_step_by_step() {
    let operators: Vec<Signer> = (0..5).map(|i| mk(i, 0xA1)).collect();
    let governance: Vec<Signer> = (10..14).map(|i| mk(i, 0x6E)).collect();
    let mut gw = build(&operators, &governance, 3);

    assert_eq!(gw.corridor_tier(SOURCE), Some(1));

    let up_two: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 2)).collect();
    gw.set_corridor_tier(SOURCE, 2, &up_two).expect("governance upgrade to two is accepted");
    assert_eq!(gw.corridor_tier(SOURCE), Some(2));

    let up_three: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 3)).collect();
    gw.set_corridor_tier(SOURCE, 3, &up_three).expect("governance upgrade to three is accepted");
    assert_eq!(gw.corridor_tier(SOURCE), Some(3));
}

#[test]
fn a_tier_downgrade_is_rejected() {
    let operators: Vec<Signer> = (0..5).map(|i| mk(i, 0xA1)).collect();
    let governance: Vec<Signer> = (10..14).map(|i| mk(i, 0x6E)).collect();
    let mut gw = build(&operators, &governance, 3);

    let up_three: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 3)).collect();
    gw.set_corridor_tier(SOURCE, 3, &up_three).expect("first raise to three");

    let down: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 2)).collect();
    assert_eq!(
        gw.set_corridor_tier(SOURCE, 2, &down),
        Err(GatewayError::TierDowngrade { from: 3, to: 2 })
    );
    assert_eq!(gw.corridor_tier(SOURCE), Some(3));
}

#[test]
fn a_sideways_reassert_of_the_same_tier_is_rejected() {
    let operators: Vec<Signer> = (0..5).map(|i| mk(i, 0xA1)).collect();
    let governance: Vec<Signer> = (10..14).map(|i| mk(i, 0x6E)).collect();
    let mut gw = build(&operators, &governance, 3);

    let up_two: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 2)).collect();
    gw.set_corridor_tier(SOURCE, 2, &up_two).expect("raise to two");

    let same: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 2)).collect();
    assert_eq!(
        gw.set_corridor_tier(SOURCE, 2, &same),
        Err(GatewayError::TierDowngrade { from: 2, to: 2 })
    );
}

#[test]
fn an_operator_quorum_cannot_move_the_tier() {
    let operators: Vec<Signer> = (0..5).map(|i| mk(i, 0xA1)).collect();
    let governance: Vec<Signer> = (10..14).map(|i| mk(i, 0x6E)).collect();
    let mut gw = build(&operators, &governance, 3);

    let by_operators: Vec<SignerSig> = operators[0..3]
        .iter()
        .map(|op| sign_tier(op, SOURCE, 2))
        .collect();
    assert_eq!(
        gw.set_corridor_tier(SOURCE, 2, &by_operators),
        Err(GatewayError::BelowThreshold { got: 0, need: 3 })
    );
    assert_eq!(gw.corridor_tier(SOURCE), Some(1));
}

#[test]
fn a_short_governance_quorum_cannot_move_the_tier() {
    let operators: Vec<Signer> = (0..5).map(|i| mk(i, 0xA1)).collect();
    let governance: Vec<Signer> = (10..14).map(|i| mk(i, 0x6E)).collect();
    let mut gw = build(&operators, &governance, 3);

    let two_of_three: Vec<SignerSig> = governance[0..2].iter().map(|g| sign_tier(g, SOURCE, 2)).collect();
    assert_eq!(
        gw.set_corridor_tier(SOURCE, 2, &two_of_three),
        Err(GatewayError::BelowThreshold { got: 2, need: 3 })
    );
}

#[test]
fn a_gateway_with_no_governance_set_upgrades_nothing() {
    let operators: Vec<Signer> = (0..5).map(|i| mk(i, 0xA1)).collect();
    let mut ops = OperatorSet::new(3);
    for op in &operators {
        ops.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, ops, 1_000_000);
    gw.register_corridor(SOURCE, 6);

    let governance: Vec<Signer> = (10..14).map(|i| mk(i, 0x6E)).collect();
    let sigs: Vec<SignerSig> = governance[0..3].iter().map(|g| sign_tier(g, SOURCE, 2)).collect();
    assert_eq!(
        gw.set_corridor_tier(SOURCE, 2, &sigs),
        Err(GatewayError::NoGovernanceSet)
    );
}
