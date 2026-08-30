// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::SignerSig;
use q_codec::Writer;
use q_gateway::gateway::{FREEZE_DOMAIN, REORG_DOMAIN};
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey, SIGNATURE_BYTES};

const DEST_ID: u64 = 0x0000_002a_0000_2328;
const OTHER_DEST_ID: u64 = DEST_ID ^ 0xffff_ffff;
const CHAIN_ID: u32 = 9000;

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0x91;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn sign_ctx(op: &Op, message: &[u8], context: &[u8]) -> SignerSig {
    SignerSig {
        operator_id: op.id,
        signature: ml_dsa::sign(&op.sk, message, context, &[0u8; 32])
            .unwrap()
            .to_vec(),
    }
}

fn freeze_msg(until: u64, dest: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(until);
    w.u64(dest);
    w.finish()
}

fn gateway(threshold: usize, ops: &[Op]) -> Gateway {
    let mut set = OperatorSet::new(threshold);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000);
    gw.register_corridor(1, 6);
    gw
}

#[test]
fn a_no_signature_freeze_or_reorg_is_refused() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(3, &ops);
    assert_eq!(
        gw.emergency_freeze(5_000, &[]),
        Err(GatewayError::BelowThreshold { got: 0, need: 3 })
    );
    assert!(!gw.is_frozen());
    assert_eq!(
        gw.report_reorg(1, 2, &[]),
        Err(GatewayError::BelowThreshold { got: 0, need: 3 })
    );
    assert!(!gw.is_source_paused(1));
}

#[test]
fn a_forged_signature_earns_no_freeze() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(3, &ops);
    let junk = vec![SignerSig {
        operator_id: ops[0].id,
        signature: vec![0u8; SIGNATURE_BYTES],
    }];
    assert_eq!(
        gw.emergency_freeze(5_000, &junk),
        Err(GatewayError::BelowThreshold { got: 0, need: 3 })
    );
    assert!(!gw.is_frozen());
}

#[test]
fn one_operator_repeated_is_counted_once_not_toward_the_whole_quorum() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(3, &ops);
    let one = sign_ctx(&ops[0], &freeze_msg(5_000, DEST_ID), FREEZE_DOMAIN);
    let stuffed = vec![one.clone(), one.clone(), one.clone(), one];
    assert_eq!(
        gw.emergency_freeze(5_000, &stuffed),
        Err(GatewayError::BelowThreshold { got: 1, need: 3 }),
        "a single signer submitted four times is one distinct signer"
    );
    assert!(!gw.is_frozen());
}

#[test]
fn a_freeze_quorum_signed_over_the_reorg_domain_does_not_freeze() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(3, &ops);
    let wrong_domain: Vec<SignerSig> = ops[0..3]
        .iter()
        .map(|op| sign_ctx(op, &freeze_msg(5_000, DEST_ID), REORG_DOMAIN))
        .collect();
    assert_eq!(
        gw.emergency_freeze(5_000, &wrong_domain),
        Err(GatewayError::BelowThreshold { got: 0, need: 3 }),
        "a signature over the wrong action domain earns no quorum"
    );
    assert!(!gw.is_frozen());
}

#[test]
fn a_freeze_quorum_bound_to_another_destination_chain_does_not_freeze() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(3, &ops);
    let wrong_chain: Vec<SignerSig> = ops[0..3]
        .iter()
        .map(|op| sign_ctx(op, &freeze_msg(5_000, OTHER_DEST_ID), FREEZE_DOMAIN))
        .collect();
    assert_eq!(
        gw.emergency_freeze(5_000, &wrong_chain),
        Err(GatewayError::BelowThreshold { got: 0, need: 3 }),
        "a signature bound to a sibling chain id earns no quorum here"
    );
    assert!(!gw.is_frozen());
}

#[test]
fn a_single_operator_cannot_freeze_when_the_threshold_is_left_below_a_supermajority() {
    let ops: Vec<Op> = (0..9).map(mk).collect();
    let mut gw = gateway(0, &ops);
    let one = vec![sign_ctx(
        &ops[0],
        &freeze_msg(u64::MAX, DEST_ID),
        FREEZE_DOMAIN,
    )];
    assert_eq!(
        gw.emergency_freeze(u64::MAX, &one),
        Err(GatewayError::BelowThreshold { got: 1, need: 6 })
    );
    assert!(
        !gw.is_frozen(),
        "one of nine cannot freeze the whole gateway"
    );

    let six: Vec<SignerSig> = ops[0..6]
        .iter()
        .map(|op| sign_ctx(op, &freeze_msg(u64::MAX, DEST_ID), FREEZE_DOMAIN))
        .collect();
    assert_eq!(gw.emergency_freeze(u64::MAX, &six), Ok(()));
    assert!(
        gw.is_frozen(),
        "a two-thirds supermajority of nine freezes the gateway"
    );
}
