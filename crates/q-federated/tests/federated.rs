// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use q_airlock::{parse, Artifact, AttestationEnvelope, SignerSig};
use q_codec::{
    AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION,
};
use q_federated::{
    admit, corridors, find, install, Corridor, FederatedError, SourceEndpoint, SourceRegistry,
    Tier, TrustGrade, AVALANCHE, BNB_CHAIN, LITECOIN, POLYGON, SOLANA, TRON, ZCASH,
};
use q_gateway::{Gateway, GatewayError, OperatorSet};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const CHAIN_ID: u32 = 9000;

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[1] = (id >> 8) as u8;
    seed[31] = 0xF7;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn gateway(ops: &[Op], threshold: usize) -> Gateway {
    let mut set = OperatorSet::new(threshold);
    for op in ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000_000_000_000);
    install(&mut gw);
    gw
}

fn deposit(c: &Corridor, source_ref: [u8; 32], amount: u128) -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: c.chain_id,
        dest_chain: CHAIN_ID,
        route_id: c.chain_id,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(source_ref),
        asset_id: AssetId(c.origin_asset.0),
        amount,
        recipient: Recipient([0x55; 32]),
        finality_depth: c.confirmation_depth + 8,
        observed_height: 900_000,
        expiry_height: 1_800_000,
    }
}

fn attest(op: &Op, f: &BridgeFact) -> SignerSig {
    let sig = ml_dsa::sign(&op.sk, &f.attest_preimage(DEST_ID), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
    SignerSig {
        operator_id: op.id,
        signature: sig.to_vec(),
    }
}

fn envelope(ops: &[&Op], f: &BridgeFact) -> AttestationEnvelope {
    AttestationEnvelope {
        fact: f.clone(),
        signatures: ops.iter().map(|op| attest(op, f)).collect(),
    }
}

fn ep(byte: u8) -> SourceEndpoint {
    SourceEndpoint([byte; 32])
}

fn independent_sources(corridor: u32, ops: &[Op]) -> SourceRegistry {
    let mut reg = SourceRegistry::new();
    for op in ops {
        let mut fp = [0u8; 32];
        fp[0] = corridor as u8;
        fp[1] = op.id as u8;
        fp[2] = 0x9d;
        reg.declare(corridor, op.id, SourceEndpoint(fp));
    }
    reg
}

#[test]
fn a_distinct_signer_quorum_over_the_canonical_fact_mints() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let sources = independent_sources(SOLANA, &ops);
    let c = find(SOLANA).unwrap();
    let f = deposit(&c, [0x11; 32], 500);
    let env = envelope(&[&ops[0], &ops[1], &ops[2]], &f);

    let receipt = admit(&mut gw, &c, &sources, &env).expect("independent quorum mints");
    assert_eq!(receipt.amount, 500);
    assert_eq!(receipt.asset_id, c.origin_asset.0);
    assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 500);
}

#[test]
fn a_wide_two_thirds_corridor_quorum_holds() {
    let ops: Vec<Op> = (0..9).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    gw.set_corridor_quorum(SOLANA, 6).expect("two thirds is a wide margin");
    let sources = independent_sources(SOLANA, &ops);
    let c = find(SOLANA).unwrap();
    let f = deposit(&c, [0x12; 32], 500);

    let five: Vec<&Op> = ops[0..5].iter().collect();
    assert_eq!(
        admit(&mut gw, &c, &sources, &envelope(&five, &f)),
        Err(FederatedError::Gateway(GatewayError::BelowThreshold { got: 5, need: 6 }))
    );

    let six: Vec<&Op> = ops[0..6].iter().collect();
    assert_eq!(
        admit(&mut gw, &c, &sources, &envelope(&six, &f)).expect("wide margin mints").amount,
        500
    );
}

#[test]
fn a_sub_quorum_does_not_mint() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let sources = independent_sources(SOLANA, &ops);
    let c = find(SOLANA).unwrap();
    let f = deposit(&c, [0x13; 32], 500);
    let env = envelope(&[&ops[0], &ops[1]], &f);

    assert_eq!(
        admit(&mut gw, &c, &sources, &env),
        Err(FederatedError::Gateway(GatewayError::BelowThreshold { got: 2, need: 3 }))
    );
    assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
}

#[test]
fn a_duplicate_signer_does_not_double_count() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let sources = independent_sources(SOLANA, &ops);
    let c = find(SOLANA).unwrap();
    let f = deposit(&c, [0x14; 32], 500);
    let s0 = attest(&ops[0], &f);
    let s1 = attest(&ops[1], &f);
    let env = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![s0.clone(), s0, s1],
    };

    assert_eq!(
        admit(&mut gw, &c, &sources, &env),
        Err(FederatedError::Gateway(GatewayError::BelowThreshold { got: 2, need: 3 }))
    );
    assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
}

#[test]
fn every_named_corridor_is_labeled_federated_tier() {
    let all = corridors();
    assert_eq!(all.len(), 19);
    for c in &all {
        assert_eq!(c.tier, Tier::Federated);
        assert_eq!(c.tier.label(), "Federated");
        assert_eq!(c.grade, TrustGrade::TrustedRelayer);
        assert!(!c.tier.is_proof_backed_tier());
        assert!(!c.tier.proof_backed());
    }
    let names: BTreeSet<&str> = all.iter().map(|c| c.name).collect();
    for expected in [
        "BNB Chain",
        "Polygon",
        "Avalanche",
        "Solana",
        "TRON",
        "XRP Ledger",
        "Cardano",
        "Near",
        "Sui",
        "Aptos",
        "Hedera",
        "Algorand",
        "Ton",
        "Stellar",
        "Monero",
        "Litecoin",
        "Dogecoin",
        "Zcash",
        "Circle CCTP USDC",
    ] {
        assert!(names.contains(expected), "missing corridor {expected}");
    }
}

#[test]
fn an_operator_on_a_shared_source_is_distinguishable_from_independent_sources() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let c = find(SOLANA).unwrap();
    let signers: BTreeSet<u32> = [0u32, 1, 2].into_iter().collect();

    let clean = independent_sources(SOLANA, &ops);
    let clean_report = clean.analyze(SOLANA, &signers);
    assert!(clean_report.fully_independent());
    assert_eq!(clean_report.independent_sources, 3);

    let mut shared = SourceRegistry::new();
    shared.declare(SOLANA, 0, ep(0xaa));
    shared.declare(SOLANA, 1, ep(0xaa));
    shared.declare(SOLANA, 2, ep(0xcc));
    for op in &ops[3..] {
        shared.declare(SOLANA, op.id, ep(0xd0 + op.id as u8));
    }
    let shared_report = shared.analyze(SOLANA, &signers);
    assert!(shared_report.correlated());
    assert_eq!(shared_report.independent_sources, 2);
    assert_ne!(clean_report, shared_report);

    let f = deposit(&c, [0x15; 32], 500);
    let env = envelope(&[&ops[0], &ops[1], &ops[2]], &f);

    let mut gw_clean = gateway(&ops, 3);
    assert!(admit(&mut gw_clean, &c, &clean, &env).is_ok());

    let mut gw_shared = gateway(&ops, 3);
    assert_eq!(
        admit(&mut gw_shared, &c, &shared, &env),
        Err(FederatedError::CorrelatedSources { independent: 2, signers: 3 })
    );
    assert_eq!(gw_shared.minted_of_asset(&c.origin_asset.0), 0);
}

#[test]
fn only_an_ml_dsa_attestation_over_the_canonical_preimage_counts() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let sources = independent_sources(SOLANA, &ops);
    let c = find(SOLANA).unwrap();
    let f = deposit(&c, [0x16; 32], 500);

    let foreign_der = vec![
        0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd, 0xef, 0x02, 0x20, 0x11, 0x22, 0x33,
    ];
    let env = AttestationEnvelope {
        fact: f.clone(),
        signatures: vec![
            attest(&ops[0], &f),
            attest(&ops[1], &f),
            SignerSig {
                operator_id: ops[2].id,
                signature: foreign_der,
            },
        ],
    };

    assert_eq!(
        admit(&mut gw, &c, &sources, &env),
        Err(FederatedError::Gateway(GatewayError::BadSignature(2)))
    );
    assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    assert!(!c.tier.is_proof_backed_tier());
    assert!(!c.tier.proof_backed());
}

#[test]
fn the_federated_deposit_crosses_as_an_attestation_never_a_stark() {
    let ops: Vec<Op> = (0..3).map(mk).collect();
    let c = find(SOLANA).unwrap();
    let f = deposit(&c, [0x17; 32], 500);
    let env = envelope(&[&ops[0], &ops[1], &ops[2]], &f);

    let wire = env.encode();
    match parse(&wire).expect("airlock admits the attestation") {
        Artifact::Attestation(_) => {}
        Artifact::Stark(_) => panic!("federated tier must never ride a stark"),
    }
}

#[test]
fn assets_are_origin_tagged_per_corridor() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);

    let ltc = find(LITECOIN).unwrap();
    let ltc_sources = independent_sources(LITECOIN, &ops);
    let ltc_fact = deposit(&ltc, [0x18; 32], 500);
    let ltc_receipt = admit(&mut gw, &ltc, &ltc_sources, &envelope(&[&ops[0], &ops[1], &ops[2]], &ltc_fact))
        .expect("litecoin mints");

    let zec = find(ZCASH).unwrap();
    let zec_sources = independent_sources(ZCASH, &ops);
    let zec_fact = deposit(&zec, [0x19; 32], 700);
    let zec_receipt = admit(&mut gw, &zec, &zec_sources, &envelope(&[&ops[0], &ops[1], &ops[2]], &zec_fact))
        .expect("zcash mints");

    assert_eq!(&ltc_receipt.asset_id[0..4], &LITECOIN.to_le_bytes());
    assert_eq!(&zec_receipt.asset_id[0..4], &ZCASH.to_le_bytes());
    assert_ne!(ltc_receipt.asset_id, zec_receipt.asset_id);
}

#[test]
fn caps_are_enforced_in_base_units_never_usd() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);
    let c = find(SOLANA).unwrap();
    gw.register_asset_cap(c.origin_asset.0, 1_000);
    let sources = independent_sources(SOLANA, &ops);

    let first = deposit(&c, [0x1a; 32], 600);
    admit(&mut gw, &c, &sources, &envelope(&[&ops[0], &ops[1], &ops[2]], &first))
        .expect("first mint under the base-unit cap");
    assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 600);

    let over = deposit(&c, [0x1b; 32], 600);
    assert_eq!(
        admit(&mut gw, &c, &sources, &envelope(&[&ops[0], &ops[1], &ops[2]], &over)),
        Err(FederatedError::Gateway(GatewayError::AssetCapExceeded {
            minted: 600,
            cap: 1_000,
            add: 600
        }))
    );
    assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 600);
}

#[test]
fn each_corridor_watches_its_own_independent_source() {
    let ops: Vec<Op> = (0..4).map(mk).collect();
    let mut gw = gateway(&ops, 3);

    let sol = find(SOLANA).unwrap();
    let trx = find(TRON).unwrap();
    let sol_sources = independent_sources(SOLANA, &ops);
    let trx_sources = independent_sources(TRON, &ops);

    assert_ne!(
        sol_sources.endpoint(SOLANA, 0),
        trx_sources.endpoint(TRON, 0)
    );

    let sol_fact = deposit(&sol, [0x1c; 32], 500);
    let trx_fact = deposit(&trx, [0x1d; 32], 400);

    admit(&mut gw, &sol, &sol_sources, &envelope(&[&ops[0], &ops[1], &ops[2]], &sol_fact))
        .expect("solana corridor mints from its own source");
    admit(&mut gw, &trx, &trx_sources, &envelope(&[&ops[0], &ops[1], &ops[2]], &trx_fact))
        .expect("tron corridor mints from its own source");

    assert_eq!(gw.minted_of_asset(&sol.origin_asset.0), 500);
    assert_eq!(gw.minted_of_asset(&trx.origin_asset.0), 400);
}

#[test]
fn bnb_chain_polygon_and_avalanche_keep_their_existing_canonical_ids() {
    assert_eq!(BNB_CHAIN, 3);
    assert_eq!(POLYGON, 4);
    assert_eq!(AVALANCHE, 5);
    for (id, name) in [
        (BNB_CHAIN, "BNB Chain"),
        (POLYGON, "Polygon"),
        (AVALANCHE, "Avalanche"),
    ] {
        let c = find(id).expect("the corridor is registered under its existing id");
        assert_eq!(c.name, name);
        assert_eq!(c.tier, Tier::Federated);
        assert_eq!(c.grade, TrustGrade::TrustedRelayer);
    }
}

#[test]
fn a_distinct_signer_quorum_mints_for_bnb_chain_polygon_and_avalanche() {
    for id in [BNB_CHAIN, POLYGON, AVALANCHE] {
        let ops: Vec<Op> = (0..4).map(mk).collect();
        let mut gw = gateway(&ops, 3);
        let sources = independent_sources(id, &ops);
        let c = find(id).unwrap();
        let f = deposit(&c, [id as u8; 32], 500);
        let env = envelope(&[&ops[0], &ops[1], &ops[2]], &f);

        let receipt = admit(&mut gw, &c, &sources, &env)
            .unwrap_or_else(|e| panic!("{} independent quorum mints, got {:?}", c.name, e));
        assert_eq!(receipt.amount, 500);
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 500);
    }
}

#[test]
fn a_sub_quorum_does_not_mint_for_bnb_chain_polygon_and_avalanche() {
    for id in [BNB_CHAIN, POLYGON, AVALANCHE] {
        let ops: Vec<Op> = (0..4).map(mk).collect();
        let mut gw = gateway(&ops, 3);
        let sources = independent_sources(id, &ops);
        let c = find(id).unwrap();
        let f = deposit(&c, [0x60 + id as u8; 32], 500);
        let env = envelope(&[&ops[0], &ops[1]], &f);

        assert_eq!(
            admit(&mut gw, &c, &sources, &env),
            Err(FederatedError::Gateway(GatewayError::BelowThreshold { got: 2, need: 3 })),
            "{} must refuse a sub quorum",
            c.name
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }
}

#[test]
fn a_correlated_source_quorum_is_refused_for_bnb_chain_polygon_and_avalanche() {
    for id in [BNB_CHAIN, POLYGON, AVALANCHE] {
        let ops: Vec<Op> = (0..4).map(mk).collect();
        let mut gw = gateway(&ops, 3);
        let mut sources = SourceRegistry::new();
        sources.declare(id, ops[0].id, ep(0xaa));
        sources.declare(id, ops[1].id, ep(0xaa));
        sources.declare(id, ops[2].id, ep(0xcc));
        let c = find(id).unwrap();
        let f = deposit(&c, [0x70 + id as u8; 32], 500);
        let env = envelope(&[&ops[0], &ops[1], &ops[2]], &f);

        assert_eq!(
            admit(&mut gw, &c, &sources, &env),
            Err(FederatedError::CorrelatedSources { independent: 2, signers: 3 }),
            "{} must refuse a correlated quorum before any mint",
            c.name
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }
}
