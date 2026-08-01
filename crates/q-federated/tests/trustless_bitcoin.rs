// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
use q_federated::corridors::{origin_tag, Tier, TrustGrade};
use q_federated::{admit_bitcoin_trustless, install, Corridor, TrustlessError, SOLANA};
use q_gateway::{Gateway, OperatorSet};
use qlc_bitcoin::params::Network;
use qlc_bitcoin::tx::Transaction;
use qlc_bitcoin::{
    verify_chain, verify_trustless_deposit, BlockHeader, Checkpoint, NetworkParams, TrustlessDeposit,
    U256,
};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const BITCOIN_CHAIN: u32 = 2;
const DEST: u32 = 9000;

const EASY: NetworkParams = NetworkParams {
    network: Network::Bitcoin,
    name: "Crafted",
    magic: [0xfa, 0xbf, 0xb5, 0xda],
    pow_limit_bits: 0x207f_ffff,
    target_timespan: 1_209_600,
    target_spacing: 600,
    confirmation_depth: 1,
};

fn p2pkh(hash160: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&hash160);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn op_return(recipient: [u8; 32]) -> Vec<u8> {
    let mut s = vec![0x6a, 0x20];
    s.extend_from_slice(&recipient);
    s
}

fn raw_deposit_tx(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&2u32.to_le_bytes());
    out.push(0x01);
    out.extend_from_slice(&[0u8; 36]);
    out.push(0x00);
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.push(outputs.len() as u8);
    for (value, script) in outputs {
        out.extend_from_slice(&value.to_le_bytes());
        out.push(script.len() as u8);
        out.extend_from_slice(script);
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn mined_block(txid: [u8; 32]) -> BlockHeader {
    let mut header = BlockHeader {
        version: 1,
        prev_block: [0u8; 32],
        merkle_root: txid,
        timestamp: 1_700_000_000,
        bits: EASY.pow_limit_bits,
        nonce: 0,
    };
    while !header.meets_pow() {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

fn bitcoin_corridor() -> Corridor {
    Corridor {
        chain_id: BITCOIN_CHAIN,
        name: "Bitcoin",
        tier: Tier::ProofBacked,
        grade: TrustGrade::Trustless,
        confirmation_depth: 1,
        origin_asset: origin_tag(BITCOIN_CHAIN),
        cap_base_units: 1_000_000_000,
        active: true,
    }
}

fn prove_crafted_deposit(bridge: &[u8], recipient: [u8; 32], amount: u64) -> (TrustlessDeposit, Vec<u8>) {
    let raw = raw_deposit_tx(&[(amount, bridge.to_vec()), (0, op_return(recipient))]);
    let txid = Transaction::parse(&raw).unwrap().txid();
    let chain = verify_chain(&[mined_block(txid)], 0, &EASY).unwrap();
    let checkpoint = Checkpoint {
        height: chain.start_height,
        hash: chain.header_at(chain.start_height).unwrap().block_hash(),
        min_work: U256::ZERO,
    };
    let proven =
        verify_trustless_deposit(&chain, &EASY, &checkpoint, 0, &[], &raw, bridge).unwrap();
    (proven, raw)
}

fn bitcoin_fact(c: &Corridor, proven: &TrustlessDeposit) -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: c.chain_id,
        dest_chain: DEST,
        route_id: 1,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(proven.txid),
        asset_id: AssetId(c.origin_asset.0),
        amount: proven.amount,
        recipient: Recipient(proven.recipient),
        finality_depth: 1,
        observed_height: 800_000,
        expiry_height: 900_000,
    }
}

struct Op {
    id: u32,
    pk: PublicKey,
    sk: SecretKey,
}

fn mk(id: u32) -> Op {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0x5e;
    let (pk, sk) = ml_dsa::keygen(&seed);
    Op { id, pk, sk }
}

fn attest(op: &Op, f: &BridgeFact) -> SignerSig {
    let sig = ml_dsa::sign(&op.sk, &f.attest_preimage(DEST_ID), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
    SignerSig {
        operator_id: op.id,
        signature: sig.to_vec(),
    }
}

fn gateway_with_bitcoin_asset() -> Gateway {
    let ops: Vec<Op> = (0..3).map(mk).collect();
    let mut set = OperatorSet::new(3);
    for op in &ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(DEST, DEST_ID, set, 1_000_000_000_000);
    install(&mut gw);
    gw.register_asset_cap(origin_tag(BITCOIN_CHAIN).0, 1_000_000_000);
    gw
}

#[test]
fn a_crafted_bitcoin_deposit_proves_and_clears_the_trustless_gate() {
    let c = bitcoin_corridor();
    let mut gw = gateway_with_bitcoin_asset();
    let bridge = p2pkh([0x11; 20]);
    let recipient = [0x42u8; 32];
    let (proven, _raw) = prove_crafted_deposit(&bridge, recipient, 250_000);
    let f = bitcoin_fact(&c, &proven);

    let mint = admit_bitcoin_trustless(&mut gw, &c, &proven, &f).expect("proven deposit clears the gate");
    assert_eq!(mint.amount, 250_000);
    assert_eq!(mint.recipient, recipient);
    assert_eq!(mint.source_ref, proven.txid);
    assert_eq!(mint.source_chain, BITCOIN_CHAIN);
    assert_eq!(mint.asset_id, c.origin_asset.0);
}

#[test]
fn a_fact_that_overstates_a_proven_deposit_is_refused() {
    let c = bitcoin_corridor();
    let mut gw = gateway_with_bitcoin_asset();
    let bridge = p2pkh([0x11; 20]);
    let recipient = [0x42u8; 32];
    let (proven, _raw) = prove_crafted_deposit(&bridge, recipient, 250_000);
    let mut f = bitcoin_fact(&c, &proven);
    f.amount = 5_000_000;

    assert_eq!(
        admit_bitcoin_trustless(&mut gw, &c, &proven, &f),
        Err(TrustlessError::AmountMismatch {
            proven: 250_000,
            fact: 5_000_000
        })
    );
}

#[test]
fn a_source_reference_is_bound_per_corridor_and_a_same_corridor_replay_is_still_refused() {
    let c = bitcoin_corridor();
    let mut gw = gateway_with_bitcoin_asset();
    let bridge = p2pkh([0x11; 20]);
    let recipient = [0x42u8; 32];
    let (proven, _raw) = prove_crafted_deposit(&bridge, recipient, 250_000);

    let ops: Vec<Op> = (0..3).map(mk).collect();
    let solana = origin_tag(SOLANA).0;
    let spent = BridgeFact {
        version: FACT_VERSION,
        source_chain: SOLANA,
        dest_chain: DEST,
        route_id: 7,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(proven.txid),
        asset_id: AssetId(solana),
        amount: 10,
        recipient: Recipient([0x9u8; 32]),
        finality_depth: 40,
        observed_height: 800_000,
        expiry_height: 900_000,
    };
    let env = AttestationEnvelope {
        fact: spent.clone(),
        signatures: vec![attest(&ops[0], &spent), attest(&ops[1], &spent), attest(&ops[2], &spent)],
    };
    gw.process_deposit(&env).expect("the solana mint consumes the reference on its own corridor");
    assert!(gw.is_reference_used_on(SOLANA, &proven.txid));

    let f = bitcoin_fact(&c, &proven);
    admit_bitcoin_trustless(&mut gw, &c, &proven, &f)
        .expect("a cross-corridor reference collision is not a replay");
    assert!(gw.is_reference_used_on(c.chain_id, &proven.txid));

    assert_eq!(
        admit_bitcoin_trustless(&mut gw, &c, &proven, &f),
        Err(TrustlessError::ReplayedReference)
    );
}
