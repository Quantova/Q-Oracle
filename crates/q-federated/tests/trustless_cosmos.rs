// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
use q_federated::corridors::{origin_tag, Tier, TrustGrade};
use q_federated::{admit_cosmos_trustless, install, Corridor, TrustlessError, SOLANA};
use q_gateway::{Gateway, OperatorSet};
use qlc_cosmos::chain::COSMOS_HUB;
use qlc_cosmos::commit::{BlockIdFlag, Commit, CommitSig, Header};
use qlc_cosmos::ed25519::{public_key_from_seed, sign};
use qlc_cosmos::proof::{encode_deposit_value, ExistenceProof, InnerOp, LeafOp};
use qlc_cosmos::proto::{vote_sign_bytes, BlockId, CanonicalVote, Timestamp, PRECOMMIT_TYPE};
use qlc_cosmos::validator::{ValidatorInfo, ValidatorSet};
use qlc_cosmos::{verify_trustless_deposit, TrustlessDeposit};
use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

const DEST_ID: u64 = 0x0000_002a_0000_2328;

const DEST: u32 = 9000;
const COSMOS_ASSET: [u8; 16] = *b"qATOM.atom\0\0\0\0\0\0";

struct Keyed {
    seed: [u8; 32],
    info: ValidatorInfo,
}

fn keyed(byte: u8, power: u64) -> Keyed {
    let seed = [byte; 32];
    Keyed {
        seed,
        info: ValidatorInfo {
            pubkey: public_key_from_seed(&seed),
            voting_power: power,
        },
    }
}

fn deposit_proof(recipient: [u8; 32], asset: [u8; 16], amount: u128) -> ExistenceProof {
    ExistenceProof {
        key: b"bridge/deposits/0x1a2b".to_vec(),
        value: encode_deposit_value(&recipient, &asset, amount),
        leaf: LeafOp {
            prefix: vec![0x00, 0x02, 0x00],
        },
        path: vec![
            InnerOp {
                prefix: vec![0x01, 0x0a],
                suffix: vec![0x1b, 0x2c],
            },
            InnerOp {
                prefix: vec![0x01],
                suffix: vec![0x33, 0x44, 0x55],
            },
        ],
        store: None,
    }
}

fn signed_scene(
    recipient: [u8; 32],
    asset: [u8; 16],
    amount: u128,
) -> (Header, Commit, ValidatorSet, ExistenceProof) {
    let vs = [keyed(1, 25), keyed(2, 25), keyed(3, 25), keyed(4, 25)];
    let set = ValidatorSet::new(vs.iter().map(|k| k.info).collect());
    let (app_hash, proof) =
        qlc_cosmos::proof::wrap_store_layer(deposit_proof(recipient, asset, amount), b"bridge");

    let header = Header {
        version_block: 11,
        version_app: 0,
        chain_id: COSMOS_HUB.chain_id.to_string(),
        height: 18_500_000,
        time: Timestamp {
            seconds: 1_700_000_000,
            nanos: 9,
        },
        last_block_id: BlockId {
            hash: vec![0xaa; 32],
            part_total: 1,
            part_hash: vec![0xbb; 32],
        },
        last_commit_hash: vec![0x01; 32],
        data_hash: vec![0x02; 32],
        validators_hash: set.hash().to_vec(),
        next_validators_hash: set.hash().to_vec(),
        consensus_hash: vec![0x03; 32],
        app_hash: app_hash.to_vec(),
        last_results_hash: vec![0x05; 32],
        evidence_hash: vec![0x06; 32],
        proposer_address: set.validators[0].address().to_vec(),
    };

    let block_id = BlockId {
        hash: header.hash().to_vec(),
        part_total: 1,
        part_hash: vec![0xcc; 32],
    };
    let mut signatures = Vec::new();
    for k in &vs {
        let timestamp = Timestamp {
            seconds: 1_700_000_001,
            nanos: k.seed[0] as i32,
        };
        let vote = CanonicalVote {
            vote_type: PRECOMMIT_TYPE,
            height: header.height,
            round: 0,
            block_id: block_id.clone(),
            timestamp,
            chain_id: COSMOS_HUB.chain_id.to_string(),
        };
        signatures.push(CommitSig {
            flag: BlockIdFlag::Commit,
            validator_address: k.info.address(),
            timestamp,
            signature: sign(&k.seed, &vote_sign_bytes(&vote)).to_vec(),
        });
    }
    let commit = Commit {
        height: header.height,
        round: 0,
        block_id,
        signatures,
    };
    (header, commit, set, proof)
}

fn prove_cosmos_deposit(recipient: [u8; 32], asset: [u8; 16], amount: u128) -> TrustlessDeposit {
    let (header, commit, set, proof) = signed_scene(recipient, asset, amount);
    let trusted = qlc_cosmos::light::TrustedState {
        height: 0,
        time: Timestamp { seconds: 1_700_000_000 - 3600, nanos: 0 },
        header_hash: [0u8; 32],
        validators: set.clone(),
        next_validators_hash: set.hash().to_vec(),
    };
    verify_trustless_deposit(&COSMOS_HUB, &trusted, &header, &commit, &set, &proof, header.time).unwrap()
}

fn cosmos_corridor() -> Corridor {
    Corridor {
        chain_id: COSMOS_HUB.corridor_id,
        name: "Cosmos Hub",
        tier: Tier::ProofBacked,
        grade: TrustGrade::Trustless,
        confirmation_depth: COSMOS_HUB.confirmation_depth,
        origin_asset: origin_tag(COSMOS_HUB.corridor_id),
        cap_base_units: 1_000_000_000,
        active: true,
    }
}

fn cosmos_fact(c: &Corridor, proven: &TrustlessDeposit, asset: [u8; 16]) -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: c.chain_id,
        dest_chain: DEST,
        route_id: 1,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(proven.source_ref()),
        asset_id: AssetId(asset),
        amount: proven.amount(),
        recipient: Recipient(proven.recipient()),
        finality_depth: c.confirmation_depth,
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

fn gateway_with_cosmos_asset() -> Gateway {
    let ops: Vec<Op> = (0..3).map(mk).collect();
    let mut set = OperatorSet::new(3);
    for op in &ops {
        set.register(op.id, op.pk);
    }
    let mut gw = Gateway::new(DEST, DEST_ID, set, 1_000_000_000_000);
    install(&mut gw);
    gw.register_asset_cap(COSMOS_ASSET, 1_000_000_000);
    gw
}

#[test]
fn a_signed_cosmos_deposit_proves_and_clears_the_trustless_gate() {
    let c = cosmos_corridor();
    let mut gw = gateway_with_cosmos_asset();
    let recipient = [0x51u8; 32];
    let proven = prove_cosmos_deposit(recipient, COSMOS_ASSET, 7_500_000);
    let f = cosmos_fact(&c, &proven, COSMOS_ASSET);

    let mint = admit_cosmos_trustless(&mut gw, &c, &proven, &f).expect("proven deposit clears the gate");
    assert_eq!(mint.amount, 7_500_000);
    assert_eq!(mint.recipient, recipient);
    assert_eq!(mint.source_ref, proven.source_ref());
    assert_eq!(mint.source_chain, COSMOS_HUB.corridor_id);
    assert_eq!(mint.asset_id, COSMOS_ASSET);
}

#[test]
fn a_fact_that_overstates_a_proven_cosmos_deposit_is_refused() {
    let c = cosmos_corridor();
    let mut gw = gateway_with_cosmos_asset();
    let recipient = [0x51u8; 32];
    let proven = prove_cosmos_deposit(recipient, COSMOS_ASSET, 7_500_000);
    let mut f = cosmos_fact(&c, &proven, COSMOS_ASSET);
    f.amount = 9_000_000;

    assert_eq!(
        admit_cosmos_trustless(&mut gw, &c, &proven, &f),
        Err(TrustlessError::AmountMismatch {
            proven: 7_500_000,
            fact: 9_000_000
        })
    );
}

#[test]
fn a_source_reference_is_bound_per_corridor_and_a_same_corridor_replay_is_still_refused() {
    let c = cosmos_corridor();
    let mut gw = gateway_with_cosmos_asset();
    let recipient = [0x51u8; 32];
    let proven = prove_cosmos_deposit(recipient, COSMOS_ASSET, 7_500_000);

    let ops: Vec<Op> = (0..3).map(mk).collect();
    let solana = origin_tag(SOLANA).0;
    let spent = BridgeFact {
        version: FACT_VERSION,
        source_chain: SOLANA,
        dest_chain: DEST,
        route_id: 7,
        direction: Direction::Deposit,
        nonce: 1,
        source_ref: SourceRef(proven.source_ref()),
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
    assert!(gw.is_reference_used_on(SOLANA, &proven.source_ref()));

    let f = cosmos_fact(&c, &proven, COSMOS_ASSET);
    admit_cosmos_trustless(&mut gw, &c, &proven, &f)
        .expect("a cross-corridor reference collision is not a replay");
    assert!(gw.is_reference_used_on(c.chain_id, &proven.source_ref()));

    assert_eq!(
        admit_cosmos_trustless(&mut gw, &c, &proven, &f),
        Err(TrustlessError::ReplayedReference)
    );
}
