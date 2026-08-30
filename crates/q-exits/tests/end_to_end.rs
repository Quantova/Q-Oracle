// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    BitcoinPayoutWatcher, BitcoinReleaseProof, DeskConfig, ExitDesk, ExitError, ExitState,
    MemberConfig, ProofOfBurn, QuantovaAnchor,
};

use qlc_bitcoin::{
    double_sha256, BlockHeader, Checkpoint, MerkleStep, NetworkParams, BITCOIN, U256,
};

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Block, Certificate, Envelope, Parent};
use qtv_block::{event_root, prove_inclusion, Header};
use qtv_codec::{to_bytes, Encoder};
use qtv_sampler::beacon::Beacon;

const CHAIN_ID: u64 = 9000;
const HEIGHT: u64 = 4_200_000;
const SLOT: u64 = 0;
const BUDGET: u64 = 300;
const TAU: u64 = 3;
const CORRIDOR: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];
const HOLDER: [u8; 32] = [0x33; 32];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 500;
const BURN_REF: [u8; 32] = [0x11; 32];

const SECURE_BPS: u32 = 15_000;
const PREMIUM_BPS: u32 = 10_000;
const REQUIRED: u128 = 750;
const USER_PAYOUT: u128 = 500;

fn attesters() -> [Attester; 3] {
    [
        Attester::new(1, 100),
        Attester::new(2, 100),
        Attester::new(3, 100),
    ]
}

fn committee(members: &[Attester]) -> qtv_attest::CommitteeCommitment {
    let refs: Vec<&Attester> = members.iter().collect();
    qtv_attest::CommitteeCommitment::from_attesters_with_budget(SLOT, &refs, BUDGET)
}

fn member_configs(members: &[Attester]) -> Vec<MemberConfig> {
    members
        .iter()
        .map(|a| MemberConfig {
            id: a.id(),
            weight: a.weight(),
            root_digest: a.root().digest,
            root_slots: a.root().slots,
            attest_pk: a.attest_public_key().to_vec(),
        })
        .collect()
}

fn burn_leaf(amount: u128, asset: [u8; 16], destination: [u8; 32], burn_ref: [u8; 32]) -> Vec<u8> {
    let mut data = Encoder::new();
    data.put_bytes(&asset);
    data.put_bytes(&HOLDER);
    data.put_u128(amount);
    data.put_bytes(&destination);
    data.put_u64(CHAIN_ID);
    data.put_u64(0);
    data.put_u64(1);
    data.put_bytes(&burn_ref);

    let mut leaf = Encoder::new();
    leaf.put_bytes(b"qtv/native");
    leaf.put_bytes(b"QBBN");
    leaf.put_bytes(&data.into_bytes());
    leaf.into_bytes()
}

fn header_for(leaves: &[Vec<u8>]) -> Header {
    Header::new(
        HEIGHT,
        [0u8; 32],
        [0x01; 32],
        [0u8; 32],
        event_root(leaves),
        [0u8; 32],
        "qtv1proposer".to_string(),
        1,
    )
}

fn finalized_certificate(members: &[Attester], block: Block, beacon: &Beacon) -> Certificate {
    let commitment = committee(members);
    let atts: Vec<_> = members
        .iter()
        .map(|a| {
            a.attest(
                CHAIN_ID,
                HEIGHT,
                SLOT,
                0,
                commitment.digest(),
                block,
                beacon,
            )
        })
        .collect();
    aggregate(
        CHAIN_ID,
        HEIGHT,
        SLOT,
        block,
        &commitment,
        beacon,
        &atts,
        TAU,
    )
    .expect("a full committee finalizes")
}

fn anchor(members: &[Attester], beacon: &Beacon) -> QuantovaAnchor {
    QuantovaAnchor::from_config(
        CHAIN_ID,
        TAU,
        SLOT,
        BUDGET,
        *beacon.seed(),
        member_configs(members),
    )
    .expect("the pinned anchor is well formed")
}

fn config() -> DeskConfig {
    DeskConfig {
        corridor: CORRIDOR,
        dest_chain: CHAIN_ID,
        secure_bps: SECURE_BPS,
        premium_bps: PREMIUM_BPS,
        window: 100,
    }
}

fn proof_of(members: &[Attester], beacon: &Beacon, burn_ref: [u8; 32]) -> ProofOfBurn {
    let leaves = vec![
        vec![0xde; 8],
        burn_leaf(AMOUNT, ASSET, BENEFICIARY, burn_ref),
        vec![0xad; 12],
    ];
    let burn_index = 1;
    let header = header_for(&leaves);
    let block = Block::new(HEIGHT, header.hash(), Parent::Genesis);
    ProofOfBurn {
        header_bytes: to_bytes(&header),
        certificate: finalized_certificate(members, block, beacon),
        leaf: leaves[burn_index].clone(),
        inclusion: prove_inclusion(&leaves, burn_index).unwrap(),
    }
}

fn desk() -> ExitDesk {
    let members = attesters();
    let beacon = Beacon::genesis();
    ExitDesk::new(config(), anchor(&members, &beacon)).unwrap()
}

const EASY: NetworkParams = NetworkParams {
    network: BITCOIN.network,
    name: BITCOIN.name,
    magic: BITCOIN.magic,
    pow_limit_bits: 0x207f_ffff,
    target_timespan: BITCOIN.target_timespan,
    target_spacing: BITCOIN.target_spacing,
    confirmation_depth: BITCOIN.confirmation_depth,
    requires_pinned_checkpoint: false,
};

fn put_varint(value: u64, out: &mut Vec<u8>) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn release_tx(beneficiary: &[u8; 32], amount: u64, burn_ref: &[u8; 32]) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&1u32.to_le_bytes());
    put_varint(1, &mut tx);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    put_varint(0, &mut tx);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    put_varint(2, &mut tx);
    tx.extend_from_slice(&amount.to_le_bytes());
    let mut payout_script = vec![0x51u8, 0x20];
    payout_script.extend_from_slice(beneficiary);
    put_varint(payout_script.len() as u64, &mut tx);
    tx.extend_from_slice(&payout_script);
    tx.extend_from_slice(&0u64.to_le_bytes());
    let mut reference_script = vec![0x6au8, 0x20];
    reference_script.extend_from_slice(burn_ref);
    put_varint(reference_script.len() as u64, &mut tx);
    tx.extend_from_slice(&reference_script);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

fn mine(mut header: BlockHeader) -> BlockHeader {
    while !header.meets_pow() {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

fn release_around(raw_tx: Vec<u8>) -> BitcoinReleaseProof {
    let coinbase = [0xcb; 32];
    let release_txid = double_sha256(&raw_tx);
    let mut leaves = Vec::new();
    leaves.extend_from_slice(&coinbase);
    leaves.extend_from_slice(&release_txid);
    let root = double_sha256(&leaves);
    let branch = vec![MerkleStep {
        hash: coinbase,
        sibling_on_left: true,
    }];

    let mut headers = Vec::new();
    let first = mine(BlockHeader {
        version: 1,
        prev_block: [0u8; 32],
        merkle_root: root,
        timestamp: 1_700_000_000,
        bits: 0x207f_ffff,
        nonce: 0,
    });
    headers.push(first);
    for i in 1..BITCOIN.confirmation_depth {
        let prev = headers[headers.len() - 1].block_hash();
        let next = mine(BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: [0x33; 32],
            timestamp: 1_700_000_000 + i,
            bits: 0x207f_ffff,
            nonce: 0,
        });
        headers.push(next);
    }

    BitcoinReleaseProof {
        headers,
        start_height: 100,
        release_height: 100,
        branch,
        raw_tx,
    }
}

fn bitcoin_watcher(release: BitcoinReleaseProof) -> BitcoinPayoutWatcher {
    let checkpoint = Checkpoint {
        height: release.start_height,
        hash: release.headers[0].block_hash(),
        min_work: U256::ZERO,
    };
    BitcoinPayoutWatcher::new(
        CORRIDOR,
        ASSET,
        EASY,
        checkpoint,
        EASY.confirmation_depth,
        vec![release],
    )
}

#[test]
fn opening_an_exit_locks_the_required_collateral() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();
    assert_eq!(desk.locked_collateral(1), REQUIRED);
    assert_eq!(desk.free_collateral(1), 2_000 - REQUIRED);
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Pending);
    assert_eq!(desk.exit(id).unwrap().statement.amount, AMOUNT);
    assert_eq!(desk.exit(id).unwrap().statement.holder, HOLDER);
    assert_eq!(desk.exit(id).unwrap().statement.destination, BENEFICIARY);
    assert!(desk.is_consumed(&BURN_REF));
}

#[test]
fn a_thin_vault_is_refused_and_does_not_consume_the_burn() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, REQUIRED - 1);
    assert_eq!(
        desk.open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10),
        Err(ExitError::ThinVault {
            have: REQUIRED - 1,
            need: REQUIRED
        })
    );
    assert!(!desk.is_consumed(&BURN_REF));
}

#[test]
fn an_unknown_vault_is_refused() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    assert_eq!(
        desk.open_exit(&proof_of(&members, &beacon, BURN_REF), 7, 10),
        Err(ExitError::UnknownVault(7))
    );
    assert!(!desk.is_consumed(&BURN_REF));
}

#[test]
fn settling_within_the_window_against_a_bitcoin_payout_releases_the_collateral() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();

    let watcher = bitcoin_watcher(release_around(release_tx(
        &BENEFICIARY,
        AMOUNT as u64,
        &BURN_REF,
    )));
    let release = desk.settle(id, &watcher, 60).unwrap();
    assert_eq!(release.released, REQUIRED);
    assert_eq!(desk.locked_collateral(1), 0);
    assert_eq!(desk.free_collateral(1), 2_000);
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Settled);
}

#[test]
fn settling_after_the_window_is_refused() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();
    let watcher = bitcoin_watcher(release_around(release_tx(
        &BENEFICIARY,
        AMOUNT as u64,
        &BURN_REF,
    )));
    assert_eq!(
        desk.settle(id, &watcher, 200),
        Err(ExitError::WindowExpired {
            now: 200,
            deadline: 110
        })
    );
}

#[test]
fn settle_refuses_when_the_watcher_cannot_prove_a_covering_payout() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();

    let watcher = bitcoin_watcher(release_around(release_tx(
        &[0x66; 32],
        AMOUNT as u64,
        &BURN_REF,
    )));
    assert_eq!(
        desk.settle(id, &watcher, 60),
        Err(ExitError::PayoutUnproven)
    );
    assert_eq!(
        desk.locked_collateral(1),
        REQUIRED,
        "custody stays locked when no anchored payout covers the exit"
    );
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Pending);
}

#[test]
fn a_burn_for_another_destination_chain_cannot_open_an_exit() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut cfg = config();
    cfg.dest_chain = CHAIN_ID + 1;
    let mut desk = ExitDesk::new(cfg, anchor(&members, &beacon)).unwrap();
    desk.register_vault(1, 2_000);
    assert_eq!(
        desk.open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10),
        Err(ExitError::WrongDestination {
            got: CHAIN_ID,
            expected: CHAIN_ID + 1
        })
    );
    assert!(!desk.is_consumed(&BURN_REF));
    assert_eq!(desk.locked_collateral(1), 0);
}

#[test]
fn the_window_elapsing_then_slash_re_mints_one_to_one_to_the_holder() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();

    let outcome = desk.slash(id, 200).unwrap();
    assert_eq!(outcome.user_payout, USER_PAYOUT);
    assert_eq!(
        outcome.user_payout, AMOUNT,
        "the on-chain re-mint equals the value burned with no premium"
    );
    assert_eq!(outcome.remainder, REQUIRED - USER_PAYOUT);
    assert_eq!(
        outcome.holder, HOLDER,
        "the slash refund is owed to the on-chain holder, not the foreign destination"
    );
    assert_eq!(desk.locked_collateral(1), 0);
    assert_eq!(desk.free_collateral(1), 2_000 - REQUIRED);
    assert_eq!(desk.exit(id).unwrap().state, ExitState::Slashed);
}

#[test]
fn the_exit_fact_carries_the_holder_for_credit_and_the_destination_for_payout() {
    use q_exits::{ExitDecision, ExitOutcome};
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();
    let statement = desk.exit(id).unwrap().statement.clone();

    let settle = ExitDecision::settle(&statement, CHAIN_ID as u32);
    assert_eq!(settle.outcome, ExitOutcome::Settle);
    assert_eq!(settle.holder, HOLDER);
    assert_eq!(settle.destination, BENEFICIARY);
    assert_eq!(settle.amount, AMOUNT);

    let slash = ExitDecision::slash(&statement, CHAIN_ID as u32);
    assert_eq!(slash.outcome, ExitOutcome::Slash);
    assert_eq!(
        slash.holder, HOLDER,
        "the on-chain slash fact credits the holder"
    );
    assert_eq!(slash.destination, BENEFICIARY);
    assert_eq!(
        slash.amount, AMOUNT,
        "the slash fact re-mints exactly the burned amount"
    );
}

#[test]
fn slashing_before_the_deadline_is_refused() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();
    assert_eq!(
        desk.slash(id, 100),
        Err(ExitError::WindowOpen {
            now: 100,
            deadline: 110
        })
    );
    assert_eq!(desk.locked_collateral(1), REQUIRED);
}

#[test]
fn a_replayed_burn_opens_no_second_exit() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 5_000);
    let proof = proof_of(&members, &beacon, BURN_REF);
    desk.open_exit(&proof, 1, 10).unwrap();
    assert_eq!(desk.open_exit(&proof, 1, 10), Err(ExitError::ReplayedExit));
    assert_eq!(desk.locked_collateral(1), REQUIRED);
}

#[test]
fn a_forged_header_cannot_open_an_exit() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let mut proof = proof_of(&members, &beacon, BURN_REF);
    proof.header_bytes[45] ^= 0xff;
    assert_eq!(
        desk.open_exit(&proof, 1, 10),
        Err(ExitError::HeaderMismatch)
    );
    assert!(!desk.is_consumed(&BURN_REF));
    assert_eq!(desk.locked_collateral(1), 0);
}

const BURN_REF_B: [u8; 32] = [0x22; 32];

#[test]
fn an_exit_bound_to_one_burn_cannot_settle_against_a_payout_for_another() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, 2_000);
    let id_a = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();

    let payout_for_b = bitcoin_watcher(release_around(release_tx(
        &BENEFICIARY,
        AMOUNT as u64,
        &BURN_REF_B,
    )));
    assert_eq!(
        desk.settle(id_a, &payout_for_b, 60),
        Err(ExitError::PayoutUnproven),
        "a payout naming burn B cannot settle an exit bound to burn A"
    );
    assert_eq!(
        desk.locked_collateral(1),
        REQUIRED,
        "the custody stays locked when the burn does not match"
    );
    assert_eq!(desk.exit(id_a).unwrap().state, ExitState::Pending);

    let payout_for_a = bitcoin_watcher(release_around(release_tx(
        &BENEFICIARY,
        AMOUNT as u64,
        &BURN_REF,
    )));
    let release = desk.settle(id_a, &payout_for_a, 60).unwrap();
    assert_eq!(release.released, REQUIRED);
    assert_eq!(desk.exit(id_a).unwrap().state, ExitState::Settled);
}

#[test]
fn collateral_is_conserved_across_a_settle_and_a_slash() {
    const INITIAL: u128 = 5_000;
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut desk = desk();
    desk.register_vault(1, INITIAL);

    let id_a = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF), 1, 10)
        .unwrap();
    let id_b = desk
        .open_exit(&proof_of(&members, &beacon, BURN_REF_B), 1, 10)
        .unwrap();
    assert_eq!(desk.locked_collateral(1), 2 * REQUIRED);
    assert_eq!(
        desk.free_collateral(1) + desk.locked_collateral(1),
        INITIAL,
        "nothing is seized yet"
    );

    let payout_for_a = bitcoin_watcher(release_around(release_tx(
        &BENEFICIARY,
        AMOUNT as u64,
        &BURN_REF,
    )));
    let release = desk.settle(id_a, &payout_for_a, 60).unwrap();
    assert_eq!(release.released, REQUIRED);
    assert_eq!(
        desk.free_collateral(1) + desk.locked_collateral(1),
        INITIAL,
        "a settle conserves custody"
    );

    let outcome = desk.slash(id_b, 200).unwrap();
    assert_eq!(outcome.user_payout, USER_PAYOUT);
    assert_eq!(
        outcome.user_payout + outcome.remainder,
        REQUIRED,
        "the slash splits exactly the seized collateral"
    );

    let remaining = desk.free_collateral(1) + desk.locked_collateral(1);
    let seized = INITIAL - remaining;
    assert_eq!(
        seized, REQUIRED,
        "only the slashed exit's collateral leaves custody"
    );
    assert_eq!(
        desk.locked_collateral(1),
        0,
        "no collateral is left locked once both exits close"
    );
    assert_eq!(
        remaining + seized,
        INITIAL,
        "free + locked + seized is conserved across both lifecycles"
    );
    assert_eq!(desk.exit(id_a).unwrap().state, ExitState::Settled);
    assert_eq!(desk.exit(id_b).unwrap().state, ExitState::Slashed);
}

#[test]
fn an_unfinalized_burn_cannot_open_an_exit() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let leaves = vec![burn_leaf(AMOUNT, ASSET, BENEFICIARY, BURN_REF)];
    let header = header_for(&leaves);
    let block = Block::new(HEIGHT, header.hash(), Parent::Genesis);
    let commitment = committee(&members);
    let envelope = Envelope::new(HEIGHT, SLOT, block, &commitment);
    let lone = members[0].attest(
        CHAIN_ID,
        HEIGHT,
        SLOT,
        0,
        commitment.digest(),
        block,
        &beacon,
    );
    let thin = Certificate::new(envelope, vec![lone]);
    let proof = ProofOfBurn {
        header_bytes: to_bytes(&header),
        certificate: thin,
        leaf: leaves[0].clone(),
        inclusion: prove_inclusion(&leaves, 0).unwrap(),
    };

    let mut desk = desk();
    desk.register_vault(1, 2_000);
    assert_eq!(desk.open_exit(&proof, 1, 10), Err(ExitError::NotFinalized));
    assert!(!desk.is_consumed(&BURN_REF));
    assert_eq!(desk.locked_collateral(1), 0);
}
