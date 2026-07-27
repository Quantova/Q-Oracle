// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::path::PathBuf;

use q_exits::{
    BurnWatcher, CustodyConfig, ExitConfig, ExitError, FailClosedPayout, FinalizedBlock,
    MemberConfig, MemoryLedger, OperatorAuthorizer, OperatorQuorum, PersistentLedger,
    ProofOfBurn, QuantovaAnchor, QuantovaBurnSource, ReleaseAggregator, ReleaseAuthorization,
    ReleaseDesk, ReleasePipeline, ReplayLedger, ReplayStore, SoftReleaseSigner,
};
use q_exits::ReleaseSigner;

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Block, Certificate, Parent};
use qtv_block::{event_root, Header};
use qtv_codec::{to_bytes, Encoder};
use qtv_crypto::ml_dsa::SEED_BYTES;
use qtv_sampler::beacon::Beacon;

const CHAIN_ID: u64 = 9000;
const HEIGHT: u64 = 4_200_000;
const SLOT: u64 = 0;
const BUDGET: u64 = 300;
const TAU: u64 = 2;
const DEST_CHAIN: u32 = 42;
const VAULT: [u8; 32] = [0x99; 32];
const ASSET: [u8; 16] = [0xa1; 16];
const HOLDER: [u8; 32] = [0x33; 32];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 500;
const BURN_REF: [u8; 32] = [0x11; 32];

fn attesters() -> [Attester; 3] {
    [Attester::new(1, 100), Attester::new(2, 100), Attester::new(3, 100)]
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

fn header_at(height: u64, leaves: &[Vec<u8>]) -> Header {
    Header::new(
        height,
        [0u8; 32],
        [0x01; 32],
        [0u8; 32],
        event_root(leaves),
        [0u8; 32],
        "qtv1proposer".to_string(),
        1,
    )
}

fn finalized_certificate(
    members: &[Attester],
    height: u64,
    block: Block,
    beacon: &Beacon,
) -> Certificate {
    let commitment = committee(members);
    let atts: Vec<_> = members
        .iter()
        .map(|a| a.attest(CHAIN_ID, height, SLOT, 0, block, beacon))
        .collect();
    aggregate(CHAIN_ID, height, SLOT, block, &commitment, beacon, &atts, TAU)
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

fn finalized_block(members: &[Attester], height: u64, beacon: &Beacon, burn: [u8; 32]) -> FinalizedBlock {
    let leaves = vec![
        vec![0xde; 8],
        burn_leaf(AMOUNT, ASSET, BENEFICIARY, burn),
        vec![0xad; 12],
    ];
    let header = header_at(height, &leaves);
    let block = Block::new(height, header.hash(), Parent::Genesis);
    FinalizedBlock {
        header_bytes: to_bytes(&header),
        certificate: finalized_certificate(members, height, block, beacon),
        events: leaves,
    }
}

struct MockNode {
    head: u64,
    blocks: BTreeMap<u64, FinalizedBlock>,
}

impl QuantovaBurnSource for MockNode {
    fn finalized_height(&self) -> Result<u64, q_exits::BurnWatchError> {
        Ok(self.head)
    }

    fn finalized_block(
        &self,
        height: u64,
    ) -> Result<Option<FinalizedBlock>, q_exits::BurnWatchError> {
        Ok(self.blocks.get(&height).map(clone_block))
    }
}

fn clone_block(block: &FinalizedBlock) -> FinalizedBlock {
    FinalizedBlock {
        header_bytes: block.header_bytes.clone(),
        certificate: block.certificate.clone(),
        events: block.events.clone(),
    }
}

fn operator_roster() -> [(u32, [u8; SEED_BYTES]); 3] {
    [1u8, 2, 3].map(|id| (id as u32, [id; SEED_BYTES]))
}

fn quorum(threshold: usize) -> OperatorQuorum {
    let roster: Vec<(u32, Vec<u8>)> = operator_roster()
        .iter()
        .map(|(id, seed)| {
            let signer = SoftReleaseSigner::from_seed(*id, seed);
            (*id, signer.public_key().to_vec())
        })
        .collect();
    OperatorQuorum::from_config(roster, threshold).expect("the quorum is well formed")
}

fn custody(threshold: usize) -> CustodyConfig {
    CustodyConfig::new(VAULT, DEST_CHAIN, quorum(threshold)).expect("custody is configured")
}

fn authorization_for(
    proof: &ProofOfBurn,
    members: &[Attester],
    beacon: &Beacon,
    signers: usize,
    ledger: &dyn ReplayLedger,
) -> ReleaseAuthorization {
    let mut agg = ReleaseAggregator::new(signers);
    for (id, seed) in operator_roster().iter().take(signers) {
        let signer = SoftReleaseSigner::from_seed(*id, seed);
        let authorizer =
            OperatorAuthorizer::new(anchor(members, beacon), signer, VAULT, DEST_CHAIN).unwrap();
        let (terms, sig) = authorizer.authorize(proof, ledger).expect("operator signs");
        agg.add(&terms, sig).expect("terms agree");
    }
    agg.try_finalize().expect("the aggregator reaches its own threshold")
}

#[test]
fn the_watcher_surfaces_a_finalized_burn_and_skips_a_non_finalized_one() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(&members, HEIGHT, &beacon, BURN_REF));
    blocks.insert(HEIGHT + 1, finalized_block(&members, HEIGHT + 1, &beacon, [0x22; 32]));
    let node = MockNode { head: HEIGHT, blocks };

    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let surfaced = watcher.poll(&node).expect("the poll succeeds");
    assert_eq!(surfaced.len(), 1, "only the finalized burn is surfaced");
    assert_eq!(watcher.scanned_through(), HEIGHT);

    let anchor = anchor(&members, &beacon);
    let burn = surfaced[0].verify(&anchor).expect("the assembled proof verifies");
    assert_eq!(burn.burn_ref, BURN_REF);
    assert_eq!(burn.amount, AMOUNT);
    assert_eq!(burn.finalized_height, HEIGHT);

    let again = watcher.poll(&node).expect("a second poll succeeds");
    assert!(again.is_empty(), "the non-finalized height is never scanned");
}

#[test]
fn an_assembled_proof_is_accepted_by_the_desk_end_to_end() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(&members, HEIGHT, &beacon, BURN_REF));
    let node = MockNode { head: HEIGHT, blocks };

    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&node).expect("the poll succeeds");
    let proof = &proofs[0];

    let mut desk = ReleaseDesk::new(anchor(&members, &beacon), custody(2));
    let ledger = MemoryLedger::new();
    let authorization = authorization_for(proof, &members, &beacon, 2, &ledger);

    let release = desk.authorize_release(proof, &authorization).expect("the desk releases");
    assert_eq!(release.burn_ref, BURN_REF);
    assert_eq!(release.amount, AMOUNT);
    assert_eq!(release.beneficiary, BENEFICIARY);
    assert!(desk.is_released(&BURN_REF));
}

#[test]
fn a_quorum_authorizes_at_threshold_and_refuses_below_it() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(&members, HEIGHT, &beacon, BURN_REF));
    let node = MockNode { head: HEIGHT, blocks };
    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&node).unwrap();
    let proof = &proofs[0];
    let ledger = MemoryLedger::new();

    let mut desk_at = ReleaseDesk::new(anchor(&members, &beacon), custody(2));
    let at_threshold = authorization_for(proof, &members, &beacon, 2, &ledger);
    assert!(desk_at.authorize_release(proof, &at_threshold).is_ok());

    let mut desk_below = ReleaseDesk::new(anchor(&members, &beacon), custody(2));
    let below = authorization_for(proof, &members, &beacon, 1, &ledger);
    assert_eq!(
        desk_below.authorize_release(proof, &below),
        Err(ExitError::BelowThreshold { have: 1, need: 2 })
    );
    assert!(!desk_below.is_released(&BURN_REF));
}

fn temp_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("q-oracle-exit-restart-{tag}-{}-{nanos}.led", std::process::id()));
    path
}

#[test]
fn the_persisted_ledger_refuses_a_replayed_burn_across_a_restart() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(&members, HEIGHT, &beacon, BURN_REF));
    let node = MockNode { head: HEIGHT, blocks };
    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&node).unwrap();
    let proof = &proofs[0];

    let mem = MemoryLedger::new();
    let authorization = authorization_for(proof, &members, &beacon, 2, &mem);

    let path = temp_path("replay");
    {
        let ledger = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
        let mut desk =
            ReleaseDesk::with_ledger(anchor(&members, &beacon), custody(2), Box::new(ledger));
        let release = desk.authorize_release(proof, &authorization).expect("first release");
        assert_eq!(release.burn_ref, BURN_REF);
    }

    let reloaded = PersistentLedger::open(ReplayStore::new(path.clone())).unwrap();
    assert!(reloaded.is_released(&BURN_REF), "the burn_ref survives the restart");
    let mut desk =
        ReleaseDesk::with_ledger(anchor(&members, &beacon), custody(2), Box::new(reloaded));
    assert_eq!(
        desk.authorize_release(proof, &authorization),
        Err(ExitError::ReplayedBurn)
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn a_gated_off_pipeline_moves_nothing_and_records_nothing() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(&members, HEIGHT, &beacon, BURN_REF));
    let node = MockNode { head: HEIGHT, blocks };
    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&node).unwrap();
    let proof = &proofs[0];
    let mem = MemoryLedger::new();
    let authorization = authorization_for(proof, &members, &beacon, 2, &mem);

    let desk = ReleaseDesk::new(anchor(&members, &beacon), custody(2));
    let mut pipeline = ReleasePipeline::new(desk, FailClosedPayout::new(), ExitConfig::default());
    assert!(!pipeline.is_enabled());
    assert_eq!(
        pipeline.settle(proof, &authorization),
        Err(ExitError::PayoutUnconfigured)
    );
    assert!(
        !pipeline.is_released(&BURN_REF),
        "a gated-off pipeline never records a release"
    );
}

#[test]
fn an_enabled_pipeline_records_the_release_then_the_fail_closed_executor_refuses() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(&members, HEIGHT, &beacon, BURN_REF));
    let node = MockNode { head: HEIGHT, blocks };
    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&node).unwrap();
    let proof = &proofs[0];
    let mem = MemoryLedger::new();
    let authorization = authorization_for(proof, &members, &beacon, 2, &mem);

    let desk = ReleaseDesk::new(anchor(&members, &beacon), custody(2));
    let mut pipeline =
        ReleasePipeline::new(desk, FailClosedPayout::new(), ExitConfig { enabled: true });
    assert!(pipeline.is_enabled());
    assert_eq!(
        pipeline.settle(proof, &authorization),
        Err(ExitError::PayoutUnconfigured)
    );
    assert!(
        pipeline.is_released(&BURN_REF),
        "the release is recorded before payout so it cannot double-release"
    );
}
