// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::path::PathBuf;

use q_exits::{
    BurnFeed, BurnWatchError, DeskConfig, ExitConfig, ExitDesk, ExitError, ExitEvent, ExitId,
    ExitJournal, ExitState, FeedError, FinalizedBlock, JournaledExit, MemberConfig,
    PersistentJournal, QuantovaAnchor, QuantovaBurnSource, ReplayStore, EXIT_STATEMENT_VERSION,
};

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Block, Certificate, Parent};
use qtv_block::{event_root, Header};
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
const REQUIRED: u128 = 750;
const VAULT: u32 = 1;

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
        .map(|a| {
            a.attest(
                CHAIN_ID,
                height,
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
        height,
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
        secure_bps: 15_000,
        premium_bps: 11_000,
        window: 100,
    }
}

fn finalized_block(
    members: &[Attester],
    height: u64,
    beacon: &Beacon,
    burn: [u8; 32],
) -> FinalizedBlock {
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
    fn finalized_height(&self) -> Result<u64, BurnWatchError> {
        Ok(self.head)
    }

    fn finalized_block(&self, height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError> {
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

fn node(members: &[Attester], beacon: &Beacon) -> MockNode {
    let mut blocks = BTreeMap::new();
    blocks.insert(HEIGHT, finalized_block(members, HEIGHT, beacon, BURN_REF));
    MockNode {
        head: HEIGHT,
        blocks,
    }
}

fn temp_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "q-oracle-exit-restart-{tag}-{}-{nanos}.led",
        std::process::id()
    ));
    path
}

#[test]
fn the_feed_opens_a_vault_exit_from_a_watched_burn() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let node = node(&members, &beacon);

    let mut desk = ExitDesk::new(config(), anchor(&members, &beacon)).unwrap();
    desk.register_vault(VAULT, 2_000);

    let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
    let opened = feed
        .drive(&node, &mut desk, VAULT, 10)
        .expect("the enabled feed drives");
    assert_eq!(opened.len(), 1, "the watched burn opens one exit");
    assert_eq!(feed.scanned_through(), HEIGHT);

    let exit = desk.exit(opened[0]).unwrap();
    assert_eq!(exit.state, ExitState::Pending);
    assert_eq!(exit.statement.burn_ref, BURN_REF);
    assert_eq!(exit.statement.amount, AMOUNT);
    assert_eq!(desk.locked_collateral(VAULT), REQUIRED);
    assert!(desk.is_consumed(&BURN_REF));
}

#[test]
fn a_burn_that_hits_a_thin_vault_is_retried_not_dropped() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let node = node(&members, &beacon);

    let mut desk = ExitDesk::new(config(), anchor(&members, &beacon)).unwrap();
    desk.register_vault(VAULT, REQUIRED - 50);

    let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
    let opened = feed
        .drive(&node, &mut desk, VAULT, 10)
        .expect("the enabled feed drives");
    assert_eq!(opened.len(), 0, "a thin vault opens nothing yet");
    assert_eq!(
        feed.pending_len(),
        1,
        "the proven burn is queued, not dropped past the cursor"
    );
    assert!(
        !desk.is_consumed(&BURN_REF),
        "a thin-vault failure does not consume the burn ref"
    );

    desk.register_vault(VAULT, 100);
    let opened = feed
        .drive(&node, &mut desk, VAULT, 11)
        .expect("the feed drives again");
    assert_eq!(
        opened.len(),
        1,
        "the queued burn opens once the vault has collateral"
    );
    assert_eq!(feed.pending_len(), 0, "the retry queue drains on success");
    assert!(desk.is_consumed(&BURN_REF));
}

#[test]
fn a_burn_for_another_destination_is_dropped_not_re_queued_forever() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let node = node(&members, &beacon);

    let mut cfg = config();
    cfg.dest_chain = CHAIN_ID + 1;
    let mut desk = ExitDesk::new(cfg, anchor(&members, &beacon)).unwrap();
    desk.register_vault(VAULT, 2_000);

    let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
    let opened = feed
        .drive(&node, &mut desk, VAULT, 10)
        .expect("the feed drives");
    assert_eq!(opened.len(), 0);
    assert_eq!(
        feed.pending_len(),
        0,
        "a permanent failure is dropped, not re-queued every poll"
    );
    assert!(!desk.is_consumed(&BURN_REF));
}

#[test]
fn a_gated_off_feed_opens_nothing() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let node = node(&members, &beacon);

    let mut desk = ExitDesk::new(config(), anchor(&members, &beacon)).unwrap();
    desk.register_vault(VAULT, 2_000);

    let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig::default());
    assert!(!feed.is_enabled());
    assert_eq!(
        feed.drive(&node, &mut desk, VAULT, 10),
        Err(FeedError::Disabled)
    );
    assert_eq!(desk.locked_collateral(VAULT), 0);
    assert!(!desk.is_consumed(&BURN_REF));
}

#[test]
fn a_pending_exit_survives_a_restart_through_the_journal() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let path = temp_path("journal-pending");

    let deadline;
    {
        let node = node(&members, &beacon);
        let journal = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
        let mut desk =
            ExitDesk::with_journal(config(), anchor(&members, &beacon), Box::new(journal)).unwrap();
        desk.register_vault(VAULT, 2_000);
        let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
        let opened = feed.drive(&node, &mut desk, VAULT, 10).unwrap();
        assert_eq!(opened.len(), 1, "the first run opens the exit");
        deadline = desk.exit(opened[0]).unwrap().deadline;
        assert_eq!(desk.locked_collateral(VAULT), REQUIRED);
    }

    let journal = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
    let mut desk =
        ExitDesk::with_journal(config(), anchor(&members, &beacon), Box::new(journal)).unwrap();
    desk.register_vault(VAULT, 2_000);
    desk.reconstruct().unwrap();

    assert_eq!(
        desk.exit_count(),
        1,
        "the pending exit is rebuilt, not lost"
    );
    let exit = desk.exit(ExitId(0)).unwrap();
    assert_eq!(exit.state, ExitState::Pending);
    assert_eq!(
        exit.deadline, deadline,
        "the original deadline survives so a restart cannot reset the slash window"
    );
    assert_eq!(
        desk.locked_collateral(VAULT),
        REQUIRED,
        "the collateral is re-locked"
    );
    assert!(desk.is_consumed(&BURN_REF));
    assert_eq!(
        desk.slashable(deadline + 1),
        vec![ExitId(0)],
        "the rebuilt exit is still slashable on its original schedule"
    );

    let node = node(&members, &beacon);
    let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
    let opened = feed.drive(&node, &mut desk, VAULT, 20).unwrap();
    assert!(
        opened.is_empty(),
        "the rebuilt exit is not opened a second time"
    );
    assert_eq!(desk.locked_collateral(VAULT), REQUIRED);

    std::fs::remove_file(&path).ok();
}

#[test]
fn a_journal_with_a_duplicate_open_is_refused_not_double_paid() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let path = temp_path("journal-dup");

    {
        let mut journal = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
        let framed = JournaledExit {
            version: EXIT_STATEMENT_VERSION,
            corridor: CORRIDOR,
            asset_id: ASSET,
            amount: AMOUNT,
            holder: HOLDER,
            destination: BENEFICIARY,
            burn_ref: BURN_REF,
            finalized_height: HEIGHT,
            vault_id: VAULT,
            locked: REQUIRED,
            issued_at: 10,
            deadline: 110,
        };
        journal
            .append(&ExitEvent::Open {
                index: 0,
                exit: framed.clone(),
            })
            .unwrap();
        journal
            .append(&ExitEvent::Open {
                index: 1,
                exit: framed,
            })
            .unwrap();
    }

    let journal = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
    let mut desk =
        ExitDesk::with_journal(config(), anchor(&members, &beacon), Box::new(journal)).unwrap();
    desk.register_vault(VAULT, 2_000);
    assert_eq!(
        desk.reconstruct(),
        Err(ExitError::PersistFailed),
        "a second open for a burn already seen must fail closed, never build two payable exits"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn a_slashed_exit_is_not_reopened_after_a_restart() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let path = temp_path("journal-slashed");

    {
        let node = node(&members, &beacon);
        let journal = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
        let mut desk =
            ExitDesk::with_journal(config(), anchor(&members, &beacon), Box::new(journal)).unwrap();
        desk.register_vault(VAULT, 2_000);
        let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
        let id = feed.drive(&node, &mut desk, VAULT, 10).unwrap()[0];
        let deadline = desk.exit(id).unwrap().deadline;
        desk.slash(id, deadline + 1).unwrap();
        assert_eq!(desk.exit(id).unwrap().state, ExitState::Slashed);
    }

    let journal = PersistentJournal::open(ReplayStore::new(path.clone())).unwrap();
    let mut desk =
        ExitDesk::with_journal(config(), anchor(&members, &beacon), Box::new(journal)).unwrap();
    desk.register_vault(VAULT, 2_000);
    desk.reconstruct().unwrap();

    assert_eq!(desk.exit_count(), 1);
    assert_eq!(
        desk.exit(ExitId(0)).unwrap().state,
        ExitState::Slashed,
        "a terminal exit is not resurrected as pending"
    );
    assert!(desk.is_consumed(&BURN_REF));
    assert!(
        desk.slashable(u64::MAX).is_empty(),
        "a slashed exit is never paid out a second time after a restart"
    );

    let node = node(&members, &beacon);
    let mut feed = BurnFeed::new(HEIGHT - 1, ExitConfig { enabled: true });
    let opened = feed.drive(&node, &mut desk, VAULT, 20).unwrap();
    assert!(
        opened.is_empty(),
        "the burn of a slashed exit opens no new exit"
    );

    std::fs::remove_file(&path).ok();
}
