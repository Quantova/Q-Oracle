// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{
    CustodyConfig, ExitError, MemberConfig, OperatorQuorum, OperatorSig, ProofOfBurn,
    QuantovaAnchor, ReleaseAuthorization, ReleaseDesk, ReleaseTerms,
};

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Block, Certificate, Envelope, Parent};
use qtv_block::{event_root, prove_inclusion, Header};
use qtv_codec::{to_bytes, Encoder};
use qtv_crypto::ml_dsa::{keygen, sign, SEED_BYTES};
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
        .map(|a| a.attest(CHAIN_ID, HEIGHT, SLOT, 0, block, beacon))
        .collect();
    aggregate(CHAIN_ID, HEIGHT, SLOT, block, &commitment, beacon, &atts, TAU)
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

struct Operator {
    id: u32,
    seed: [u8; SEED_BYTES],
    public_key: Vec<u8>,
}

fn operators() -> [Operator; 3] {
    [1u8, 2, 3].map(|id| {
        let seed = [id; SEED_BYTES];
        let (pk, _sk) = keygen(&seed);
        Operator {
            id: id as u32,
            seed,
            public_key: pk.to_vec(),
        }
    })
}

fn quorum(ops: &[Operator], threshold: usize) -> OperatorQuorum {
    let roster: Vec<(u32, Vec<u8>)> = ops.iter().map(|o| (o.id, o.public_key.clone())).collect();
    OperatorQuorum::from_config(roster, threshold).expect("the operator quorum is well formed")
}

fn sign_release(op: &Operator, terms: &ReleaseTerms) -> OperatorSig {
    let preimage = terms.preimage(&VAULT, DEST_CHAIN);
    let (_pk, sk) = keygen(&op.seed);
    let rnd = [0u8; 32];
    let signature = sign(&sk, &preimage, q_exits::RELEASE_DOMAIN, &rnd)
        .expect("ml-dsa signs the release preimage")
        .to_vec();
    OperatorSig {
        operator_id: op.id,
        signature,
    }
}

struct Scenario {
    proof: ProofOfBurn,
    authorization: ReleaseAuthorization,
}

fn valid_scenario() -> (ReleaseDesk, Scenario) {
    let members = attesters();
    let beacon = Beacon::genesis();

    let leaves = vec![
        vec![0xde; 8],
        burn_leaf(AMOUNT, ASSET, BENEFICIARY, BURN_REF),
        vec![0xad; 12],
    ];
    let burn_index = 1;
    let header = header_for(&leaves);
    let header_bytes = to_bytes(&header);
    let block = Block::new(HEIGHT, header.hash(), Parent::Genesis);
    let certificate = finalized_certificate(&members, block, &beacon);
    let inclusion = prove_inclusion(&leaves, burn_index).unwrap();

    let proof = ProofOfBurn {
        header_bytes,
        certificate,
        leaf: leaves[burn_index].clone(),
        inclusion,
    };

    let ops = operators();
    let terms = ReleaseTerms {
        asset_id: ASSET,
        amount: AMOUNT,
        beneficiary: BENEFICIARY,
        burn_ref: BURN_REF,
    };
    let authorization = ReleaseAuthorization {
        terms: terms.clone(),
        signatures: vec![sign_release(&ops[0], &terms), sign_release(&ops[1], &terms)],
    };

    let desk = ReleaseDesk::new(anchor(&members, &beacon), custody());
    (desk, Scenario { proof, authorization })
}

fn custody() -> CustodyConfig {
    CustodyConfig::new(VAULT, DEST_CHAIN, quorum(&operators(), 2)).expect("custody is configured")
}

#[test]
fn a_proven_burn_and_a_quorum_authorize_a_bound_release() {
    let (mut desk, s) = valid_scenario();
    let release = desk.authorize_release(&s.proof, &s.authorization).unwrap();
    assert_eq!(release.vault, VAULT);
    assert_eq!(release.asset_id, ASSET);
    assert_eq!(release.amount, AMOUNT);
    assert_eq!(release.beneficiary, BENEFICIARY);
    assert_eq!(release.burn_ref, BURN_REF);
    assert_eq!(release.finalized_height, HEIGHT);
    assert!(desk.is_released(&BURN_REF));
}

#[test]
fn a_forged_header_is_rejected() {
    let (mut desk, mut s) = valid_scenario();
    s.proof.header_bytes[45] ^= 0xff;
    assert_eq!(
        desk.authorize_release(&s.proof, &s.authorization),
        Err(ExitError::HeaderMismatch)
    );
    assert!(!desk.is_released(&BURN_REF));
}

#[test]
fn an_unfinalized_certificate_is_rejected() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let leaves = vec![burn_leaf(AMOUNT, ASSET, BENEFICIARY, BURN_REF)];
    let header = header_for(&leaves);
    let block = Block::new(HEIGHT, header.hash(), Parent::Genesis);

    let commitment = committee(&members);
    let envelope = Envelope::new(HEIGHT, SLOT, block, &commitment);
    let lone = members[0].attest(CHAIN_ID, HEIGHT, SLOT, 0, block, &beacon);
    let thin = Certificate::new(envelope, vec![lone]);

    let proof = ProofOfBurn {
        header_bytes: to_bytes(&header),
        certificate: thin,
        leaf: leaves[0].clone(),
        inclusion: prove_inclusion(&leaves, 0).unwrap(),
    };

    let mut desk = ReleaseDesk::new(anchor(&members, &beacon), custody());
    let ops = operators();
    let terms = ReleaseTerms::from_burn(&q_exits::AuthenticatedBurn {
        asset_id: ASSET,
        beneficiary: BENEFICIARY,
        amount: AMOUNT,
        burn_ref: BURN_REF,
        finalized_height: HEIGHT,
    });
    let authorization = ReleaseAuthorization {
        terms: terms.clone(),
        signatures: vec![sign_release(&ops[0], &terms), sign_release(&ops[1], &terms)],
    };
    assert_eq!(
        desk.authorize_release(&proof, &authorization),
        Err(ExitError::NotFinalized)
    );
}

#[test]
fn a_tampered_inclusion_branch_is_rejected() {
    let (mut desk, mut s) = valid_scenario();
    s.proof.inclusion.steps[0].sibling[0] ^= 0xff;
    assert_eq!(
        desk.authorize_release(&s.proof, &s.authorization),
        Err(ExitError::BadInclusion)
    );
}

#[test]
fn a_leaf_swapped_for_another_is_rejected() {
    let (mut desk, mut s) = valid_scenario();
    s.proof.leaf = burn_leaf(AMOUNT, ASSET, BENEFICIARY, [0x22; 32]);
    assert_eq!(
        desk.authorize_release(&s.proof, &s.authorization),
        Err(ExitError::BadInclusion)
    );
}

#[test]
fn a_replayed_burn_ref_is_refused() {
    let (mut desk, s) = valid_scenario();
    assert!(desk.authorize_release(&s.proof, &s.authorization).is_ok());
    assert_eq!(
        desk.authorize_release(&s.proof, &s.authorization),
        Err(ExitError::ReplayedBurn)
    );
}

#[test]
fn a_release_below_the_operator_threshold_is_refused() {
    let (mut desk, mut s) = valid_scenario();
    s.authorization.signatures.truncate(1);
    assert_eq!(
        desk.authorize_release(&s.proof, &s.authorization),
        Err(ExitError::BelowThreshold { have: 1, need: 2 })
    );
    assert!(!desk.is_released(&BURN_REF));
}

#[test]
fn the_beneficiary_cannot_be_substituted_away_from_the_proven_burn() {
    let (mut desk, s) = valid_scenario();
    let ops = operators();
    let stolen = ReleaseTerms {
        asset_id: ASSET,
        amount: AMOUNT,
        beneficiary: [0xee; 32],
        burn_ref: BURN_REF,
    };
    let substituted = ReleaseAuthorization {
        terms: stolen.clone(),
        signatures: vec![sign_release(&ops[0], &stolen), sign_release(&ops[1], &stolen)],
    };
    assert_eq!(
        desk.authorize_release(&s.proof, &substituted),
        Err(ExitError::BurnMismatch)
    );
}

#[test]
fn the_amount_cannot_be_substituted_away_from_the_proven_burn() {
    let (mut desk, s) = valid_scenario();
    let ops = operators();
    let inflated = ReleaseTerms {
        asset_id: ASSET,
        amount: AMOUNT + 1,
        beneficiary: BENEFICIARY,
        burn_ref: BURN_REF,
    };
    let substituted = ReleaseAuthorization {
        terms: inflated.clone(),
        signatures: vec![sign_release(&ops[0], &inflated), sign_release(&ops[1], &inflated)],
    };
    assert_eq!(
        desk.authorize_release(&s.proof, &substituted),
        Err(ExitError::BurnMismatch)
    );
}

#[test]
fn the_release_amount_asset_and_beneficiary_come_from_the_proven_leaf() {
    let members = attesters();
    let beacon = Beacon::genesis();
    let asset = [0xc4; 16];
    let beneficiary = [0x7b; 32];
    let amount = 987_654;
    let burn_ref = [0x44; 32];

    let leaves = vec![burn_leaf(amount, asset, beneficiary, burn_ref), vec![0x01; 4]];
    let header = header_for(&leaves);
    let block = Block::new(HEIGHT, header.hash(), Parent::Genesis);
    let proof = ProofOfBurn {
        header_bytes: to_bytes(&header),
        certificate: finalized_certificate(&members, block, &beacon),
        leaf: leaves[0].clone(),
        inclusion: prove_inclusion(&leaves, 0).unwrap(),
    };

    let ops = operators();
    let terms = ReleaseTerms {
        asset_id: asset,
        amount,
        beneficiary,
        burn_ref,
    };
    let authorization = ReleaseAuthorization {
        terms: terms.clone(),
        signatures: vec![sign_release(&ops[0], &terms), sign_release(&ops[1], &terms)],
    };

    let mut desk = ReleaseDesk::new(anchor(&members, &beacon), custody());
    let release = desk.authorize_release(&proof, &authorization).unwrap();
    assert_eq!(release.asset_id, asset);
    assert_eq!(release.amount, amount);
    assert_eq!(release.beneficiary, beneficiary);
    assert_eq!(release.burn_ref, burn_ref);
}
