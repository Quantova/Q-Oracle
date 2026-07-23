use blst::min_pk::{AggregateSignature, SecretKey};
use q_bls::{Bls12381AggregateVerifier, ETH_SYNC_COMMITTEE_DST};
use qlc_ethereum::beacon::{
    compute_domain, compute_signing_root, BeaconBlockHeader, SyncAggregate, SyncCommittee,
    DOMAIN_SYNC_COMMITTEE, NEXT_SYNC_COMMITTEE_DEPTH, NEXT_SYNC_COMMITTEE_INDEX,
};
use qlc_ethereum::bls::{BlsPubkey, BlsSignature};
use qlc_ethereum::config::{self, EvmChainConfig};
use qlc_ethereum::engine::{
    advance_period, apply_sync_committee_update, EthError, LightClientStore, SyncCommitteeUpdate,
};
use qlc_ethereum::ssz;

const COMMITTEE_SIZE: usize = 512;
const PARTICIPATING: usize = 400;
const PERIOD: u64 = 870;
const PERIOD_SLOTS: u64 = 32 * 256;
const SIGNATURE_SLOT: u64 = PERIOD * PERIOD_SLOTS + 100;

fn secret_key(seed: u8, index: usize) -> SecretKey {
    let mut ikm = [0u8; 32];
    ikm[0] = seed;
    ikm[1] = (index & 0xff) as u8;
    ikm[2] = ((index >> 8) & 0xff) as u8;
    ikm[31] = 0xa5;
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

fn committee(seed: u8) -> (SyncCommittee, Vec<SecretKey>) {
    let secrets: Vec<SecretKey> = (0..COMMITTEE_SIZE).map(|i| secret_key(seed, i)).collect();
    let pubkeys: Vec<BlsPubkey> = secrets
        .iter()
        .map(|secret| BlsPubkey(secret.sk_to_pk().compress()))
        .collect();
    let aggregate_pubkey = pubkeys[0];
    (
        SyncCommittee {
            pubkeys,
            aggregate_pubkey,
        },
        secrets,
    )
}

fn signing_root(config: &EvmChainConfig, attested: &BeaconBlockHeader) -> [u8; 32] {
    let fork_version = config.fork_version_at_slot(SIGNATURE_SLOT);
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork_version.0,
        &config.genesis_validators_root,
    );
    compute_signing_root(&attested.hash_tree_root(), &domain)
}

fn aggregate_over(secrets: &[SecretKey], participation: &[bool], root: &[u8; 32]) -> BlsSignature {
    let mut signatures = Vec::new();
    for (index, present) in participation.iter().enumerate() {
        if *present {
            signatures.push(secrets[index].sign(root, ETH_SYNC_COMMITTEE_DST, &[]));
        }
    }
    let refs: Vec<&_> = signatures.iter().collect();
    let aggregate = AggregateSignature::aggregate(&refs, false).unwrap();
    BlsSignature(aggregate.to_signature().compress())
}

fn full_participation() -> Vec<bool> {
    let mut bits = vec![false; COMMITTEE_SIZE];
    bits[..PARTICIPATING].fill(true);
    bits
}

struct Rotation {
    store: LightClientStore,
    update: SyncCommitteeUpdate,
    next: SyncCommittee,
}

fn build_rotation() -> Rotation {
    let config = config::ethereum();
    let (current, current_secrets) = committee(0x11);
    let (next, _) = committee(0x22);

    let branch: Vec<[u8; 32]> = (0..NEXT_SYNC_COMMITTEE_DEPTH)
        .map(|i| [0xc0 + i as u8; 32])
        .collect();
    let next_leaf = next.hash_tree_root();
    let state_root = ssz::merkle_root_from_branch(&next_leaf, &branch, NEXT_SYNC_COMMITTEE_INDEX);

    let attested = BeaconBlockHeader {
        slot: PERIOD * PERIOD_SLOTS + 60,
        proposer_index: 100,
        parent_root: [0x03; 32],
        state_root,
        body_root: [0x04; 32],
    };

    let root = signing_root(&config, &attested);
    let participation = full_participation();
    let aggregate = aggregate_over(&current_secrets, &participation, &root);

    let store = LightClientStore {
        config,
        period: PERIOD,
        current_sync_committee: current,
        next_sync_committee: None,
        finalized_header: BeaconBlockHeader {
            slot: PERIOD * PERIOD_SLOTS + 40,
            proposer_index: 99,
            parent_root: [0x01; 32],
            state_root: [0x02; 32],
            body_root: [0x05; 32],
        },
    };

    let update = SyncCommitteeUpdate {
        attested_header: attested,
        next_sync_committee: next.clone(),
        next_sync_committee_branch: branch,
        sync_aggregate: SyncAggregate {
            participation,
            signature: aggregate,
        },
        signature_slot: SIGNATURE_SLOT,
    };

    Rotation {
        store,
        update,
        next,
    }
}

#[test]
fn a_real_sync_committee_aggregate_over_a_finalized_header_drives_a_rotation() {
    let mut rotation = build_rotation();
    let result = apply_sync_committee_update(
        &mut rotation.store,
        &rotation.update,
        &Bls12381AggregateVerifier::new(),
    );
    assert!(result.is_ok());
    assert_eq!(
        rotation.store.next_sync_committee,
        Some(rotation.next.clone())
    );
    assert!(advance_period(&mut rotation.store).is_ok());
    assert_eq!(rotation.store.period, PERIOD + 1);
    assert_eq!(rotation.store.current_sync_committee, rotation.next);
}

#[test]
fn a_tampered_aggregate_is_rejected_by_the_real_pairing() {
    let mut rotation = build_rotation();
    rotation.update.sync_aggregate.signature.0[0] ^= 0xff;
    assert_eq!(
        apply_sync_committee_update(
            &mut rotation.store,
            &rotation.update,
            &Bls12381AggregateVerifier::new(),
        ),
        Err(EthError::BadSignature)
    );
}

#[test]
fn a_forged_participation_bit_breaks_the_real_pairing() {
    let mut rotation = build_rotation();
    rotation.update.sync_aggregate.participation[PARTICIPATING] = true;
    assert_eq!(
        apply_sync_committee_update(
            &mut rotation.store,
            &rotation.update,
            &Bls12381AggregateVerifier::new(),
        ),
        Err(EthError::BadSignature)
    );
}

#[test]
fn a_signature_over_a_different_header_is_rejected() {
    let mut rotation = build_rotation();
    rotation.update.attested_header.body_root[0] ^= 0xff;
    assert_eq!(
        apply_sync_committee_update(
            &mut rotation.store,
            &rotation.update,
            &Bls12381AggregateVerifier::new(),
        ),
        Err(EthError::BadSignature)
    );
}
