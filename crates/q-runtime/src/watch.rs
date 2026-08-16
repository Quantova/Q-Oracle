// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The per-chain block-ingestion seam.
//!
//! A [`ChainWatcher`] is one source chain's ingestion feed. A concrete implementation is a real RPC
//! client that pulls foreign headers and blocks from a node of that chain and turns them into a
//! [`DepositProof`] the runtime already routes:
//!
//! - a proof-backed chain (Bitcoin, Ethereum, Cosmos) runs its light-client verifier
//!   ([`qlc_bitcoin::verify_trustless_deposit`], [`qlc_ethereum`], [`qlc_cosmos`]) over the pulled
//!   headers and emits the verified deposit through [`bitcoin_proof`], [`ethereum_proof`] or
//!   [`cosmos_proof`];
//! - a federated chain gathers the operator quorum's attestations and emits them through
//!   [`federated_proof`].
//!
//! The concrete per-chain RPC clients attach here, at [`WatcherPool::attach`]. They are the one
//! genuinely large remaining integration and are not stubbed in this crate. What is wired here is
//! the seam: [`ingest_once`] polls every attached watcher and routes each proof through the same
//! tested `handle` a submitted deposit takes, so a federated proof reaches the quorum admission and
//! a proof-backed proof reaches the trustless admission. The authoritative on-chain mint for a
//! proof-backed corridor stays at the seam `q_federated::trustless` documents. This loop opens no
//! no-quorum mint.

use std::collections::BTreeMap;

use q_airlock::AttestationEnvelope;
use q_codec::BridgeFact;
use q_qbridge::{
    commit_deposit, verify_deposit, BitcoinProofMaterial, BridgeState, DepositProof, DepositRequest,
    Response,
};
use qlc_cosmos::commit::{Commit, Header};
use qlc_cosmos::proof::ExistenceProof;
use qlc_cosmos::validator::ValidatorSet;
use qlc_ethereum::{DepositProof as EthDepositProof, LightClientUpdate};

use crate::http::SharedState;
use crate::persist::GuardStore;

pub const MAX_PROOFS_PER_POLL: usize = 256;

pub const MAX_RAW_TX: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchError {
    SourceUnavailable,
    Rpc(String),
}

fn within_bounds(proof: &DepositProof) -> bool {
    use crate::wire::{
        MAX_BRANCH, MAX_HEADERS, MAX_PARTICIPATION, MAX_PROOF_NODES, MAX_PROOF_PATH, MAX_VALIDATORS,
    };
    match proof {
        DepositProof::Bitcoin { material, .. } => {
            material.headers.len() <= MAX_HEADERS
                && material.branch.len() <= MAX_BRANCH
                && material.raw_tx.len() <= MAX_RAW_TX
        }
        DepositProof::Ethereum { update, deposit, .. } => {
            update.sync_aggregate.participation.len() <= MAX_PARTICIPATION
                && update.finality_branch.len() <= MAX_BRANCH
                && update.execution.execution_branch.len() <= MAX_BRANCH
                && deposit.receipt_proof.len() <= MAX_PROOF_NODES
        }
        DepositProof::Cosmos { commit, validators, proof, .. } => {
            commit.signatures.len() <= MAX_VALIDATORS
                && validators.validators.len() <= MAX_VALIDATORS
                && proof.path.len() <= MAX_PROOF_PATH
        }
        DepositProof::Federated(env) => env.signatures.len() <= MAX_VALIDATORS,
    }
}

/// One source chain's ingestion feed. The concrete implementation is the RPC client that pulls
/// foreign headers and blocks and emits verified deposits ready for admission.
pub trait ChainWatcher: Send {
    /// The origin network id this watcher feeds, as `q_assets::Network::id`.
    fn source_chain(&self) -> u32;
    /// Pull the deposits that have newly reached finality on the source chain, each already carried
    /// as the proof its corridor tier requires.
    fn poll_proven(&self) -> Result<Vec<DepositProof>, WatchError>;
}

/// A federated attestation quorum, ready for the quorum admission path.
pub fn federated_proof(envelope: AttestationEnvelope) -> DepositProof {
    DepositProof::Federated(envelope)
}

pub fn bitcoin_proof(material: BitcoinProofMaterial, fact: BridgeFact) -> DepositProof {
    DepositProof::Bitcoin { material, fact }
}

pub fn ethereum_proof(
    update: LightClientUpdate,
    deposit: EthDepositProof,
    fact: BridgeFact,
) -> DepositProof {
    DepositProof::Ethereum {
        update,
        deposit,
        fact,
    }
}

pub fn cosmos_proof(
    header: Header,
    commit: Commit,
    validators: ValidatorSet,
    proof: ExistenceProof,
    fact: BridgeFact,
) -> DepositProof {
    DepositProof::Cosmos {
        header,
        commit,
        validators,
        proof,
        fact,
    }
}

/// The set of attached per-chain watchers, one per source chain.
#[derive(Default)]
pub struct WatcherPool {
    watchers: BTreeMap<u32, Box<dyn ChainWatcher>>,
}

impl WatcherPool {
    pub fn new() -> WatcherPool {
        WatcherPool {
            watchers: BTreeMap::new(),
        }
    }

    /// Attach a concrete per-chain RPC watcher. This is the seam the real clients bind to.
    pub fn attach(&mut self, watcher: Box<dyn ChainWatcher>) {
        self.watchers.insert(watcher.source_chain(), watcher);
    }

    pub fn chains(&self) -> Vec<u32> {
        self.watchers.keys().copied().collect()
    }

    pub fn poll(&self, source_chain: u32) -> Result<Vec<DepositProof>, WatchError> {
        match self.watchers.get(&source_chain) {
            Some(w) => w.poll_proven(),
            None => Err(WatchError::SourceUnavailable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    NotPersisted,
    Persisted,
    PersistFailed,
}

/// One deposit the ingestion cycle routed, with the answer the dispatcher returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingested {
    pub source_chain: u32,
    pub response: Response,
    pub durability: Durability,
}

pub(crate) fn persist_or_rollback(
    state: &mut BridgeState,
    store: Option<&GuardStore>,
    rev_before: u64,
    snapshot: &[u8],
) -> Durability {
    if state.gateway.guard_revision() == rev_before {
        return Durability::NotPersisted;
    }
    let Some(store) = store else {
        return Durability::NotPersisted;
    };
    match store.save(&state.gateway.encode_guard()) {
        Ok(()) => Durability::Persisted,
        Err(_) => {
            let _ = state.gateway.rehydrate_guard(snapshot);
            Durability::PersistFailed
        }
    }
}

/// Run one ingestion cycle. Poll every attached watcher and route each proven deposit through the
/// same tested `handle` a submitted deposit takes, over the shared state behind its mutex. A source
/// whose RPC is unavailable is skipped without stalling the others. The mint stays at the trustless
/// seam; nothing here admits without the admission path the proof's tier already enforces.
pub fn ingest_once(
    state: &SharedState,
    pool: &WatcherPool,
    store: Option<&GuardStore>,
) -> Vec<Ingested> {
    let mut ingested = Vec::new();
    for source_chain in pool.chains() {
        let proofs = match pool.poll(source_chain) {
            Ok(proofs) => proofs,
            Err(_) => continue,
        };
        for proof in proofs.into_iter().take(MAX_PROOFS_PER_POLL) {
            if !within_bounds(&proof) {
                continue;
            }
            let request = DepositRequest { proof };
            let routed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let plan = {
                    let guard = state.read().unwrap_or_else(|e| e.into_inner());
                    verify_deposit(&guard, &request)
                };
                let plan = match plan {
                    Ok(plan) => plan,
                    Err(err) => return (Response::Error(err), Durability::NotPersisted),
                };
                let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
                let rev_before = guard.gateway.guard_revision();
                let snapshot = guard.gateway.encode_guard();
                let response = match commit_deposit(&mut guard, plan) {
                    Ok(outcome) => Response::DepositAdmitted(outcome),
                    Err(err) => Response::Error(err),
                };
                let durability = persist_or_rollback(&mut guard, store, rev_before, &snapshot);
                (response, durability)
            }));
            if let Ok((response, durability)) = routed {
                ingested.push(Ingested {
                    source_chain,
                    response,
                    durability,
                });
            }
        }
    }
    ingested
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::{boot, boot_configured, shared, DEST_CHAIN};
    use q_assets::Network;
    use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION};
    use q_federated::derive_asset_id;
    use q_qbridge::{BitcoinAnchor, DepositOutcome, Response};
    use qlc_bitcoin::{BlockHeader, Checkpoint, Network as BtcNetwork, NetworkParams, U256};
    use qlc_bitcoin::tx::Transaction;

    const EASY6: NetworkParams = NetworkParams {
        network: BtcNetwork::Bitcoin,
        name: "Crafted",
        magic: [0xfa, 0xbf, 0xb5, 0xda],
        pow_limit_bits: 0x207f_ffff,
        target_timespan: 1_209_600,
        target_spacing: 600,
        confirmation_depth: 6,
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

    fn mine(prev_block: [u8; 32], merkle_root: [u8; 32]) -> BlockHeader {
        let mut header = BlockHeader {
            version: 1,
            prev_block,
            merkle_root,
            timestamp: 1_700_000_000,
            bits: EASY6.pow_limit_bits,
            nonce: 0,
        };
        while !header.meets_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn crafted_chain(txid: [u8; 32]) -> Vec<BlockHeader> {
        let mut headers = vec![mine([0u8; 32], txid)];
        let mut prev = headers[0].block_hash();
        for i in 0..5u8 {
            let block = mine(prev, [i + 1; 32]);
            prev = block.block_hash();
            headers.push(block);
        }
        headers
    }

    struct BitcoinNode {
        raw_tx: Vec<u8>,
        asset_id: [u8; 16],
        recipient: [u8; 32],
        amount: u128,
    }

    impl ChainWatcher for BitcoinNode {
        fn source_chain(&self) -> u32 {
            Network::Bitcoin.id()
        }

        fn poll_proven(&self) -> Result<Vec<DepositProof>, WatchError> {
            let txid = Transaction::parse(&self.raw_tx)
                .map_err(|_| WatchError::Rpc("unparseable transaction".to_string()))?
                .txid();
            let material = BitcoinProofMaterial {
                headers: crafted_chain(txid),
                start_height: 0,
                deposit_height: 0,
                branch: vec![],
                raw_tx: self.raw_tx.clone(),
            };
            let fact = BridgeFact {
                version: FACT_VERSION,
                source_chain: Network::Bitcoin.id(),
                dest_chain: DEST_CHAIN,
                route_id: 1,
                direction: Direction::Deposit,
                nonce: 1,
                source_ref: SourceRef(txid),
                asset_id: AssetId(self.asset_id),
                amount: self.amount,
                recipient: Recipient(self.recipient),
                finality_depth: 6,
                observed_height: 800_000,
                expiry_height: 900_000,
            };
            Ok(vec![bitcoin_proof(material, fact)])
        }
    }

    struct SilentNode(u32);

    impl ChainWatcher for SilentNode {
        fn source_chain(&self) -> u32 {
            self.0
        }

        fn poll_proven(&self) -> Result<Vec<DepositProof>, WatchError> {
            Err(WatchError::SourceUnavailable)
        }
    }

    #[test]
    fn a_verified_bitcoin_deposit_flows_from_the_watcher_through_the_trustless_admission() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let asset_id = derive_asset_id(Network::Bitcoin, "BTC").0;
        let checkpoint = Checkpoint {
            height: 0,
            hash: crafted_chain(txid)[0].block_hash(),
            min_work: U256::ONE,
        };

        let state = shared(boot_configured());
        state
            .write()
            .unwrap()
            .set_bitcoin_anchor(BitcoinAnchor { checkpoint, params: EASY6, bridge_script: bridge.clone() });
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(BitcoinNode {
            raw_tx: raw,
            asset_id,
            recipient,
            amount: 250_000,
        }));

        let ingested = ingest_once(&state, &pool, None);
        assert_eq!(ingested.len(), 1);
        assert_eq!(ingested[0].source_chain, Network::Bitcoin.id());
        match &ingested[0].response {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 250_000);
                assert_eq!(mint.recipient, recipient);
                assert_eq!(mint.confirmations, 6);
            }
            other => panic!("expected a trustless admission, got {other:?}"),
        }

        let guard = state.read().unwrap();
        assert!(
            guard.gateway.is_reference_used(&txid),
            "the ingestion seam binds the reference authoritatively"
        );
        assert_eq!(
            guard.gateway.minted_of_asset(&asset_id),
            250_000,
            "a proof-backed deposit reserves its per-asset budget at this seam"
        );
    }

    #[test]
    fn an_unavailable_source_is_skipped_and_admits_nothing() {
        let state = shared(boot());
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(SilentNode(Network::Bitcoin.id())));
        assert!(ingest_once(&state, &pool, None).is_empty());
    }

    struct FloodNode {
        proofs: Vec<DepositProof>,
    }

    impl ChainWatcher for FloodNode {
        fn source_chain(&self) -> u32 {
            Network::Bitcoin.id()
        }

        fn poll_proven(&self) -> Result<Vec<DepositProof>, WatchError> {
            Ok(self.proofs.clone())
        }
    }

    fn btc_fact(txid: [u8; 32]) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Bitcoin.id(),
            dest_chain: DEST_CHAIN,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(txid),
            asset_id: AssetId(derive_asset_id(Network::Bitcoin, "BTC").0),
            amount: 250_000,
            recipient: Recipient([0x42; 32]),
            finality_depth: 6,
            observed_height: 800_000,
            expiry_height: 900_000,
        }
    }

    #[test]
    fn an_oversized_ingested_bitcoin_proof_is_dropped_before_verification() {
        let dummy = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            bits: 0,
            nonce: 0,
        };
        let material = BitcoinProofMaterial {
            headers: vec![dummy; crate::wire::MAX_HEADERS + 1],
            start_height: 0,
            deposit_height: 0,
            branch: vec![],
            raw_tx: vec![0u8; 4],
        };
        let state = shared(boot());
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(FloodNode {
            proofs: vec![bitcoin_proof(material, btc_fact([0x11; 32]))],
        }));
        assert!(
            ingest_once(&state, &pool, None).is_empty(),
            "an oversized proof is refused before it reaches verification under the lock"
        );
    }

    #[test]
    fn an_oversized_ingested_federated_envelope_is_dropped_before_admission() {
        let signatures: Vec<q_airlock::SignerSig> = (0..=crate::wire::MAX_VALIDATORS)
            .map(|i| q_airlock::SignerSig {
                operator_id: i as u32,
                signature: Vec::new(),
            })
            .collect();
        let env = AttestationEnvelope {
            fact: btc_fact([0x11; 32]),
            signatures,
        };
        let state = shared(boot());
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(FloodNode {
            proofs: vec![federated_proof(env)],
        }));
        assert!(
            ingest_once(&state, &pool, None).is_empty(),
            "an envelope over the validator cap is refused before it reaches admission"
        );
    }

    #[test]
    fn a_watch_path_persist_failure_rolls_back_and_the_deposit_readmits() {
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let raw = raw_deposit_tx(&[(250_000, bridge.clone()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let asset_id = derive_asset_id(Network::Bitcoin, "BTC").0;
        let checkpoint = Checkpoint {
            height: 0,
            hash: crafted_chain(txid)[0].block_hash(),
            min_work: U256::ONE,
        };
        let state = shared(boot_configured());
        state
            .write()
            .unwrap()
            .set_bitcoin_anchor(BitcoinAnchor { checkpoint, params: EASY6, bridge_script: bridge.clone() });
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(BitcoinNode {
            raw_tx: raw,
            asset_id,
            recipient,
            amount: 250_000,
        }));

        let failing = GuardStore::new("/no-such-q-oracle-dir/guard.snap");
        let ingested = ingest_once(&state, &pool, Some(&failing));
        assert_eq!(ingested.len(), 1);
        assert_eq!(
            ingested[0].durability,
            Durability::PersistFailed,
            "a durability failure on the ingestion seam is surfaced, not silently dropped"
        );
        {
            let guard = state.read().unwrap();
            assert!(
                !guard.gateway.is_reference_used(&txid),
                "a failed persist rolls the reserved reference back so memory never leads disk"
            );
            assert_eq!(
                guard.gateway.minted_of_asset(&asset_id),
                0,
                "a failed persist rolls the reserved mint budget back"
            );
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("q-oracle-watch-{}-{nanos}.snap", std::process::id()));
        let working = GuardStore::new(path.clone());
        let ingested = ingest_once(&state, &pool, Some(&working));
        assert_eq!(ingested.len(), 1);
        assert_eq!(
            ingested[0].durability,
            Durability::Persisted,
            "the same deposit re-admits and persists once the store recovers"
        );
        {
            let guard = state.read().unwrap();
            assert!(
                guard.gateway.is_reference_used(&txid),
                "the recovered persist binds the reference authoritatively"
            );
            assert_eq!(guard.gateway.minted_of_asset(&asset_id), 250_000);
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_flood_of_ingested_proofs_is_capped_per_poll() {
        let mut proofs = Vec::new();
        for i in 0..(MAX_PROOFS_PER_POLL + 5) {
            let mut txid = [0u8; 32];
            txid[0] = (i % 256) as u8;
            txid[1] = (i / 256) as u8;
            let material = BitcoinProofMaterial {
                headers: vec![],
                start_height: 0,
                deposit_height: 0,
                branch: vec![],
                raw_tx: vec![0u8; 4],
            };
            proofs.push(bitcoin_proof(material, btc_fact(txid)));
        }
        let state = shared(boot());
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(FloodNode { proofs }));
        assert_eq!(
            ingest_once(&state, &pool, None).len(),
            MAX_PROOFS_PER_POLL,
            "no more than the per poll cap is routed under the lock"
        );
    }

    #[test]
    fn the_pool_keys_each_watcher_by_its_source_chain() {
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(SilentNode(Network::Bitcoin.id())));
        pool.attach(Box::new(SilentNode(Network::Ethereum.id())));
        assert_eq!(pool.chains(), vec![Network::Bitcoin.id(), Network::Ethereum.id()]);
    }
}
