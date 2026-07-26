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
    handle, BitcoinProofMaterial, DepositProof, DepositRequest, Request, Response,
};
use qlc_cosmos::TrustlessDeposit as CosmosDeposit;
use qlc_ethereum::TrustlessDeposit as EthereumDeposit;

use crate::http::SharedState;

pub const MAX_PROOFS_PER_POLL: usize = 256;

pub const MAX_RAW_TX: usize = 100_000;

pub const MAX_DEPOSIT_SCRIPT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchError {
    SourceUnavailable,
    Rpc(String),
}

fn within_bounds(proof: &DepositProof) -> bool {
    match proof {
        DepositProof::Bitcoin { material, .. } => {
            material.headers.len() <= crate::wire::MAX_HEADERS
                && material.branch.len() <= crate::wire::MAX_BRANCH
                && material.raw_tx.len() <= MAX_RAW_TX
                && material.deposit_script.len() <= MAX_DEPOSIT_SCRIPT
        }
        _ => true,
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

/// An Ethereum deposit proven by the `qlc_ethereum` engine, paired with its fact.
pub fn ethereum_proof(proven: EthereumDeposit, fact: BridgeFact) -> DepositProof {
    DepositProof::Ethereum { proven, fact }
}

/// A Cosmos deposit proven by the `qlc_cosmos` light client, paired with its fact.
pub fn cosmos_proof(proven: CosmosDeposit, fact: BridgeFact) -> DepositProof {
    DepositProof::Cosmos { proven, fact }
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

/// One deposit the ingestion cycle routed, with the answer the dispatcher returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingested {
    pub source_chain: u32,
    pub response: Response,
}

/// Run one ingestion cycle. Poll every attached watcher and route each proven deposit through the
/// same tested `handle` a submitted deposit takes, over the shared state behind its mutex. A source
/// whose RPC is unavailable is skipped without stalling the others. The mint stays at the trustless
/// seam; nothing here admits without the admission path the proof's tier already enforces.
pub fn ingest_once(state: &SharedState, pool: &WatcherPool) -> Vec<Ingested> {
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
            let response = {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                handle(&mut guard, Request::SubmitDeposit(DepositRequest { proof }))
            };
            ingested.push(Ingested {
                source_chain,
                response,
            });
        }
    }
    ingested
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::{boot, shared, DEST_CHAIN};
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
        bridge_script: Vec<u8>,
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
                deposit_script: self.bridge_script.clone(),
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
            min_work: U256::ZERO,
        };

        let state = shared(boot());
        state
            .lock()
            .unwrap()
            .set_bitcoin_anchor(BitcoinAnchor { checkpoint, params: EASY6 });
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(BitcoinNode {
            raw_tx: raw,
            bridge_script: bridge,
            asset_id,
            recipient,
            amount: 250_000,
        }));

        let ingested = ingest_once(&state, &pool);
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

        let guard = state.lock().unwrap();
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
        assert!(ingest_once(&state, &pool).is_empty());
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
            deposit_script: vec![],
        };
        let state = shared(boot());
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(FloodNode {
            proofs: vec![bitcoin_proof(material, btc_fact([0x11; 32]))],
        }));
        assert!(
            ingest_once(&state, &pool).is_empty(),
            "an oversized proof is refused before it reaches verification under the lock"
        );
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
                deposit_script: vec![],
            };
            proofs.push(bitcoin_proof(material, btc_fact(txid)));
        }
        let state = shared(boot());
        let mut pool = WatcherPool::new();
        pool.attach(Box::new(FloodNode { proofs }));
        assert_eq!(
            ingest_once(&state, &pool).len(),
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
