// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::net::{TcpListener, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;

use q_federated::SourceEndpoint;
use q_gateway::{Gateway, OperatorSet};
use q_qbridge::BridgeState;

use crate::http::{serve, SharedState};

/// The Quantova destination chain the oracle mints against.
pub const DEST_CHAIN: u32 = 9000;

/// The default rolling epoch mint budget the gateway enforces across every corridor.
pub const DEFAULT_EPOCH_CAP: u128 = 1_000_000_000_000_000_000_000_000;

/// Build a fully seeded bridge state. Every enumerated foreign asset is a live pool and every pool
/// installs its corridor and per-asset cap on the gateway, so all thirty-four chains and every asset
/// are a live corridor the moment the runtime is up. The operator set is empty, which serves reads
/// and the proof-backed trustless path out of the box and safely refuses federated mints until an
/// operator quorum and its independent sources are declared.
pub fn boot() -> BridgeState {
    boot_with(OperatorSet::new(0), DEFAULT_EPOCH_CAP)
}

/// Build a seeded bridge state against a configured operator set and epoch budget. The federated
/// corridors mint once their operators are registered here and their independent sources declared
/// through [`declare_operator_source`].
pub fn boot_with(operators: OperatorSet, epoch_cap: u128) -> BridgeState {
    let gateway = Gateway::new(DEST_CHAIN, operators, epoch_cap);
    BridgeState::seeded(gateway)
}

/// Declare the independent foreign source an operator watches for a corridor. The federated
/// admission gate reads this registry to refuse a quorum whose signers share a source.
pub fn declare_operator_source(
    state: &mut BridgeState,
    corridor: u32,
    operator_id: u32,
    endpoint: SourceEndpoint,
) {
    state.sources.declare(corridor, operator_id, endpoint);
}

/// Wrap a bridge state for sharing across the server's connection threads.
pub fn shared(state: BridgeState) -> SharedState {
    Arc::new(Mutex::new(state))
}

/// Bind, boot a fully seeded state, and serve the endpoints, parking the calling thread while the
/// accept loop runs. The authoritative on-chain mint stays at the trustless deposit seam.
pub fn run<A: ToSocketAddrs>(addr: A) -> std::io::Result<()> {
    run_with(addr, shared(boot()))
}

/// Serve a supplied shared state, for a runtime booted with configured operators and sources.
pub fn run_with<A: ToSocketAddrs>(addr: A, state: SharedState) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve(listener, state);
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_airlock::{AttestationEnvelope, SignerSig};
    use q_assets::Network;
    use q_codec::{
        AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION,
    };
    use q_federated::derive_asset_id;
    use q_qbridge::{
        handle, DepositOutcome, DepositProof, DepositRequest, ListPoolsRequest, Request, Response,
    };
    use qlc_bitcoin::TrustlessDeposit as BitcoinDeposit;
    use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

    fn foreign_asset_count() -> usize {
        q_assets::registry::ASSETS
            .iter()
            .filter(|a| a.id.is_foreign())
            .count()
    }

    #[test]
    fn the_runtime_boots_with_every_chain_and_asset_installed() {
        let state = boot();
        let foreign = foreign_asset_count();
        assert!(foreign >= 70, "there are {foreign} foreign assets");
        assert_eq!(state.pools.len(), foreign, "every foreign asset is a pool");
        for network in Network::ALL {
            assert!(
                !state.pools.by_network(network).is_empty(),
                "no seeded pool for {network:?}"
            );
        }
        for spec in state.pools.all() {
            assert_eq!(
                state.gateway.asset_cap(&spec.asset_id.0),
                Some(spec.per_asset_cap),
                "the pool cap is installed on the gateway"
            );
            assert!(
                state.gateway.corridor_tier(spec.network.id()).is_some(),
                "the corridor is open on the gateway"
            );
        }
    }

    #[test]
    fn a_booted_runtime_lists_all_the_seeded_pools() {
        let mut state = boot();
        match handle(&mut state, Request::ListPools(ListPoolsRequest { network_id: None })) {
            Response::Pools(pools) => assert_eq!(pools.len(), foreign_asset_count()),
            other => panic!("expected Pools, got {other:?}"),
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

    fn attest(op: &Op, fact: &BridgeFact) -> SignerSig {
        let sig = ml_dsa::sign(&op.sk, &fact.attest_preimage(), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
        SignerSig {
            operator_id: op.id,
            signature: sig.to_vec(),
        }
    }

    #[test]
    fn a_federated_deposit_on_a_booted_seeded_pool_routes_to_quorum_and_mints() {
        let ops: Vec<Op> = (0..3).map(mk).collect();
        let mut set = OperatorSet::new(3);
        for op in &ops {
            set.register(op.id, op.pk);
        }
        let mut state = boot_with(set, DEFAULT_EPOCH_CAP);
        for op in &ops {
            declare_operator_source(
                &mut state,
                Network::Solana.id(),
                op.id,
                SourceEndpoint([0x10 + op.id as u8; 32]),
            );
        }
        let asset = derive_asset_id(Network::Solana, "SOL").0;
        let fact = BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Solana.id(),
            dest_chain: DEST_CHAIN,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef([0x11; 32]),
            asset_id: AssetId(asset),
            amount: 500,
            recipient: Recipient([0x55; 32]),
            finality_depth: 40,
            observed_height: 900_000,
            expiry_height: 1_800_000,
        };
        let env = AttestationEnvelope {
            fact: fact.clone(),
            signatures: vec![attest(&ops[0], &fact), attest(&ops[1], &fact), attest(&ops[2], &fact)],
        };
        match handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Federated(env),
            }),
        ) {
            Response::DepositAdmitted(DepositOutcome::Minted(receipt)) => {
                assert_eq!(receipt.amount, 500);
                assert_eq!(receipt.asset_id, asset);
            }
            other => panic!("expected a minted federated deposit, got {other:?}"),
        }
    }

    #[test]
    fn a_bitcoin_deposit_on_a_booted_seeded_pool_routes_to_the_trustless_seam() {
        let mut state = boot();
        let asset = derive_asset_id(Network::Bitcoin, "BTC").0;
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let proven = BitcoinDeposit {
            txid,
            amount: 250_000,
            recipient,
            confirmations: 6,
        };
        let fact = BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Bitcoin.id(),
            dest_chain: DEST_CHAIN,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(txid),
            asset_id: AssetId(asset),
            amount: 250_000,
            recipient: Recipient(recipient),
            finality_depth: 6,
            observed_height: 800_000,
            expiry_height: 900_000,
        };
        match handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { proven, fact },
            }),
        ) {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 250_000);
                assert_eq!(mint.source_ref, txid);
                assert!(
                    !state.gateway.is_reference_used(&txid),
                    "the trustless seam admits without minting on chain here"
                );
            }
            other => panic!("expected a trustless admission, got {other:?}"),
        }
    }
}
