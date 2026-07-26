// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::AttestationEnvelope;
use q_assets::Network;
use q_codec::BridgeFact;
use q_federated::{
    admit, admit_bitcoin_trustless, admit_cosmos_trustless, admit_ethereum_trustless, corridor_for,
    install_all, install_pool, FederatedError, PoolError, PoolRegistry, PoolRequest, PoolSpec,
    SourceRegistry, Tier, TrustlessError, TrustlessMint,
};
use q_gateway::{Gateway, MintReceipt};
use qlc_bitcoin::{
    verify_chain, verify_trustless_deposit, BlockHeader, Checkpoint, MerkleStep, NetworkParams,
    SpvError,
};
use qlc_cosmos::TrustlessDeposit as CosmosDeposit;
use qlc_ethereum::TrustlessDeposit as EthereumDeposit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinProofMaterial {
    pub headers: Vec<BlockHeader>,
    pub start_height: u32,
    pub deposit_height: u32,
    pub branch: Vec<MerkleStep>,
    pub raw_tx: Vec<u8>,
    pub deposit_script: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinAnchor {
    pub checkpoint: Checkpoint,
    pub params: NetworkParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPoolsRequest {
    pub network_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetPoolRequest {
    pub asset_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRequest {
    pub proof: DepositProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum DepositProof {
    Federated(AttestationEnvelope),
    Bitcoin { material: BitcoinProofMaterial, fact: BridgeFact },
    Ethereum { proven: EthereumDeposit, fact: BridgeFact },
    Cosmos { proven: CosmosDeposit, fact: BridgeFact },
}

impl DepositProof {
    pub fn fact(&self) -> &BridgeFact {
        match self {
            DepositProof::Federated(env) => &env.fact,
            DepositProof::Bitcoin { fact, .. } => fact,
            DepositProof::Ethereum { fact, .. } => fact,
            DepositProof::Cosmos { fact, .. } => fact,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositStatusRequest {
    pub source_ref: [u8; 32],
    pub asset_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    CreatePool(PoolRequest),
    ListPools(ListPoolsRequest),
    GetPool(GetPoolRequest),
    SubmitDeposit(DepositRequest),
    DepositStatus(DepositStatusRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolView {
    pub network_id: u32,
    pub network_name: &'static str,
    pub identifier: String,
    pub decimals: u8,
    pub asset_id: [u8; 16],
    pub per_asset_cap: u128,
    pub per_epoch_cap: u128,
    pub tier: &'static str,
}

impl From<&PoolSpec> for PoolView {
    fn from(spec: &PoolSpec) -> PoolView {
        PoolView {
            network_id: spec.network.id(),
            network_name: spec.network.name(),
            identifier: spec.identifier.clone(),
            decimals: spec.decimals,
            asset_id: spec.asset_id.0,
            per_asset_cap: spec.per_asset_cap,
            per_epoch_cap: spec.per_epoch_cap,
            tier: spec.tier.label(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositOutcome {
    Minted(MintReceipt),
    AdmittedPendingChainMint(TrustlessMint),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositStatusView {
    pub source_ref: [u8; 32],
    pub asset_id: [u8; 16],
    pub minted: bool,
    pub asset_minted_total: u128,
    pub asset_cap: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    Pool(PoolError),
    Federated(FederatedError),
    Trustless(TrustlessError),
    UnknownNetwork(u32),
    PoolNotRegistered([u8; 16]),
    AssetNetworkMismatch { fact_network: u32, pool_network: u32 },
    ProofTierMismatch,
    NoAnchor(u32),
    BitcoinSpv(SpvError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    PoolCreated(PoolView),
    Pools(Vec<PoolView>),
    Pool(PoolView),
    DepositAdmitted(DepositOutcome),
    Status(DepositStatusView),
    Error(ApiError),
}

pub struct BridgeState {
    pub pools: PoolRegistry,
    pub gateway: Gateway,
    pub sources: SourceRegistry,
    pub bitcoin_anchor: Option<BitcoinAnchor>,
}

impl BridgeState {
    pub fn new(gateway: Gateway) -> BridgeState {
        BridgeState {
            pools: PoolRegistry::new(),
            gateway,
            sources: SourceRegistry::new(),
            bitcoin_anchor: None,
        }
    }

    pub fn seeded(mut gateway: Gateway) -> BridgeState {
        let pools = PoolRegistry::seeded();
        install_all(&mut gateway, &pools);
        BridgeState {
            pools,
            gateway,
            sources: SourceRegistry::new(),
            bitcoin_anchor: None,
        }
    }

    pub fn set_bitcoin_anchor(&mut self, anchor: BitcoinAnchor) {
        self.bitcoin_anchor = Some(anchor);
    }
}

pub fn handle(state: &mut BridgeState, request: Request) -> Response {
    match request {
        Request::CreatePool(request) => match state.pools.create_pool(&request) {
            Ok(spec) => {
                install_pool(&mut state.gateway, &spec);
                Response::PoolCreated(PoolView::from(&spec))
            }
            Err(err) => Response::Error(ApiError::Pool(err)),
        },
        Request::ListPools(request) => {
            let views: Vec<PoolView> = match request.network_id {
                Some(id) => match Network::from_id(id) {
                    Some(network) => state
                        .pools
                        .by_network(network)
                        .into_iter()
                        .map(PoolView::from)
                        .collect(),
                    None => return Response::Error(ApiError::UnknownNetwork(id)),
                },
                None => state.pools.all().map(PoolView::from).collect(),
            };
            Response::Pools(views)
        }
        Request::GetPool(request) => match state.pools.get(&request.asset_id) {
            Some(spec) => Response::Pool(PoolView::from(spec)),
            None => Response::Error(ApiError::PoolNotRegistered(request.asset_id)),
        },
        Request::SubmitDeposit(request) => match dispatch_deposit(state, request) {
            Ok(outcome) => Response::DepositAdmitted(outcome),
            Err(err) => Response::Error(err),
        },
        Request::DepositStatus(request) => Response::Status(deposit_status(state, &request)),
    }
}

fn dispatch_deposit(
    state: &mut BridgeState,
    request: DepositRequest,
) -> Result<DepositOutcome, ApiError> {
    let source_chain = request.proof.fact().source_chain;
    let asset_id = request.proof.fact().asset_id.0;
    let network =
        Network::from_id(source_chain).ok_or(ApiError::UnknownNetwork(source_chain))?;
    let (tier, pool_network, cap) = {
        let spec = state
            .pools
            .get(&asset_id)
            .ok_or(ApiError::PoolNotRegistered(asset_id))?;
        (spec.tier, spec.network, spec.per_asset_cap)
    };
    if pool_network != network {
        return Err(ApiError::AssetNetworkMismatch {
            fact_network: source_chain,
            pool_network: pool_network.id(),
        });
    }
    let corridor = corridor_for(network, cap);
    match (tier, network, &request.proof) {
        (Tier::Federated, _, DepositProof::Federated(env)) => {
            let receipt = admit(&mut state.gateway, &corridor, &state.sources, env)
                .map_err(ApiError::Federated)?;
            Ok(DepositOutcome::Minted(receipt))
        }
        (Tier::ProofBacked, Network::Bitcoin, DepositProof::Bitcoin { material, fact }) => {
            let (params, checkpoint) = {
                let anchor = state
                    .bitcoin_anchor
                    .as_ref()
                    .ok_or(ApiError::NoAnchor(Network::Bitcoin.id()))?;
                (anchor.params, anchor.checkpoint.clone())
            };
            let chain = verify_chain(&material.headers, material.start_height, &params)
                .map_err(ApiError::BitcoinSpv)?;
            let proven = verify_trustless_deposit(
                &chain,
                &params,
                &checkpoint,
                material.deposit_height,
                &material.branch,
                &material.raw_tx,
                &material.deposit_script,
            )
            .map_err(ApiError::BitcoinSpv)?;
            let mint = admit_bitcoin_trustless(&mut state.gateway, &corridor, &proven, fact)
                .map_err(ApiError::Trustless)?;
            Ok(DepositOutcome::AdmittedPendingChainMint(mint))
        }
        (Tier::ProofBacked, Network::Ethereum, DepositProof::Ethereum { proven, fact }) => {
            let mint = admit_ethereum_trustless(&mut state.gateway, &corridor, proven, fact)
                .map_err(ApiError::Trustless)?;
            Ok(DepositOutcome::AdmittedPendingChainMint(mint))
        }
        (Tier::ProofBacked, Network::Cosmos, DepositProof::Cosmos { proven, fact }) => {
            let mint = admit_cosmos_trustless(&mut state.gateway, &corridor, proven, fact)
                .map_err(ApiError::Trustless)?;
            Ok(DepositOutcome::AdmittedPendingChainMint(mint))
        }
        _ => Err(ApiError::ProofTierMismatch),
    }
}

fn deposit_status(state: &BridgeState, request: &DepositStatusRequest) -> DepositStatusView {
    DepositStatusView {
        source_ref: request.source_ref,
        asset_id: request.asset_id,
        minted: state.gateway.is_reference_used(&request.source_ref),
        asset_minted_total: state.gateway.minted_of_asset(&request.asset_id),
        asset_cap: state.gateway.asset_cap(&request.asset_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_airlock::SignerSig;
    use q_codec::{
        AssetId, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION,
    };
    use q_federated::{derive_asset_id, SourceEndpoint};
    use q_gateway::OperatorSet;
    use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

    const DEST: u32 = 9000;

    fn pool_request(network_id: u32, identifier: &str) -> PoolRequest {
        PoolRequest {
            network_id,
            identifier: identifier.to_string(),
            decimals: 18,
            per_asset_cap: 1_000_000,
            per_epoch_cap: 500_000,
        }
    }

    fn empty_state(threshold: usize) -> BridgeState {
        BridgeState::new(Gateway::new(DEST, OperatorSet::new(threshold), 1_000_000_000_000))
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

    fn federated_fact(asset: [u8; 16], source_ref: [u8; 32]) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Solana.id(),
            dest_chain: DEST,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(source_ref),
            asset_id: AssetId(asset),
            amount: 500,
            recipient: Recipient([0x55; 32]),
            finality_depth: 40,
            observed_height: 900_000,
            expiry_height: 1_800_000,
        }
    }

    use qlc_bitcoin::tx::Transaction;
    use qlc_bitcoin::{Network as BtcNetwork, SpvError, U256};

    const EASY: NetworkParams = NetworkParams {
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
            bits: EASY.pow_limit_bits,
            nonce: 0,
        };
        while !header.meets_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn bitcoin_deposit(
        bridge: &[u8],
        recipient: [u8; 32],
        amount: u64,
    ) -> (BitcoinProofMaterial, BitcoinAnchor, [u8; 32]) {
        let raw = raw_deposit_tx(&[(amount, bridge.to_vec()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let mut headers = vec![mine([0u8; 32], txid)];
        let mut prev = headers[0].block_hash();
        for i in 0..5u8 {
            let block = mine(prev, [i + 1; 32]);
            prev = block.block_hash();
            headers.push(block);
        }
        let checkpoint = Checkpoint {
            height: 0,
            hash: headers[0].block_hash(),
            min_work: U256::ZERO,
        };
        let material = BitcoinProofMaterial {
            headers,
            start_height: 0,
            deposit_height: 0,
            branch: vec![],
            raw_tx: raw,
            deposit_script: bridge.to_vec(),
        };
        (material, BitcoinAnchor { checkpoint, params: EASY }, txid)
    }

    fn bitcoin_fact(asset: [u8; 16], txid: [u8; 32], recipient: [u8; 32], amount: u128) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Bitcoin.id(),
            dest_chain: DEST,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(txid),
            asset_id: AssetId(asset),
            amount,
            recipient: Recipient(recipient),
            finality_depth: 6,
            observed_height: 800_000,
            expiry_height: 900_000,
        }
    }

    fn bitcoin_pool(state: &mut BridgeState) -> PoolView {
        match handle(
            state,
            Request::CreatePool(pool_request(Network::Bitcoin.id(), "BTC")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        }
    }

    #[test]
    fn create_then_list_round_trips_the_new_pool() {
        let mut state = empty_state(0);
        let created = handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Polygon.id(), "GHO")),
        );
        let view = match created {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        };
        assert_eq!(view.identifier, "GHO");
        assert_eq!(view.tier, "Federated");
        assert_eq!(view.asset_id, derive_asset_id(Network::Polygon, "GHO").0);

        let listed = handle(
            &mut state,
            Request::ListPools(ListPoolsRequest {
                network_id: Some(Network::Polygon.id()),
            }),
        );
        match listed {
            Response::Pools(pools) => {
                assert_eq!(pools.len(), 1);
                assert_eq!(pools[0], view);
            }
            other => panic!("expected Pools, got {:?}", other),
        }
    }

    #[test]
    fn get_pool_reads_a_created_pool_and_reports_a_missing_one() {
        let mut state = empty_state(0);
        let view = match handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Ethereum.id(), "PEPE")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        };
        let got = handle(
            &mut state,
            Request::GetPool(GetPoolRequest {
                asset_id: view.asset_id,
            }),
        );
        assert_eq!(got, Response::Pool(view));
        let missing = handle(
            &mut state,
            Request::GetPool(GetPoolRequest {
                asset_id: [0xee; 16],
            }),
        );
        assert_eq!(
            missing,
            Response::Error(ApiError::PoolNotRegistered([0xee; 16]))
        );
    }

    #[test]
    fn a_duplicate_create_is_reported_as_a_pool_error() {
        let mut state = empty_state(0);
        handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Polygon.id(), "GHO")),
        );
        let again = handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Polygon.id(), "GHO")),
        );
        assert_eq!(again, Response::Error(ApiError::Pool(PoolError::DuplicatePool)));
    }

    #[test]
    fn listing_by_an_unknown_network_is_an_error_and_listing_all_returns_the_seed_set() {
        let mut state = BridgeState::seeded(Gateway::new(DEST, OperatorSet::new(0), 1_000_000_000_000));
        let bad = handle(
            &mut state,
            Request::ListPools(ListPoolsRequest { network_id: Some(44) }),
        );
        assert_eq!(bad, Response::Error(ApiError::UnknownNetwork(44)));
        match handle(&mut state, Request::ListPools(ListPoolsRequest { network_id: None })) {
            Response::Pools(pools) => assert_eq!(pools.len(), state.pools.len()),
            other => panic!("expected Pools, got {:?}", other),
        }
    }

    #[test]
    fn a_federated_deposit_is_routed_to_the_quorum_admission_and_mints() {
        let ops: Vec<Op> = (0..4).map(mk).collect();
        let mut set = OperatorSet::new(3);
        for op in &ops {
            set.register(op.id, op.pk);
        }
        let mut state = BridgeState::new(Gateway::new(DEST, set, 1_000_000_000_000));
        let view = match handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Solana.id(), "SOL")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        };
        for op in &ops {
            state
                .sources
                .declare(Network::Solana.id(), op.id, SourceEndpoint([0x10 + op.id as u8; 32]));
        }
        let fact = federated_fact(view.asset_id, [0x11; 32]);
        let env = AttestationEnvelope {
            fact: fact.clone(),
            signatures: vec![attest(&ops[0], &fact), attest(&ops[1], &fact), attest(&ops[2], &fact)],
        };
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Federated(env),
            }),
        );
        match response {
            Response::DepositAdmitted(DepositOutcome::Minted(receipt)) => {
                assert_eq!(receipt.amount, 500);
                assert_eq!(receipt.asset_id, view.asset_id);
            }
            other => panic!("expected a minted federated deposit, got {:?}", other),
        }
        let status = handle(
            &mut state,
            Request::DepositStatus(DepositStatusRequest {
                source_ref: [0x11; 32],
                asset_id: view.asset_id,
            }),
        );
        assert_eq!(
            status,
            Response::Status(DepositStatusView {
                source_ref: [0x11; 32],
                asset_id: view.asset_id,
                minted: true,
                asset_minted_total: 500,
                asset_cap: Some(1_000_000),
            })
        );
    }

    #[test]
    fn a_bitcoin_deposit_with_valid_anchored_material_is_verified_server_side_and_admitted() {
        let mut state = empty_state(0);
        let view = bitcoin_pool(&mut state);
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let (material, anchor, txid) = bitcoin_deposit(&bridge, recipient, 250_000);
        state.set_bitcoin_anchor(anchor);
        let fact = bitcoin_fact(view.asset_id, txid, recipient, 250_000);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { material, fact },
            }),
        );
        match response {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 250_000);
                assert_eq!(mint.asset_id, view.asset_id);
                assert_eq!(mint.source_ref, txid);
            }
            other => panic!("expected a trustless admission, got {:?}", other),
        }
        let status = handle(
            &mut state,
            Request::DepositStatus(DepositStatusRequest {
                source_ref: txid,
                asset_id: view.asset_id,
            }),
        );
        match status {
            Response::Status(view) => {
                assert!(view.minted, "the server-verified admission binds the reference");
                assert_eq!(view.asset_minted_total, 250_000);
            }
            other => panic!("expected Status, got {:?}", other),
        }
    }

    #[test]
    fn a_bitcoin_deposit_that_does_not_verify_against_the_pinned_checkpoint_is_rejected() {
        let mut state = empty_state(0);
        let view = bitcoin_pool(&mut state);
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let (material, _anchor, txid) = bitcoin_deposit(&bridge, recipient, 250_000);
        let foreign = BitcoinAnchor {
            checkpoint: Checkpoint {
                height: 0,
                hash: [0x99u8; 32],
                min_work: U256::ZERO,
            },
            params: EASY,
        };
        state.set_bitcoin_anchor(foreign);
        let fact = bitcoin_fact(view.asset_id, txid, recipient, 250_000);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { material, fact },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::BitcoinSpv(SpvError::CheckpointMismatch))
        );
        assert_eq!(state.gateway.minted_of_asset(&view.asset_id), 0);
    }

    #[test]
    fn a_bitcoin_deposit_with_no_pinned_anchor_is_refused() {
        let mut state = empty_state(0);
        let view = bitcoin_pool(&mut state);
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let (material, _anchor, txid) = bitcoin_deposit(&bridge, recipient, 250_000);
        let fact = bitcoin_fact(view.asset_id, txid, recipient, 250_000);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { material, fact },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::NoAnchor(Network::Bitcoin.id()))
        );
    }

    #[test]
    fn a_proof_that_does_not_match_the_pool_tier_is_refused() {
        let ops: Vec<Op> = (0..4).map(mk).collect();
        let mut set = OperatorSet::new(3);
        for op in &ops {
            set.register(op.id, op.pk);
        }
        let mut state = BridgeState::new(Gateway::new(DEST, set, 1_000_000_000_000));
        let view = match handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Solana.id(), "SOL")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        };
        let bridge = p2pkh([0x11; 20]);
        let (material, _anchor, _txid) = bitcoin_deposit(&bridge, [0x42; 32], 500);
        let mut fact = federated_fact(view.asset_id, [0x11; 32]);
        fact.finality_depth = 40;
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { material, fact },
            }),
        );
        assert_eq!(response, Response::Error(ApiError::ProofTierMismatch));
    }

    #[test]
    fn a_deposit_whose_asset_belongs_to_another_network_is_refused() {
        let mut state = empty_state(0);
        let view = match handle(
            &mut state,
            Request::CreatePool(pool_request(Network::Ethereum.id(), "USDC")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        };
        let mut fact = federated_fact(view.asset_id, [0x11; 32]);
        fact.source_chain = Network::Solana.id();
        let env = AttestationEnvelope {
            fact: fact.clone(),
            signatures: vec![],
        };
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Federated(env),
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::AssetNetworkMismatch {
                fact_network: Network::Solana.id(),
                pool_network: Network::Ethereum.id(),
            })
        );
    }

    #[test]
    fn a_deposit_for_an_unregistered_asset_or_unknown_network_is_refused() {
        let mut state = empty_state(0);
        let fact = federated_fact([0xee; 16], [0x11; 32]);
        let env = AttestationEnvelope {
            fact,
            signatures: vec![],
        };
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Federated(env),
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::PoolNotRegistered([0xee; 16]))
        );

        let mut unknown = federated_fact([0xee; 16], [0x12; 32]);
        unknown.source_chain = 44;
        let env = AttestationEnvelope {
            fact: unknown,
            signatures: vec![],
        };
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Federated(env),
            }),
        );
        assert_eq!(response, Response::Error(ApiError::UnknownNetwork(44)));
    }
}
