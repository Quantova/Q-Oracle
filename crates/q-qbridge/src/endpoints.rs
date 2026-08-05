// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::AttestationEnvelope;
use q_assets::Network;
use q_codec::BridgeFact;
use q_federated::{
    admit, admit_bitcoin_trustless, admit_cosmos_trustless, admit_ethereum_trustless, corridor_for,
    install_all, install_pool, Corridor, FederatedError, PoolError, PoolRegistry, PoolRequest,
    PoolSpec, SourceRegistry, Tier, TrustlessError, TrustlessMint,
};
use q_gateway::{Gateway, MintReceipt};
use qlc_bitcoin::{
    verify_chain, verify_trustless_deposit, BlockHeader, Checkpoint, MerkleStep, NetworkParams,
    SpvError,
};
use qlc_cosmos::commit::{Commit, Header};
use qlc_cosmos::light::TrustedState;
use qlc_cosmos::proof::ExistenceProof;
use qlc_cosmos::validator::ValidatorSet;
use qlc_cosmos::{ChainConfig, CorridorError};
use qlc_ethereum::{DepositProof as EthDepositProof, EthError, LightClientStore, LightClientUpdate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinProofMaterial {
    pub headers: Vec<BlockHeader>,
    pub start_height: u32,
    pub deposit_height: u32,
    pub branch: Vec<MerkleStep>,
    pub raw_tx: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinAnchor {
    pub checkpoint: Checkpoint,
    pub params: NetworkParams,
    pub bridge_script: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosAnchor {
    pub config: ChainConfig,
    pub trusted: TrustedState,
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
    Ethereum {
        update: LightClientUpdate,
        deposit: EthDepositProof,
        fact: BridgeFact,
    },
    Cosmos {
        header: Header,
        commit: Commit,
        validators: ValidatorSet,
        proof: ExistenceProof,
        fact: BridgeFact,
    },
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
    EthereumVerify(EthError),
    CosmosVerify(CorridorError),
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
    pub ethereum_store: Option<LightClientStore>,
    pub cosmos_anchor: Option<CosmosAnchor>,
}

impl BridgeState {
    pub fn new(gateway: Gateway) -> BridgeState {
        BridgeState {
            pools: PoolRegistry::new(),
            gateway,
            sources: SourceRegistry::new(),
            bitcoin_anchor: None,
            ethereum_store: None,
            cosmos_anchor: None,
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
            ethereum_store: None,
            cosmos_anchor: None,
        }
    }

    pub fn set_bitcoin_anchor(&mut self, anchor: BitcoinAnchor) {
        self.bitcoin_anchor = Some(anchor);
    }

    pub fn set_ethereum_anchor(&mut self, store: LightClientStore) {
        self.ethereum_store = Some(store);
    }

    pub fn set_cosmos_anchor(&mut self, anchor: CosmosAnchor) {
        self.cosmos_anchor = Some(anchor);
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

pub struct DepositPlan {
    corridor: Corridor,
    kind: PlanKind,
}

enum PlanKind {
    Federated(AttestationEnvelope),
    Bitcoin { proven: qlc_bitcoin::TrustlessDeposit, fact: BridgeFact },
    Ethereum { proven: qlc_ethereum::TrustlessDeposit, fact: BridgeFact },
    Cosmos { proven: qlc_cosmos::TrustlessDeposit, fact: BridgeFact },
}

fn resolve_corridor(
    state: &BridgeState,
    proof: &DepositProof,
) -> Result<(Tier, Network, Corridor), ApiError> {
    let source_chain = proof.fact().source_chain;
    let asset_id = proof.fact().asset_id.0;
    let network = Network::from_id(source_chain).ok_or(ApiError::UnknownNetwork(source_chain))?;
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
    Ok((tier, network, corridor_for(network, cap)))
}

fn cosmos_wall_now() -> qlc_cosmos::proto::Timestamp {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    qlc_cosmos::proto::Timestamp {
        seconds: elapsed.as_secs() as i64,
        nanos: elapsed.subsec_nanos() as i32,
    }
}

pub fn verify_deposit(state: &BridgeState, request: &DepositRequest) -> Result<DepositPlan, ApiError> {
    let (tier, network, corridor) = resolve_corridor(state, &request.proof)?;
    let kind = match (tier, network, &request.proof) {
        (Tier::Federated, _, DepositProof::Federated(env)) => PlanKind::Federated(env.clone()),
        (Tier::ProofBacked, Network::Bitcoin, DepositProof::Bitcoin { material, fact }) => {
            let (params, checkpoint, bridge_script) = {
                let anchor = state
                    .bitcoin_anchor
                    .as_ref()
                    .ok_or(ApiError::NoAnchor(Network::Bitcoin.id()))?;
                if anchor.checkpoint.min_work.is_zero() || anchor.bridge_script.is_empty() {
                    return Err(ApiError::NoAnchor(Network::Bitcoin.id()));
                }
                (anchor.params, anchor.checkpoint.clone(), anchor.bridge_script.clone())
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
                &bridge_script,
            )
            .map_err(ApiError::BitcoinSpv)?;
            PlanKind::Bitcoin { proven, fact: fact.clone() }
        }
        (Tier::ProofBacked, Network::Ethereum, DepositProof::Ethereum { update, deposit, fact }) => {
            let store = state
                .ethereum_store
                .as_ref()
                .ok_or(ApiError::NoAnchor(Network::Ethereum.id()))?;
            let verifier = q_bls::Bls12381AggregateVerifier::new();
            let proven = qlc_ethereum::verify_trustless_deposit(store, update, deposit, &verifier)
                .map_err(ApiError::EthereumVerify)?;
            PlanKind::Ethereum { proven, fact: fact.clone() }
        }
        (
            Tier::ProofBacked,
            Network::Cosmos,
            DepositProof::Cosmos {
                header,
                commit,
                validators,
                proof,
                fact,
            },
        ) => {
            let anchor = state
                .cosmos_anchor
                .as_ref()
                .ok_or(ApiError::NoAnchor(Network::Cosmos.id()))?;
            let proven = qlc_cosmos::verify_trustless_deposit(
                &anchor.config,
                &anchor.trusted,
                header,
                commit,
                validators,
                proof,
                cosmos_wall_now(),
            )
            .map_err(ApiError::CosmosVerify)?;
            PlanKind::Cosmos { proven, fact: fact.clone() }
        }
        _ => return Err(ApiError::ProofTierMismatch),
    };
    Ok(DepositPlan { corridor, kind })
}

pub fn commit_deposit(
    state: &mut BridgeState,
    plan: DepositPlan,
) -> Result<DepositOutcome, ApiError> {
    let DepositPlan { corridor, kind } = plan;
    match kind {
        PlanKind::Federated(env) => {
            let receipt = admit(&mut state.gateway, &corridor, &state.sources, &env)
                .map_err(ApiError::Federated)?;
            Ok(DepositOutcome::Minted(receipt))
        }
        PlanKind::Bitcoin { proven, fact } => {
            let mint = admit_bitcoin_trustless(&mut state.gateway, &corridor, &proven, &fact)
                .map_err(ApiError::Trustless)?;
            Ok(DepositOutcome::AdmittedPendingChainMint(mint))
        }
        PlanKind::Ethereum { proven, fact } => {
            let mint = admit_ethereum_trustless(&mut state.gateway, &corridor, &proven, &fact)
                .map_err(ApiError::Trustless)?;
            Ok(DepositOutcome::AdmittedPendingChainMint(mint))
        }
        PlanKind::Cosmos { proven, fact } => {
            let mint = admit_cosmos_trustless(&mut state.gateway, &corridor, &proven, &fact)
                .map_err(ApiError::Trustless)?;
            Ok(DepositOutcome::AdmittedPendingChainMint(mint))
        }
    }
}

fn dispatch_deposit(
    state: &mut BridgeState,
    request: DepositRequest,
) -> Result<DepositOutcome, ApiError> {
    let plan = verify_deposit(state, &request)?;
    commit_deposit(state, plan)
}

pub fn handle_read(state: &BridgeState, request: &Request) -> Option<Response> {
    match request {
        Request::ListPools(request) => {
            let views: Vec<PoolView> = match request.network_id {
                Some(id) => match Network::from_id(id) {
                    Some(network) => state
                        .pools
                        .by_network(network)
                        .into_iter()
                        .map(PoolView::from)
                        .collect(),
                    None => return Some(Response::Error(ApiError::UnknownNetwork(id))),
                },
                None => state.pools.all().map(PoolView::from).collect(),
            };
            Some(Response::Pools(views))
        }
        Request::GetPool(request) => Some(match state.pools.get(&request.asset_id) {
            Some(spec) => Response::Pool(PoolView::from(spec)),
            None => Response::Error(ApiError::PoolNotRegistered(request.asset_id)),
        }),
        Request::DepositStatus(request) => Some(Response::Status(deposit_status(state, request))),
        _ => None,
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

    const DEST_ID: u64 = 0x0000_002a_0000_2328;
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
        BridgeState::new(Gateway::new(DEST, DEST_ID, OperatorSet::new(threshold), 1_000_000_000_000))
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
        let sig = ml_dsa::sign(&op.sk, &fact.attest_preimage(DEST_ID), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
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
            min_work: U256::ONE,
        };
        let material = BitcoinProofMaterial {
            headers,
            start_height: 0,
            deposit_height: 0,
            branch: vec![],
            raw_tx: raw,
        };
        (
            material,
            BitcoinAnchor { checkpoint, params: EASY, bridge_script: bridge.to_vec() },
            txid,
        )
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
        let mut state = BridgeState::seeded(Gateway::new(DEST, DEST_ID, OperatorSet::new(0), 1_000_000_000_000));
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
        let mut state = BridgeState::new(Gateway::new(DEST, DEST_ID, set, 1_000_000_000_000));
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
    fn a_bitcoin_deposit_paying_a_script_other_than_the_pinned_bridge_script_is_refused() {
        let mut state = empty_state(0);
        let view = bitcoin_pool(&mut state);
        let attacker = p2pkh([0xaau8; 20]);
        let recipient = [0x42u8; 32];
        let (material, mut anchor, txid) = bitcoin_deposit(&attacker, recipient, 250_000);
        anchor.bridge_script = p2pkh([0x11u8; 20]);
        state.set_bitcoin_anchor(anchor);
        let fact = bitcoin_fact(view.asset_id, txid, recipient, 250_000);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { material, fact },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::BitcoinSpv(SpvError::TransactionMismatch)),
            "a real payment to an attacker chosen script, not the pinned bridge script, mints nothing"
        );
        assert_eq!(state.gateway.minted_of_asset(&view.asset_id), 0);
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
                min_work: U256::ONE,
            },
            params: EASY,
            bridge_script: bridge.to_vec(),
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
    fn a_present_bitcoin_anchor_with_a_zero_work_floor_is_refused_fail_closed() {
        let mut state = empty_state(0);
        let view = bitcoin_pool(&mut state);
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let (material, anchor, txid) = bitcoin_deposit(&bridge, recipient, 250_000);
        let unset = BitcoinAnchor {
            checkpoint: Checkpoint {
                min_work: U256::ZERO,
                ..anchor.checkpoint.clone()
            },
            params: anchor.params,
            bridge_script: anchor.bridge_script.clone(),
        };
        state.set_bitcoin_anchor(unset);
        let fact = bitcoin_fact(view.asset_id, txid, recipient, 250_000);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin {
                    material: material.clone(),
                    fact: fact.clone(),
                },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::NoAnchor(Network::Bitcoin.id())),
            "a present anchor with a zero cumulative-work floor cannot verify: a self-mined floor-difficulty chain must not admit"
        );
        assert_eq!(state.gateway.minted_of_asset(&view.asset_id), 0);

        state.set_bitcoin_anchor(anchor);
        let admitted = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Bitcoin { material, fact },
            }),
        );
        match admitted {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 250_000);
            }
            other => panic!("a non-trivial work floor must verify, got {:?}", other),
        }
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
        let mut state = BridgeState::new(Gateway::new(DEST, DEST_ID, set, 1_000_000_000_000));
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

    use blst::min_pk::{AggregateSignature, SecretKey as BlsSecretKey};
    use q_bls::{Bls12381AggregateVerifier, ETH_SYNC_COMMITTEE_DST};
    use qlc_ethereum::beacon::{
        compute_domain, compute_signing_root, current_sync_committee_layout, BeaconBlockHeader,
        SyncAggregate, SyncCommittee, CURRENT_SYNC_COMMITTEE_DEPTH, DOMAIN_SYNC_COMMITTEE,
        EXECUTION_RECEIPTS_DEPTH, EXECUTION_RECEIPTS_INDEX, FINALIZED_ROOT_DEPTH,
        FINALIZED_ROOT_INDEX,
    };
    use qlc_ethereum::bls::{BlsPubkey, BlsSignature};
    use qlc_ethereum::config as eth_config;
    use qlc_ethereum::mpt::builder as mpt_builder;
    use qlc_ethereum::receipt::fixtures::deposit_receipt;
    use qlc_ethereum::{bootstrap, rlp, ssz, ExecutionCommit};

    const ETH_PERIOD: u64 = 870;
    const ETH_PERIOD_SLOTS: u64 = 32 * 256;
    const ETH_SIG_SLOT: u64 = ETH_PERIOD * ETH_PERIOD_SLOTS + 100;

    fn eth_secret(seed: u8, i: usize) -> BlsSecretKey {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        ikm[1] = (i & 0xff) as u8;
        ikm[2] = ((i >> 8) & 0xff) as u8;
        ikm[31] = 0xa5;
        BlsSecretKey::key_gen(&ikm, &[]).unwrap()
    }

    fn eth_committee(seed: u8) -> (SyncCommittee, Vec<BlsSecretKey>) {
        let secrets: Vec<BlsSecretKey> = (0..512).map(|i| eth_secret(seed, i)).collect();
        let pubkeys: Vec<BlsPubkey> = secrets
            .iter()
            .map(|s| BlsPubkey(s.sk_to_pk().compress()))
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

    fn eth_full_participation() -> Vec<bool> {
        let mut p = vec![false; 512];
        p[..400].fill(true);
        p
    }

    fn eth_aggregate(secrets: &[BlsSecretKey], participation: &[bool], root: &[u8; 32]) -> BlsSignature {
        let mut sigs = Vec::new();
        for (i, present) in participation.iter().enumerate() {
            if *present {
                sigs.push(secrets[i].sign(root, ETH_SYNC_COMMITTEE_DST, &[]));
            }
        }
        let refs: Vec<&_> = sigs.iter().collect();
        let agg = AggregateSignature::aggregate(&refs, false).unwrap();
        BlsSignature(agg.to_signature().compress())
    }

    fn eth_current_committee_branch() -> Vec<[u8; 32]> {
        (0..CURRENT_SYNC_COMMITTEE_DEPTH)
            .map(|i| [0xd0 + i as u8; 32])
            .collect()
    }

    fn eth_checkpoint(committee: &SyncCommittee) -> BeaconBlockHeader {
        let (index, _) = current_sync_committee_layout(false);
        let branch = eth_current_committee_branch();
        let leaf = committee.hash_tree_root();
        let state_root = ssz::merkle_root_from_branch(&leaf, &branch, index);
        BeaconBlockHeader {
            slot: ETH_PERIOD * ETH_PERIOD_SLOTS + 8,
            proposer_index: 5,
            parent_root: [0u8; 32],
            state_root,
            body_root: [0u8; 32],
        }
    }

    fn eth_bootstrapped_store(seed: u8) -> LightClientStore {
        let (committee, _) = eth_committee(seed);
        let checkpoint = eth_checkpoint(&committee);
        bootstrap(
            eth_config::ethereum(),
            ETH_PERIOD,
            checkpoint,
            committee,
            eth_current_committee_branch(),
        )
        .unwrap()
    }

    fn ethereum_fixture(
        asset_id: [u8; 16],
        recipient: [u8; 32],
        amount: u128,
    ) -> (LightClientStore, LightClientUpdate, EthDepositProof) {
        let cfg = eth_config::ethereum();
        let (committee, secrets) = eth_committee(0x11);

        let receipt = deposit_receipt(&cfg.deposit_contract, &recipient, amount, &asset_id);
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for i in 0..6u64 {
            let key = rlp::encode_uint(i);
            let value = if i == 3 {
                receipt.clone()
            } else {
                let mut v = b"other-receipt-payload-over-thirty-two-bytes-".to_vec();
                v.push(i as u8);
                v
            };
            entries.push((key, value));
        }
        let nibble_entries: Vec<(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .map(|(k, v)| {
                let mut nib = Vec::new();
                for b in k {
                    nib.push(b >> 4);
                    nib.push(b & 0x0f);
                }
                (nib, v.clone())
            })
            .collect();
        let trie = mpt_builder::build(nibble_entries);
        let receipts_root = mpt_builder::root_hash(&trie);
        let receipt_proof = mpt_builder::prove(&trie, &entries[3].0);

        let execution_branch: Vec<[u8; 32]> = (0..EXECUTION_RECEIPTS_DEPTH)
            .map(|i| [0xe0 + i as u8; 32])
            .collect();
        let body_root =
            ssz::merkle_root_from_branch(&receipts_root, &execution_branch, EXECUTION_RECEIPTS_INDEX);

        let finalized_header = BeaconBlockHeader {
            slot: ETH_PERIOD * ETH_PERIOD_SLOTS + 40,
            proposer_index: 99,
            parent_root: [0x01; 32],
            state_root: [0x02; 32],
            body_root,
        };
        let finalized_root = finalized_header.hash_tree_root();

        let finality_branch: Vec<[u8; 32]> = (0..FINALIZED_ROOT_DEPTH)
            .map(|i| [0xf0 + i as u8; 32])
            .collect();
        let attested_state_root =
            ssz::merkle_root_from_branch(&finalized_root, &finality_branch, FINALIZED_ROOT_INDEX);
        let attested_header = BeaconBlockHeader {
            slot: ETH_PERIOD * ETH_PERIOD_SLOTS + 60,
            proposer_index: 100,
            parent_root: [0x03; 32],
            state_root: attested_state_root,
            body_root: [0x04; 32],
        };

        let checkpoint = eth_checkpoint(&committee);
        let store = bootstrap(
            cfg.clone(),
            ETH_PERIOD,
            checkpoint,
            committee,
            eth_current_committee_branch(),
        )
        .unwrap();

        let participation = eth_full_participation();
        let fork_version = cfg.fork_version_at_slot(ETH_SIG_SLOT);
        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version.0, &cfg.genesis_validators_root);
        let signing_root = compute_signing_root(&attested_header.hash_tree_root(), &domain);
        let signature = eth_aggregate(&secrets, &participation, &signing_root);

        let update = LightClientUpdate {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate: SyncAggregate {
                participation,
                signature,
            },
            signature_slot: ETH_SIG_SLOT,
            execution: ExecutionCommit {
                receipts_root,
                block_number: 20_000_000,
                execution_branch,
            },
        };
        let deposit = EthDepositProof {
            receipt_index: 3,
            receipt_proof,
        };
        (store, update, deposit)
    }

    fn ethereum_pool(state: &mut BridgeState) -> PoolView {
        match handle(
            state,
            Request::CreatePool(pool_request(Network::Ethereum.id(), "USDC")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        }
    }

    fn ethereum_fact(
        asset: [u8; 16],
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
    ) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Ethereum.id(),
            dest_chain: DEST,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(source_ref),
            asset_id: AssetId(asset),
            amount,
            recipient: Recipient(recipient),
            finality_depth: 64,
            observed_height: 20_000_000,
            expiry_height: 21_000_000,
        }
    }

    #[test]
    fn an_ethereum_deposit_with_valid_anchored_material_is_verified_server_side_and_admitted() {
        let mut state = empty_state(0);
        let view = ethereum_pool(&mut state);
        let recipient = [0x5cu8; 32];
        let (store, update, deposit) = ethereum_fixture(view.asset_id, recipient, 250_000);
        let proven = qlc_ethereum::verify_trustless_deposit(
            &store,
            &update,
            &deposit,
            &Bls12381AggregateVerifier::new(),
        )
        .expect("the anchored material verifies");
        state.set_ethereum_anchor(store);
        let fact = ethereum_fact(view.asset_id, proven.source_ref(), proven.amount(), recipient);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Ethereum {
                    update,
                    deposit,
                    fact,
                },
            }),
        );
        match response {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 250_000);
                assert_eq!(mint.asset_id, view.asset_id);
                assert_eq!(mint.source_ref, proven.source_ref());
            }
            other => panic!("expected a trustless admission, got {:?}", other),
        }
        assert!(state.gateway.is_reference_used(&proven.source_ref()));
    }

    #[test]
    fn an_ethereum_deposit_that_does_not_verify_against_the_pinned_checkpoint_is_rejected() {
        let mut state = empty_state(0);
        let view = ethereum_pool(&mut state);
        let recipient = [0x5cu8; 32];
        let (_store, update, deposit) = ethereum_fixture(view.asset_id, recipient, 250_000);
        state.set_ethereum_anchor(eth_bootstrapped_store(0x22));
        let fact = ethereum_fact(view.asset_id, [0x77u8; 32], 250_000, recipient);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Ethereum {
                    update,
                    deposit,
                    fact,
                },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::EthereumVerify(EthError::BadSignature))
        );
        assert_eq!(state.gateway.minted_of_asset(&view.asset_id), 0);
    }

    #[test]
    fn an_ethereum_deposit_with_no_pinned_anchor_is_refused() {
        let mut state = empty_state(0);
        let view = ethereum_pool(&mut state);
        let recipient = [0x5cu8; 32];
        let (_store, update, deposit) = ethereum_fixture(view.asset_id, recipient, 250_000);
        let fact = ethereum_fact(view.asset_id, [0x00u8; 32], 250_000, recipient);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Ethereum {
                    update,
                    deposit,
                    fact,
                },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::NoAnchor(Network::Ethereum.id()))
        );
    }

    use qlc_cosmos::chain::COSMOS_HUB;
    use qlc_cosmos::commit::{BlockIdFlag, CommitSig};
    use qlc_cosmos::ed25519::{public_key_from_seed, sign};
    use qlc_cosmos::proof::{encode_deposit_value, InnerOp, LeafOp};
    use qlc_cosmos::proto::{vote_sign_bytes, BlockId, CanonicalVote, Timestamp, PRECOMMIT_TYPE};
    use qlc_cosmos::validator::ValidatorInfo;

    struct CosmosKeyed {
        seed: [u8; 32],
        info: ValidatorInfo,
    }

    fn cosmos_keyed(byte: u8, power: u64) -> CosmosKeyed {
        let seed = [byte; 32];
        CosmosKeyed {
            seed,
            info: ValidatorInfo {
                pubkey: public_key_from_seed(&seed),
                voting_power: power,
            },
        }
    }

    fn cosmos_deposit_proof(recipient: [u8; 32], asset: [u8; 16], amount: u128) -> ExistenceProof {
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
        }
    }

    fn cosmos_scene(
        recipient: [u8; 32],
        asset: [u8; 16],
        amount: u128,
    ) -> (Header, Commit, ValidatorSet, ExistenceProof) {
        let vs = [
            cosmos_keyed(1, 25),
            cosmos_keyed(2, 25),
            cosmos_keyed(3, 25),
            cosmos_keyed(4, 25),
        ];
        let set = ValidatorSet::new(vs.iter().map(|k| k.info).collect());
        let proof = cosmos_deposit_proof(recipient, asset, amount);
        let app_hash = proof.calculate_root();
        let header = Header {
            version_block: 11,
            version_app: 0,
            chain_id: COSMOS_HUB.chain_id.to_string(),
            height: 18_500_000,
            time: cosmos_wall_now(),
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

    fn cosmos_anchor_for(set: &ValidatorSet) -> CosmosAnchor {
        let mut trusted_time = cosmos_wall_now();
        trusted_time.seconds -= 3600;
        trusted_time.nanos = 0;
        CosmosAnchor {
            config: COSMOS_HUB,
            trusted: TrustedState {
                height: 0,
                time: trusted_time,
                header_hash: [0u8; 32],
                validators: set.clone(),
                next_validators_hash: set.hash().to_vec(),
            },
        }
    }

    fn cosmos_pool(state: &mut BridgeState) -> PoolView {
        match handle(
            state,
            Request::CreatePool(pool_request(Network::Cosmos.id(), "ATOM")),
        ) {
            Response::PoolCreated(view) => view,
            other => panic!("expected PoolCreated, got {:?}", other),
        }
    }

    fn cosmos_fact(
        asset: [u8; 16],
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
    ) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: Network::Cosmos.id(),
            dest_chain: DEST,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(source_ref),
            asset_id: AssetId(asset),
            amount,
            recipient: Recipient(recipient),
            finality_depth: COSMOS_HUB.confirmation_depth,
            observed_height: 18_500_000,
            expiry_height: 19_000_000,
        }
    }

    #[test]
    fn a_cosmos_deposit_with_valid_anchored_material_is_verified_server_side_and_admitted() {
        let mut state = empty_state(0);
        let view = cosmos_pool(&mut state);
        let recipient = [0x51u8; 32];
        let (header, commit, set, proof) = cosmos_scene(recipient, view.asset_id, 400_000);
        let anchor = cosmos_anchor_for(&set);
        let proven = qlc_cosmos::verify_trustless_deposit(
            &anchor.config,
            &anchor.trusted,
            &header,
            &commit,
            &set,
            &proof,
            header.time,
        )
        .expect("the anchored material verifies");
        state.set_cosmos_anchor(anchor);
        let fact = cosmos_fact(view.asset_id, proven.source_ref(), proven.amount(), recipient);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Cosmos {
                    header,
                    commit,
                    validators: set,
                    proof,
                    fact,
                },
            }),
        );
        match response {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 400_000);
                assert_eq!(mint.asset_id, view.asset_id);
                assert_eq!(mint.source_ref, proven.source_ref());
            }
            other => panic!("expected a trustless admission, got {:?}", other),
        }
        assert!(state.gateway.is_reference_used(&proven.source_ref()));
    }

    #[test]
    fn a_cosmos_deposit_that_does_not_verify_against_the_pinned_trusted_state_is_rejected() {
        let mut state = empty_state(0);
        let view = cosmos_pool(&mut state);
        let recipient = [0x51u8; 32];
        let (header, commit, set, proof) = cosmos_scene(recipient, view.asset_id, 400_000);
        let foreign = ValidatorSet::new(
            [
                cosmos_keyed(50, 25),
                cosmos_keyed(51, 25),
                cosmos_keyed(52, 25),
                cosmos_keyed(53, 25),
            ]
            .iter()
            .map(|k| k.info)
            .collect(),
        );
        state.set_cosmos_anchor(cosmos_anchor_for(&foreign));
        let fact = cosmos_fact(view.asset_id, [0x77u8; 32], 400_000, recipient);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Cosmos {
                    header,
                    commit,
                    validators: set,
                    proof,
                    fact,
                },
            }),
        );
        assert!(
            matches!(
                response,
                Response::Error(ApiError::CosmosVerify(CorridorError::Unanchored(_)))
            ),
            "a set that does not overlap the pinned trusted state is refused"
        );
        assert_eq!(state.gateway.minted_of_asset(&view.asset_id), 0);
    }

    #[test]
    fn a_cosmos_deposit_with_no_pinned_anchor_is_refused() {
        let mut state = empty_state(0);
        let view = cosmos_pool(&mut state);
        let recipient = [0x51u8; 32];
        let (header, commit, set, proof) = cosmos_scene(recipient, view.asset_id, 400_000);
        let fact = cosmos_fact(view.asset_id, [0x00u8; 32], 400_000, recipient);
        let response = handle(
            &mut state,
            Request::SubmitDeposit(DepositRequest {
                proof: DepositProof::Cosmos {
                    header,
                    commit,
                    validators: set,
                    proof,
                    fact,
                },
            }),
        );
        assert_eq!(
            response,
            Response::Error(ApiError::NoAnchor(Network::Cosmos.id()))
        );
    }
}
