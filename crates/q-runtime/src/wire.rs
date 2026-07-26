// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::Artifact;
use q_assets::Network;
use q_codec::{BridgeFact, CodecError};
use q_federated::{FederatedError, PoolError, PoolRequest, TrustlessError, TrustlessMint};
use q_gateway::{GatewayError, MintReceipt};
use q_qbridge::{
    ApiError, BitcoinProofMaterial, DepositOutcome, DepositProof, DepositRequest,
    DepositStatusRequest, DepositStatusView, GetPoolRequest, ListPoolsRequest, PoolView, Request,
    Response,
};
use qlc_bitcoin::{BlockHeader, MerkleStep, SpvError};

use crate::json::{from_hex, object, to_hex, Json};

/// Every rejection the wire raises before the dispatcher is reached. A transport frame that names no
/// method is a not-found, everything else the request layer refuses is a bad request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    UnknownMethod(String),
    BadBody(String),
    Missing(&'static str),
    BadType(&'static str),
    BadField(&'static str),
    BadHex(&'static str),
    BadLen { field: &'static str, expected: usize, got: usize },
    BadNumber(&'static str),
    BadProofKind(String),
    BadEnvelope,
    BadFact,
    UnknownResult(String),
    UnknownErrorCode(String),
}

impl WireError {
    pub fn http(&self) -> (u16, &'static str, String) {
        match self {
            WireError::UnknownMethod(m) => {
                (404, "unknown_method", format!("no method {m} under /v1/"))
            }
            WireError::BadBody(e) => (400, "bad_request", format!("the body is not JSON, {e}")),
            other => (400, "bad_request", format!("{other:?}")),
        }
    }
}

fn field<'a>(j: &'a Json, key: &'static str) -> Result<&'a Json, WireError> {
    j.get(key).ok_or(WireError::Missing(key))
}

fn as_str<'a>(j: &'a Json, name: &'static str) -> Result<&'a str, WireError> {
    j.as_str().ok_or(WireError::BadType(name))
}

fn as_bool(j: &Json, name: &'static str) -> Result<bool, WireError> {
    j.as_bool().ok_or(WireError::BadType(name))
}

fn as_u64(j: &Json, name: &'static str) -> Result<u64, WireError> {
    j.as_u64().ok_or(WireError::BadType(name))
}

fn as_u32(j: &Json, name: &'static str) -> Result<u32, WireError> {
    let n = as_u64(j, name)?;
    u32::try_from(n).map_err(|_| WireError::BadNumber(name))
}

fn as_u8(j: &Json, name: &'static str) -> Result<u8, WireError> {
    let n = as_u64(j, name)?;
    u8::try_from(n).map_err(|_| WireError::BadNumber(name))
}

fn as_usize(j: &Json, name: &'static str) -> Result<usize, WireError> {
    Ok(as_u64(j, name)? as usize)
}

fn as_u128(j: &Json, name: &'static str) -> Result<u128, WireError> {
    match j {
        Json::Str(s) => s.parse::<u128>().map_err(|_| WireError::BadNumber(name)),
        Json::Int(n) => Ok(*n as u128),
        _ => Err(WireError::BadType(name)),
    }
}

fn as_hex(j: &Json, name: &'static str) -> Result<Vec<u8>, WireError> {
    from_hex(as_str(j, name)?).map_err(|_| WireError::BadHex(name))
}

fn hex_array<const N: usize>(j: &Json, name: &'static str) -> Result<[u8; N], WireError> {
    let bytes = as_hex(j, name)?;
    if bytes.len() != N {
        return Err(WireError::BadLen {
            field: name,
            expected: N,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn u128s(v: u128) -> Json {
    Json::str(v.to_string())
}

fn hexs(bytes: &[u8]) -> Json {
    Json::str(to_hex(bytes))
}

fn u32j(v: u32) -> Json {
    Json::Int(v as u64)
}

fn usizej(v: usize) -> Json {
    Json::Int(v as u64)
}

fn static_tier(s: &str) -> Result<&'static str, WireError> {
    match s {
        "Federated" => Ok("Federated"),
        "ProofBacked" => Ok("ProofBacked"),
        _ => Err(WireError::BadField("tier")),
    }
}

pub fn method_of(req: &Request) -> &'static str {
    match req {
        Request::CreatePool(_) => "create_pool",
        Request::ListPools(_) => "list_pools",
        Request::GetPool(_) => "get_pool",
        Request::SubmitDeposit(_) => "submit_deposit",
        Request::DepositStatus(_) => "deposit_status",
    }
}

pub fn encode_request(req: &Request) -> Json {
    match req {
        Request::CreatePool(r) => object(vec![
            ("network_id", u32j(r.network_id)),
            ("identifier", Json::str(r.identifier.clone())),
            ("decimals", Json::Int(r.decimals as u64)),
            ("per_asset_cap", u128s(r.per_asset_cap)),
            ("per_epoch_cap", u128s(r.per_epoch_cap)),
        ]),
        Request::ListPools(r) => object(vec![(
            "network_id",
            match r.network_id {
                Some(id) => u32j(id),
                None => Json::Null,
            },
        )]),
        Request::GetPool(r) => object(vec![("asset_id", hexs(&r.asset_id))]),
        Request::SubmitDeposit(r) => object(vec![("proof", encode_proof(&r.proof))]),
        Request::DepositStatus(r) => object(vec![
            ("source_ref", hexs(&r.source_ref)),
            ("asset_id", hexs(&r.asset_id)),
        ]),
    }
}

pub fn decode_request(method: &str, body: &Json) -> Result<Request, WireError> {
    match method {
        "create_pool" => Ok(Request::CreatePool(PoolRequest {
            network_id: as_u32(field(body, "network_id")?, "network_id")?,
            identifier: as_str(field(body, "identifier")?, "identifier")?.to_string(),
            decimals: as_u8(field(body, "decimals")?, "decimals")?,
            per_asset_cap: as_u128(field(body, "per_asset_cap")?, "per_asset_cap")?,
            per_epoch_cap: as_u128(field(body, "per_epoch_cap")?, "per_epoch_cap")?,
        })),
        "list_pools" => {
            let network_id = match body.get("network_id") {
                None => None,
                Some(v) if v.is_null() => None,
                Some(v) => Some(as_u32(v, "network_id")?),
            };
            Ok(Request::ListPools(ListPoolsRequest { network_id }))
        }
        "get_pool" => Ok(Request::GetPool(GetPoolRequest {
            asset_id: hex_array::<16>(field(body, "asset_id")?, "asset_id")?,
        })),
        "submit_deposit" => Ok(Request::SubmitDeposit(DepositRequest {
            proof: decode_proof(field(body, "proof")?)?,
        })),
        "deposit_status" => Ok(Request::DepositStatus(DepositStatusRequest {
            source_ref: hex_array::<32>(field(body, "source_ref")?, "source_ref")?,
            asset_id: hex_array::<16>(field(body, "asset_id")?, "asset_id")?,
        })),
        other => Err(WireError::UnknownMethod(other.to_string())),
    }
}

fn encode_proof(proof: &DepositProof) -> Json {
    match proof {
        DepositProof::Federated(env) => object(vec![
            ("kind", Json::str("federated")),
            ("envelope", hexs(&env.encode())),
        ]),
        DepositProof::Bitcoin { material, fact } => object(vec![
            ("kind", Json::str("bitcoin")),
            (
                "headers",
                Json::Array(material.headers.iter().map(|h| hexs(&h.serialize())).collect()),
            ),
            ("start_height", u32j(material.start_height)),
            ("deposit_height", u32j(material.deposit_height)),
            (
                "branch",
                Json::Array(
                    material
                        .branch
                        .iter()
                        .map(|s| {
                            object(vec![
                                ("hash", hexs(&s.hash)),
                                ("sibling_on_left", Json::Bool(s.sibling_on_left)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("raw_tx", hexs(&material.raw_tx)),
            ("deposit_script", hexs(&material.deposit_script)),
            ("fact", hexs(&fact.encode())),
        ]),
        DepositProof::Ethereum { .. } => object(vec![("kind", Json::str("ethereum"))]),
        DepositProof::Cosmos { .. } => object(vec![("kind", Json::str("cosmos"))]),
    }
}

fn decode_fact(j: &Json) -> Result<BridgeFact, WireError> {
    BridgeFact::decode(&as_hex(field(j, "fact")?, "fact")?).map_err(|_| WireError::BadFact)
}

fn decode_proof(j: &Json) -> Result<DepositProof, WireError> {
    let kind = as_str(field(j, "kind")?, "kind")?;
    match kind {
        "federated" => {
            let bytes = as_hex(field(j, "envelope")?, "envelope")?;
            match q_airlock::parse(&bytes) {
                Ok(Artifact::Attestation(env)) => Ok(DepositProof::Federated(env)),
                _ => Err(WireError::BadEnvelope),
            }
        }
        "bitcoin" => {
            let headers_json = field(j, "headers")?
                .as_array()
                .ok_or(WireError::BadType("headers"))?;
            let mut headers = Vec::with_capacity(headers_json.len());
            for h in headers_json {
                let bytes = as_hex(h, "headers")?;
                headers.push(BlockHeader::parse(&bytes).map_err(|_| WireError::BadField("headers"))?);
            }
            let branch_json = field(j, "branch")?
                .as_array()
                .ok_or(WireError::BadType("branch"))?;
            let mut branch = Vec::with_capacity(branch_json.len());
            for s in branch_json {
                branch.push(MerkleStep {
                    hash: hex_array::<32>(field(s, "hash")?, "hash")?,
                    sibling_on_left: as_bool(field(s, "sibling_on_left")?, "sibling_on_left")?,
                });
            }
            Ok(DepositProof::Bitcoin {
                material: BitcoinProofMaterial {
                    headers,
                    start_height: as_u32(field(j, "start_height")?, "start_height")?,
                    deposit_height: as_u32(field(j, "deposit_height")?, "deposit_height")?,
                    branch,
                    raw_tx: as_hex(field(j, "raw_tx")?, "raw_tx")?,
                    deposit_script: as_hex(field(j, "deposit_script")?, "deposit_script")?,
                },
                fact: decode_fact(j)?,
            })
        }
        "ethereum" | "cosmos" => Err(WireError::BadProofKind(kind.to_string())),
        other => Err(WireError::BadProofKind(other.to_string())),
    }
}

fn pool_view_json(v: &PoolView) -> Json {
    object(vec![
        ("network_id", u32j(v.network_id)),
        ("network_name", Json::str(v.network_name)),
        ("identifier", Json::str(v.identifier.clone())),
        ("decimals", Json::Int(v.decimals as u64)),
        ("asset_id", hexs(&v.asset_id)),
        ("per_asset_cap", u128s(v.per_asset_cap)),
        ("per_epoch_cap", u128s(v.per_epoch_cap)),
        ("tier", Json::str(v.tier)),
    ])
}

fn pool_view_from(j: &Json) -> Result<PoolView, WireError> {
    let network_id = as_u32(field(j, "network_id")?, "network_id")?;
    let network_name = Network::from_id(network_id)
        .ok_or(WireError::BadField("network_id"))?
        .name();
    Ok(PoolView {
        network_id,
        network_name,
        identifier: as_str(field(j, "identifier")?, "identifier")?.to_string(),
        decimals: as_u8(field(j, "decimals")?, "decimals")?,
        asset_id: hex_array::<16>(field(j, "asset_id")?, "asset_id")?,
        per_asset_cap: as_u128(field(j, "per_asset_cap")?, "per_asset_cap")?,
        per_epoch_cap: as_u128(field(j, "per_epoch_cap")?, "per_epoch_cap")?,
        tier: static_tier(as_str(field(j, "tier")?, "tier")?)?,
    })
}

fn outcome_json(outcome: &DepositOutcome) -> Json {
    match outcome {
        DepositOutcome::Minted(r) => object(vec![
            ("status", Json::str("minted")),
            ("asset_id", hexs(&r.asset_id)),
            ("recipient", hexs(&r.recipient)),
            ("amount", u128s(r.amount)),
            ("source_ref", hexs(&r.source_ref)),
        ]),
        DepositOutcome::AdmittedPendingChainMint(m) => object(vec![
            ("status", Json::str("admitted_pending_chain_mint")),
            ("asset_id", hexs(&m.asset_id)),
            ("recipient", hexs(&m.recipient)),
            ("amount", u128s(m.amount)),
            ("source_ref", hexs(&m.source_ref)),
            ("source_chain", u32j(m.source_chain)),
            ("confirmations", u32j(m.confirmations)),
        ]),
    }
}

fn outcome_from(j: &Json) -> Result<DepositOutcome, WireError> {
    match as_str(field(j, "status")?, "status")? {
        "minted" => Ok(DepositOutcome::Minted(MintReceipt {
            asset_id: hex_array::<16>(field(j, "asset_id")?, "asset_id")?,
            recipient: hex_array::<32>(field(j, "recipient")?, "recipient")?,
            amount: as_u128(field(j, "amount")?, "amount")?,
            source_ref: hex_array::<32>(field(j, "source_ref")?, "source_ref")?,
        })),
        "admitted_pending_chain_mint" => {
            Ok(DepositOutcome::AdmittedPendingChainMint(TrustlessMint {
                asset_id: hex_array::<16>(field(j, "asset_id")?, "asset_id")?,
                recipient: hex_array::<32>(field(j, "recipient")?, "recipient")?,
                amount: as_u128(field(j, "amount")?, "amount")?,
                source_ref: hex_array::<32>(field(j, "source_ref")?, "source_ref")?,
                source_chain: as_u32(field(j, "source_chain")?, "source_chain")?,
                confirmations: as_u32(field(j, "confirmations")?, "confirmations")?,
            }))
        }
        other => Err(WireError::UnknownResult(other.to_string())),
    }
}

pub fn encode_response(resp: &Response) -> Json {
    match resp {
        Response::PoolCreated(v) => object(vec![
            ("result", Json::str("pool_created")),
            ("pool", pool_view_json(v)),
        ]),
        Response::Pools(vs) => object(vec![
            ("result", Json::str("pools")),
            ("pools", Json::Array(vs.iter().map(pool_view_json).collect())),
        ]),
        Response::Pool(v) => object(vec![
            ("result", Json::str("pool")),
            ("pool", pool_view_json(v)),
        ]),
        Response::DepositAdmitted(outcome) => object(vec![
            ("result", Json::str("deposit_admitted")),
            ("outcome", outcome_json(outcome)),
        ]),
        Response::Status(v) => object(vec![
            ("result", Json::str("status")),
            ("source_ref", hexs(&v.source_ref)),
            ("asset_id", hexs(&v.asset_id)),
            ("minted", Json::Bool(v.minted)),
            ("asset_minted_total", u128s(v.asset_minted_total)),
            (
                "asset_cap",
                match v.asset_cap {
                    Some(cap) => u128s(cap),
                    None => Json::Null,
                },
            ),
        ]),
        Response::Error(api) => object(vec![
            ("result", Json::str("error")),
            ("error", api_json(api)),
        ]),
    }
}

pub fn decode_response(j: &Json) -> Result<Response, WireError> {
    match as_str(field(j, "result")?, "result")? {
        "pool_created" => Ok(Response::PoolCreated(pool_view_from(field(j, "pool")?)?)),
        "pool" => Ok(Response::Pool(pool_view_from(field(j, "pool")?)?)),
        "pools" => {
            let items = field(j, "pools")?
                .as_array()
                .ok_or(WireError::BadType("pools"))?;
            let mut views = Vec::with_capacity(items.len());
            for item in items {
                views.push(pool_view_from(item)?);
            }
            Ok(Response::Pools(views))
        }
        "deposit_admitted" => Ok(Response::DepositAdmitted(outcome_from(field(j, "outcome")?)?)),
        "status" => Ok(Response::Status(DepositStatusView {
            source_ref: hex_array::<32>(field(j, "source_ref")?, "source_ref")?,
            asset_id: hex_array::<16>(field(j, "asset_id")?, "asset_id")?,
            minted: as_bool(field(j, "minted")?, "minted")?,
            asset_minted_total: as_u128(field(j, "asset_minted_total")?, "asset_minted_total")?,
            asset_cap: match field(j, "asset_cap")? {
                v if v.is_null() => None,
                v => Some(as_u128(v, "asset_cap")?),
            },
        })),
        "error" => Ok(Response::Error(api_from(field(j, "error")?)?)),
        other => Err(WireError::UnknownResult(other.to_string())),
    }
}

fn tagged(category: &str, code: &str, mut fields: Vec<(&str, Json)>) -> Json {
    let mut all = vec![
        ("category".to_string(), Json::str(category)),
        ("code".to_string(), Json::str(code)),
    ];
    all.extend(fields.drain(..).map(|(k, v)| (k.to_string(), v)));
    Json::Object(all)
}

fn code_of(j: &Json) -> Result<&str, WireError> {
    as_str(field(j, "code")?, "code")
}

fn api_json(api: &ApiError) -> Json {
    match api {
        ApiError::UnknownNetwork(id) => {
            tagged("api", "unknown_network", vec![("network_id", u32j(*id))])
        }
        ApiError::PoolNotRegistered(a) => {
            tagged("api", "pool_not_registered", vec![("asset_id", hexs(a))])
        }
        ApiError::AssetNetworkMismatch {
            fact_network,
            pool_network,
        } => tagged(
            "api",
            "asset_network_mismatch",
            vec![
                ("fact_network", u32j(*fact_network)),
                ("pool_network", u32j(*pool_network)),
            ],
        ),
        ApiError::ProofTierMismatch => tagged("api", "proof_tier_mismatch", vec![]),
        ApiError::NoAnchor(id) => tagged("api", "no_anchor", vec![("network_id", u32j(*id))]),
        ApiError::BitcoinSpv(e) => tagged("api", "bitcoin_spv", vec![("spv", spv_err_json(e))]),
        ApiError::Pool(e) => pool_err_json(e),
        ApiError::Federated(e) => federated_err_json(e),
        ApiError::Trustless(e) => trustless_err_json(e),
    }
}

fn spv_err_json(e: &SpvError) -> Json {
    match e {
        SpvError::ShortHeader => tagged("spv", "short_header", vec![]),
        SpvError::PowNotMet => tagged("spv", "pow_not_met", vec![]),
        SpvError::TargetBelowFloor { index } => {
            tagged("spv", "target_below_floor", vec![("index", usizej(*index))])
        }
        SpvError::BrokenLink { index } => {
            tagged("spv", "broken_link", vec![("index", usizej(*index))])
        }
        SpvError::EmptyChain => tagged("spv", "empty_chain", vec![]),
        SpvError::MerkleMismatch => tagged("spv", "merkle_mismatch", vec![]),
        SpvError::RetargetOnANonBoundary { index } => {
            tagged("spv", "retarget_on_a_non_boundary", vec![("index", usizej(*index))])
        }
        SpvError::RetargetMismatch { index } => {
            tagged("spv", "retarget_mismatch", vec![("index", usizej(*index))])
        }
        SpvError::HeightOverflow => tagged("spv", "height_overflow", vec![]),
        SpvError::HeightOutOfRange => tagged("spv", "height_out_of_range", vec![]),
        SpvError::InsufficientConfirmations { have, need } => tagged(
            "spv",
            "insufficient_confirmations",
            vec![("have", u32j(*have)), ("need", u32j(*need))],
        ),
        SpvError::CheckpointNotInChain => tagged("spv", "checkpoint_not_in_chain", vec![]),
        SpvError::CheckpointMismatch => tagged("spv", "checkpoint_mismatch", vec![]),
        SpvError::InsufficientWork => tagged("spv", "insufficient_work", vec![]),
        SpvError::MalformedTransaction => tagged("spv", "malformed_transaction", vec![]),
        SpvError::TransactionMismatch => tagged("spv", "transaction_mismatch", vec![]),
    }
}

fn spv_err_from(j: &Json) -> Result<SpvError, WireError> {
    match code_of(j)? {
        "short_header" => Ok(SpvError::ShortHeader),
        "pow_not_met" => Ok(SpvError::PowNotMet),
        "target_below_floor" => Ok(SpvError::TargetBelowFloor {
            index: as_usize(field(j, "index")?, "index")?,
        }),
        "broken_link" => Ok(SpvError::BrokenLink {
            index: as_usize(field(j, "index")?, "index")?,
        }),
        "empty_chain" => Ok(SpvError::EmptyChain),
        "merkle_mismatch" => Ok(SpvError::MerkleMismatch),
        "retarget_on_a_non_boundary" => Ok(SpvError::RetargetOnANonBoundary {
            index: as_usize(field(j, "index")?, "index")?,
        }),
        "retarget_mismatch" => Ok(SpvError::RetargetMismatch {
            index: as_usize(field(j, "index")?, "index")?,
        }),
        "height_overflow" => Ok(SpvError::HeightOverflow),
        "height_out_of_range" => Ok(SpvError::HeightOutOfRange),
        "insufficient_confirmations" => Ok(SpvError::InsufficientConfirmations {
            have: as_u32(field(j, "have")?, "have")?,
            need: as_u32(field(j, "need")?, "need")?,
        }),
        "checkpoint_not_in_chain" => Ok(SpvError::CheckpointNotInChain),
        "checkpoint_mismatch" => Ok(SpvError::CheckpointMismatch),
        "insufficient_work" => Ok(SpvError::InsufficientWork),
        "malformed_transaction" => Ok(SpvError::MalformedTransaction),
        "transaction_mismatch" => Ok(SpvError::TransactionMismatch),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn api_from(j: &Json) -> Result<ApiError, WireError> {
    match as_str(field(j, "category")?, "category")? {
        "api" => match code_of(j)? {
            "unknown_network" => Ok(ApiError::UnknownNetwork(as_u32(
                field(j, "network_id")?,
                "network_id",
            )?)),
            "pool_not_registered" => Ok(ApiError::PoolNotRegistered(hex_array::<16>(
                field(j, "asset_id")?,
                "asset_id",
            )?)),
            "asset_network_mismatch" => Ok(ApiError::AssetNetworkMismatch {
                fact_network: as_u32(field(j, "fact_network")?, "fact_network")?,
                pool_network: as_u32(field(j, "pool_network")?, "pool_network")?,
            }),
            "proof_tier_mismatch" => Ok(ApiError::ProofTierMismatch),
            "no_anchor" => Ok(ApiError::NoAnchor(as_u32(
                field(j, "network_id")?,
                "network_id",
            )?)),
            "bitcoin_spv" => Ok(ApiError::BitcoinSpv(spv_err_from(field(j, "spv")?)?)),
            other => Err(WireError::UnknownErrorCode(other.to_string())),
        },
        "pool" => Ok(ApiError::Pool(pool_err_from(j)?)),
        "federated" => Ok(ApiError::Federated(federated_err_from(j)?)),
        "trustless" => Ok(ApiError::Trustless(trustless_err_from(j)?)),
        _ => Err(WireError::BadField("category")),
    }
}

fn pool_err_json(e: &PoolError) -> Json {
    match e {
        PoolError::UnknownNetwork(id) => {
            tagged("pool", "unknown_network", vec![("network_id", u32j(*id))])
        }
        PoolError::MalformedIdentifier => tagged("pool", "malformed_identifier", vec![]),
        PoolError::DecimalsTooLarge { decimals, max } => tagged(
            "pool",
            "decimals_too_large",
            vec![
                ("decimals", Json::Int(*decimals as u64)),
                ("max", Json::Int(*max as u64)),
            ],
        ),
        PoolError::ZeroCap => tagged("pool", "zero_cap", vec![]),
        PoolError::CapTooLarge { cap, max } => tagged(
            "pool",
            "cap_too_large",
            vec![("cap", u128s(*cap)), ("max", u128s(*max))],
        ),
        PoolError::EpochCapAboveAssetCap { epoch, asset } => tagged(
            "pool",
            "epoch_cap_above_asset_cap",
            vec![("epoch", u128s(*epoch)), ("asset", u128s(*asset))],
        ),
        PoolError::DuplicatePool => tagged("pool", "duplicate_pool", vec![]),
        PoolError::AssetIdMismatch => tagged("pool", "asset_id_mismatch", vec![]),
        PoolError::TierMismatch => tagged("pool", "tier_mismatch", vec![]),
        PoolError::RegistryFull { max } => {
            tagged("pool", "registry_full", vec![("max", usizej(*max))])
        }
    }
}

fn pool_err_from(j: &Json) -> Result<PoolError, WireError> {
    match code_of(j)? {
        "unknown_network" => Ok(PoolError::UnknownNetwork(as_u32(
            field(j, "network_id")?,
            "network_id",
        )?)),
        "malformed_identifier" => Ok(PoolError::MalformedIdentifier),
        "decimals_too_large" => Ok(PoolError::DecimalsTooLarge {
            decimals: as_u8(field(j, "decimals")?, "decimals")?,
            max: as_u8(field(j, "max")?, "max")?,
        }),
        "zero_cap" => Ok(PoolError::ZeroCap),
        "cap_too_large" => Ok(PoolError::CapTooLarge {
            cap: as_u128(field(j, "cap")?, "cap")?,
            max: as_u128(field(j, "max")?, "max")?,
        }),
        "epoch_cap_above_asset_cap" => Ok(PoolError::EpochCapAboveAssetCap {
            epoch: as_u128(field(j, "epoch")?, "epoch")?,
            asset: as_u128(field(j, "asset")?, "asset")?,
        }),
        "duplicate_pool" => Ok(PoolError::DuplicatePool),
        "asset_id_mismatch" => Ok(PoolError::AssetIdMismatch),
        "tier_mismatch" => Ok(PoolError::TierMismatch),
        "registry_full" => Ok(PoolError::RegistryFull {
            max: as_usize(field(j, "max")?, "max")?,
        }),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn trustless_err_json(e: &TrustlessError) -> Json {
    match e {
        TrustlessError::NotProofBacked => tagged("trustless", "not_proof_backed", vec![]),
        TrustlessError::SourceMismatch { corridor, fact } => tagged(
            "trustless",
            "source_mismatch",
            vec![("corridor", u32j(*corridor)), ("fact", u32j(*fact))],
        ),
        TrustlessError::ReferenceMismatch => tagged("trustless", "reference_mismatch", vec![]),
        TrustlessError::AmountMismatch { proven, fact } => tagged(
            "trustless",
            "amount_mismatch",
            vec![("proven", u128s(*proven)), ("fact", u128s(*fact))],
        ),
        TrustlessError::RecipientMismatch => tagged("trustless", "recipient_mismatch", vec![]),
        TrustlessError::AssetMismatch => tagged("trustless", "asset_mismatch", vec![]),
        TrustlessError::InsufficientConfirmations { have, need } => tagged(
            "trustless",
            "insufficient_confirmations",
            vec![("have", u32j(*have)), ("need", u32j(*need))],
        ),
        TrustlessError::ReplayedReference => tagged("trustless", "replayed_reference", vec![]),
        TrustlessError::AssetNotRegistered => tagged("trustless", "asset_not_registered", vec![]),
        TrustlessError::AssetCapExceeded { minted, cap, add } => tagged(
            "trustless",
            "asset_cap_exceeded",
            vec![
                ("minted", u128s(*minted)),
                ("cap", u128s(*cap)),
                ("add", u128s(*add)),
            ],
        ),
        TrustlessError::Gateway(g) => {
            tagged("trustless", "gateway", vec![("gateway", gateway_err_json(g))])
        }
    }
}

fn trustless_err_from(j: &Json) -> Result<TrustlessError, WireError> {
    match code_of(j)? {
        "not_proof_backed" => Ok(TrustlessError::NotProofBacked),
        "source_mismatch" => Ok(TrustlessError::SourceMismatch {
            corridor: as_u32(field(j, "corridor")?, "corridor")?,
            fact: as_u32(field(j, "fact")?, "fact")?,
        }),
        "reference_mismatch" => Ok(TrustlessError::ReferenceMismatch),
        "amount_mismatch" => Ok(TrustlessError::AmountMismatch {
            proven: as_u128(field(j, "proven")?, "proven")?,
            fact: as_u128(field(j, "fact")?, "fact")?,
        }),
        "recipient_mismatch" => Ok(TrustlessError::RecipientMismatch),
        "asset_mismatch" => Ok(TrustlessError::AssetMismatch),
        "insufficient_confirmations" => Ok(TrustlessError::InsufficientConfirmations {
            have: as_u32(field(j, "have")?, "have")?,
            need: as_u32(field(j, "need")?, "need")?,
        }),
        "replayed_reference" => Ok(TrustlessError::ReplayedReference),
        "asset_not_registered" => Ok(TrustlessError::AssetNotRegistered),
        "asset_cap_exceeded" => Ok(TrustlessError::AssetCapExceeded {
            minted: as_u128(field(j, "minted")?, "minted")?,
            cap: as_u128(field(j, "cap")?, "cap")?,
            add: as_u128(field(j, "add")?, "add")?,
        }),
        "gateway" => Ok(TrustlessError::Gateway(gateway_err_from(field(j, "gateway")?)?)),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn federated_err_json(e: &FederatedError) -> Json {
    match e {
        FederatedError::Foreign => tagged("federated", "foreign", vec![]),
        FederatedError::NotFederated => tagged("federated", "not_federated", vec![]),
        FederatedError::UndeclaredSource(id) => tagged(
            "federated",
            "undeclared_source",
            vec![("operator_id", u32j(*id))],
        ),
        FederatedError::CorrelatedSources {
            independent,
            signers,
        } => tagged(
            "federated",
            "correlated_sources",
            vec![
                ("independent", usizej(*independent)),
                ("signers", usizej(*signers)),
            ],
        ),
        FederatedError::Gateway(g) => tagged(
            "federated",
            "gateway",
            vec![("gateway", gateway_err_json(g))],
        ),
    }
}

fn federated_err_from(j: &Json) -> Result<FederatedError, WireError> {
    match code_of(j)? {
        "foreign" => Ok(FederatedError::Foreign),
        "not_federated" => Ok(FederatedError::NotFederated),
        "undeclared_source" => Ok(FederatedError::UndeclaredSource(as_u32(
            field(j, "operator_id")?,
            "operator_id",
        )?)),
        "correlated_sources" => Ok(FederatedError::CorrelatedSources {
            independent: as_usize(field(j, "independent")?, "independent")?,
            signers: as_usize(field(j, "signers")?, "signers")?,
        }),
        "gateway" => Ok(FederatedError::Gateway(gateway_err_from(field(
            j, "gateway",
        )?)?)),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn codec_err_json(e: &CodecError) -> Json {
    match e {
        CodecError::ShortInput => tagged("codec", "short_input", vec![]),
        CodecError::TrailingBytes => tagged("codec", "trailing_bytes", vec![]),
        CodecError::UnknownTag(t) => {
            tagged("codec", "unknown_tag", vec![("tag", Json::Int(*t as u64))])
        }
        CodecError::BadVersion(v) => {
            tagged("codec", "bad_version", vec![("version", Json::Int(*v as u64))])
        }
        CodecError::ZeroAmount => tagged("codec", "zero_amount", vec![]),
        CodecError::ZeroAsset => tagged("codec", "zero_asset", vec![]),
        CodecError::ZeroRecipient => tagged("codec", "zero_recipient", vec![]),
        CodecError::ZeroSourceRef => tagged("codec", "zero_source_ref", vec![]),
        CodecError::ZeroChain => tagged("codec", "zero_chain", vec![]),
        CodecError::LengthMismatch => tagged("codec", "length_mismatch", vec![]),
    }
}

fn codec_err_from(j: &Json) -> Result<CodecError, WireError> {
    match code_of(j)? {
        "short_input" => Ok(CodecError::ShortInput),
        "trailing_bytes" => Ok(CodecError::TrailingBytes),
        "unknown_tag" => Ok(CodecError::UnknownTag(as_u8(field(j, "tag")?, "tag")?)),
        "bad_version" => Ok(CodecError::BadVersion(as_u8(field(j, "version")?, "version")?)),
        "zero_amount" => Ok(CodecError::ZeroAmount),
        "zero_asset" => Ok(CodecError::ZeroAsset),
        "zero_recipient" => Ok(CodecError::ZeroRecipient),
        "zero_source_ref" => Ok(CodecError::ZeroSourceRef),
        "zero_chain" => Ok(CodecError::ZeroChain),
        "length_mismatch" => Ok(CodecError::LengthMismatch),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn gateway_err_json(e: &GatewayError) -> Json {
    match e {
        GatewayError::GlobalPause => tagged("gateway", "global_pause", vec![]),
        GatewayError::WrongDirection => tagged("gateway", "wrong_direction", vec![]),
        GatewayError::WrongDestination => tagged("gateway", "wrong_destination", vec![]),
        GatewayError::CorridorNotOpen(c) => tagged(
            "gateway",
            "corridor_not_open",
            vec![("source_chain", u32j(*c))],
        ),
        GatewayError::CorridorInactive(c) => tagged(
            "gateway",
            "corridor_inactive",
            vec![("source_chain", u32j(*c))],
        ),
        GatewayError::SourcePaused(c) => {
            tagged("gateway", "source_paused", vec![("source_chain", u32j(*c))])
        }
        GatewayError::InsufficientFinality { got, need } => tagged(
            "gateway",
            "insufficient_finality",
            vec![("got", u32j(*got)), ("need", u32j(*need))],
        ),
        GatewayError::AssetNotRegistered => tagged("gateway", "asset_not_registered", vec![]),
        GatewayError::AssetCapExceeded { minted, cap, add } => tagged(
            "gateway",
            "asset_cap_exceeded",
            vec![
                ("minted", u128s(*minted)),
                ("cap", u128s(*cap)),
                ("add", u128s(*add)),
            ],
        ),
        GatewayError::EpochCapExceeded { minted, cap, add } => tagged(
            "gateway",
            "epoch_cap_exceeded",
            vec![
                ("minted", u128s(*minted)),
                ("cap", u128s(*cap)),
                ("add", u128s(*add)),
            ],
        ),
        GatewayError::ReplayedReference => tagged("gateway", "replayed_reference", vec![]),
        GatewayError::UnknownOperator(id) => tagged(
            "gateway",
            "unknown_operator",
            vec![("operator_id", u32j(*id))],
        ),
        GatewayError::BadSignature(id) => {
            tagged("gateway", "bad_signature", vec![("operator_id", u32j(*id))])
        }
        GatewayError::BelowThreshold { got, need } => tagged(
            "gateway",
            "below_threshold",
            vec![("got", usizej(*got)), ("need", usizej(*need))],
        ),
        GatewayError::ThinQuorum { quorum, size } => tagged(
            "gateway",
            "thin_quorum",
            vec![("quorum", usizej(*quorum)), ("size", usizej(*size))],
        ),
        GatewayError::ProveNothing => tagged("gateway", "prove_nothing", vec![]),
        GatewayError::InvalidFact(c) => {
            tagged("gateway", "invalid_fact", vec![("codec", codec_err_json(c))])
        }
        GatewayError::Unauthorized => tagged("gateway", "unauthorized", vec![]),
        GatewayError::NoGovernanceSet => tagged("gateway", "no_governance_set", vec![]),
        GatewayError::TierDowngrade { from, to } => tagged(
            "gateway",
            "tier_downgrade",
            vec![
                ("from", Json::Int(*from as u64)),
                ("to", Json::Int(*to as u64)),
            ],
        ),
        GatewayError::Frozen { until } => {
            tagged("gateway", "frozen", vec![("until", Json::Int(*until))])
        }
        GatewayError::WatchdogWindowTooWide { until, max } => tagged(
            "gateway",
            "watchdog_window_too_wide",
            vec![("until", Json::Int(*until)), ("max", Json::Int(*max))],
        ),
        GatewayError::StaleBatch { got, expected } => tagged(
            "gateway",
            "stale_batch",
            vec![("got", Json::Int(*got)), ("expected", Json::Int(*expected))],
        ),
        GatewayError::ExitExceedsMinted { minted, amount } => tagged(
            "gateway",
            "exit_exceeds_minted",
            vec![("minted", u128s(*minted)), ("amount", u128s(*amount))],
        ),
        GatewayError::ExitNotReady { now, unlock } => tagged(
            "gateway",
            "exit_not_ready",
            vec![("now", Json::Int(*now)), ("unlock", Json::Int(*unlock))],
        ),
        GatewayError::UnknownExit(id) => {
            tagged("gateway", "unknown_exit", vec![("exit_id", Json::Int(*id))])
        }
        GatewayError::MessageExpired { now, expiry } => tagged(
            "gateway",
            "message_expired",
            vec![("now", Json::Int(*now)), ("expiry", Json::Int(*expiry))],
        ),
        GatewayError::StaleOrReplayedNonce { got, high_water } => tagged(
            "gateway",
            "stale_or_replayed_nonce",
            vec![
                ("got", Json::Int(*got)),
                ("high_water", Json::Int(*high_water)),
            ],
        ),
    }
}

fn gateway_err_from(j: &Json) -> Result<GatewayError, WireError> {
    match code_of(j)? {
        "global_pause" => Ok(GatewayError::GlobalPause),
        "wrong_direction" => Ok(GatewayError::WrongDirection),
        "wrong_destination" => Ok(GatewayError::WrongDestination),
        "corridor_not_open" => Ok(GatewayError::CorridorNotOpen(as_u32(
            field(j, "source_chain")?,
            "source_chain",
        )?)),
        "corridor_inactive" => Ok(GatewayError::CorridorInactive(as_u32(
            field(j, "source_chain")?,
            "source_chain",
        )?)),
        "source_paused" => Ok(GatewayError::SourcePaused(as_u32(
            field(j, "source_chain")?,
            "source_chain",
        )?)),
        "insufficient_finality" => Ok(GatewayError::InsufficientFinality {
            got: as_u32(field(j, "got")?, "got")?,
            need: as_u32(field(j, "need")?, "need")?,
        }),
        "asset_not_registered" => Ok(GatewayError::AssetNotRegistered),
        "asset_cap_exceeded" => Ok(GatewayError::AssetCapExceeded {
            minted: as_u128(field(j, "minted")?, "minted")?,
            cap: as_u128(field(j, "cap")?, "cap")?,
            add: as_u128(field(j, "add")?, "add")?,
        }),
        "epoch_cap_exceeded" => Ok(GatewayError::EpochCapExceeded {
            minted: as_u128(field(j, "minted")?, "minted")?,
            cap: as_u128(field(j, "cap")?, "cap")?,
            add: as_u128(field(j, "add")?, "add")?,
        }),
        "replayed_reference" => Ok(GatewayError::ReplayedReference),
        "unknown_operator" => Ok(GatewayError::UnknownOperator(as_u32(
            field(j, "operator_id")?,
            "operator_id",
        )?)),
        "bad_signature" => Ok(GatewayError::BadSignature(as_u32(
            field(j, "operator_id")?,
            "operator_id",
        )?)),
        "below_threshold" => Ok(GatewayError::BelowThreshold {
            got: as_usize(field(j, "got")?, "got")?,
            need: as_usize(field(j, "need")?, "need")?,
        }),
        "thin_quorum" => Ok(GatewayError::ThinQuorum {
            quorum: as_usize(field(j, "quorum")?, "quorum")?,
            size: as_usize(field(j, "size")?, "size")?,
        }),
        "prove_nothing" => Ok(GatewayError::ProveNothing),
        "invalid_fact" => Ok(GatewayError::InvalidFact(codec_err_from(field(
            j, "codec",
        )?)?)),
        "unauthorized" => Ok(GatewayError::Unauthorized),
        "no_governance_set" => Ok(GatewayError::NoGovernanceSet),
        "tier_downgrade" => Ok(GatewayError::TierDowngrade {
            from: as_u8(field(j, "from")?, "from")?,
            to: as_u8(field(j, "to")?, "to")?,
        }),
        "frozen" => Ok(GatewayError::Frozen {
            until: as_u64(field(j, "until")?, "until")?,
        }),
        "watchdog_window_too_wide" => Ok(GatewayError::WatchdogWindowTooWide {
            until: as_u64(field(j, "until")?, "until")?,
            max: as_u64(field(j, "max")?, "max")?,
        }),
        "stale_batch" => Ok(GatewayError::StaleBatch {
            got: as_u64(field(j, "got")?, "got")?,
            expected: as_u64(field(j, "expected")?, "expected")?,
        }),
        "exit_exceeds_minted" => Ok(GatewayError::ExitExceedsMinted {
            minted: as_u128(field(j, "minted")?, "minted")?,
            amount: as_u128(field(j, "amount")?, "amount")?,
        }),
        "exit_not_ready" => Ok(GatewayError::ExitNotReady {
            now: as_u64(field(j, "now")?, "now")?,
            unlock: as_u64(field(j, "unlock")?, "unlock")?,
        }),
        "unknown_exit" => Ok(GatewayError::UnknownExit(as_u64(
            field(j, "exit_id")?,
            "exit_id",
        )?)),
        "message_expired" => Ok(GatewayError::MessageExpired {
            now: as_u64(field(j, "now")?, "now")?,
            expiry: as_u64(field(j, "expiry")?, "expiry")?,
        }),
        "stale_or_replayed_nonce" => Ok(GatewayError::StaleOrReplayedNonce {
            got: as_u64(field(j, "got")?, "got")?,
            high_water: as_u64(field(j, "high_water")?, "high_water")?,
        }),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;
    use q_airlock::{AttestationEnvelope, SignerSig};
    use q_codec::{AssetId, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION};
    use qtv_crypto::ml_dsa;

    fn round_request(req: Request) {
        let body = encode_request(&req);
        let text = body.render();
        let reparsed = parse(&text).expect("the encoded request is valid JSON");
        let back = decode_request(method_of(&req), &reparsed).expect("the request round trips");
        assert_eq!(req, back);
    }

    fn round_response(resp: Response) {
        let body = encode_response(&resp);
        let text = body.render();
        let reparsed = parse(&text).expect("the encoded response is valid JSON");
        let back = decode_response(&reparsed).expect("the response round trips");
        assert_eq!(resp, back);
    }

    fn sample_fact() -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            direction: Direction::Deposit,
            nonce: 42,
            source_ref: SourceRef([9u8; 32]),
            asset_id: AssetId([3u8; 16]),
            amount: 1_000_000,
            recipient: Recipient([5u8; 32]),
            finality_depth: 12,
            observed_height: 880_000,
            expiry_height: 900_000,
        }
    }

    #[test]
    fn create_pool_round_trips() {
        round_request(Request::CreatePool(PoolRequest {
            network_id: 4,
            identifier: "GHO".to_string(),
            decimals: 18,
            per_asset_cap: 340_282_366_920_938_463_463_374_607_431_768_211_455,
            per_epoch_cap: 500_000,
        }));
    }

    #[test]
    fn list_and_get_pool_round_trip() {
        round_request(Request::ListPools(ListPoolsRequest { network_id: Some(22) }));
        round_request(Request::ListPools(ListPoolsRequest { network_id: None }));
        round_request(Request::GetPool(GetPoolRequest { asset_id: [0xab; 16] }));
    }

    #[test]
    fn deposit_status_round_trips() {
        round_request(Request::DepositStatus(DepositStatusRequest {
            source_ref: [0x11; 32],
            asset_id: [0x22; 16],
        }));
    }

    #[test]
    fn a_federated_deposit_round_trips_through_the_envelope_frame() {
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let (_pk, sk) = ml_dsa::keygen(&seed);
        let fact = sample_fact();
        let sig = ml_dsa::sign(&sk, &fact.attest_preimage(), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
        let env = AttestationEnvelope {
            fact,
            signatures: vec![SignerSig {
                operator_id: 0,
                signature: sig.to_vec(),
            }],
        };
        round_request(Request::SubmitDeposit(DepositRequest {
            proof: DepositProof::Federated(env),
        }));
    }

    #[test]
    fn a_bitcoin_deposit_round_trips_its_raw_material_and_fact() {
        let material = BitcoinProofMaterial {
            headers: vec![BlockHeader {
                version: 1,
                prev_block: [0xaa; 32],
                merkle_root: [0xbb; 32],
                timestamp: 1_700_000_000,
                bits: 0x207f_ffff,
                nonce: 42,
            }],
            start_height: 100,
            deposit_height: 100,
            branch: vec![MerkleStep {
                hash: [0xcc; 32],
                sibling_on_left: true,
            }],
            raw_tx: vec![0x01, 0x02, 0x03, 0x04],
            deposit_script: vec![0x76, 0xa9, 0x14],
        };
        round_request(Request::SubmitDeposit(DepositRequest {
            proof: DepositProof::Bitcoin {
                material,
                fact: sample_fact(),
            },
        }));
    }

    #[test]
    fn an_ethereum_proof_from_an_untrusted_client_is_refused() {
        let body = object(vec![("proof", object(vec![("kind", Json::str("ethereum"))]))]);
        assert!(matches!(
            decode_request("submit_deposit", &body),
            Err(WireError::BadProofKind(_))
        ));
    }

    #[test]
    fn a_cosmos_proof_from_an_untrusted_client_is_refused() {
        let body = object(vec![("proof", object(vec![("kind", Json::str("cosmos"))]))]);
        assert!(matches!(
            decode_request("submit_deposit", &body),
            Err(WireError::BadProofKind(_))
        ));
    }

    #[test]
    fn a_pool_view_response_round_trips() {
        round_response(Response::Pool(PoolView {
            network_id: 2,
            network_name: "Ethereum",
            identifier: "USDC".to_string(),
            decimals: 6,
            asset_id: [0x9a; 16],
            per_asset_cap: 1_000_000,
            per_epoch_cap: 500_000,
            tier: "ProofBacked",
        }));
    }

    #[test]
    fn both_deposit_outcomes_round_trip() {
        round_response(Response::DepositAdmitted(DepositOutcome::Minted(MintReceipt {
            asset_id: [0x9a; 16],
            recipient: [0x42; 32],
            amount: 500,
            source_ref: [0x11; 32],
        })));
        round_response(Response::DepositAdmitted(
            DepositOutcome::AdmittedPendingChainMint(TrustlessMint {
                asset_id: [0x9a; 16],
                recipient: [0x42; 32],
                amount: 250_000,
                source_ref: [0x11; 32],
                source_chain: 0,
                confirmations: 6,
            }),
        ));
    }

    #[test]
    fn a_status_response_round_trips_with_and_without_a_cap() {
        round_response(Response::Status(DepositStatusView {
            source_ref: [0x11; 32],
            asset_id: [0x22; 16],
            minted: true,
            asset_minted_total: 500,
            asset_cap: Some(1_000_000),
        }));
        round_response(Response::Status(DepositStatusView {
            source_ref: [0x11; 32],
            asset_id: [0x22; 16],
            minted: false,
            asset_minted_total: 0,
            asset_cap: None,
        }));
    }

    #[test]
    fn the_error_responses_round_trip_across_every_category() {
        round_response(Response::Error(ApiError::UnknownNetwork(8)));
        round_response(Response::Error(ApiError::PoolNotRegistered([0xee; 16])));
        round_response(Response::Error(ApiError::ProofTierMismatch));
        round_response(Response::Error(ApiError::AssetNetworkMismatch {
            fact_network: 22,
            pool_network: 2,
        }));
        round_response(Response::Error(ApiError::Pool(PoolError::DuplicatePool)));
        round_response(Response::Error(ApiError::Pool(PoolError::CapTooLarge {
            cap: 9,
            max: 8,
        })));
        round_response(Response::Error(ApiError::Trustless(
            TrustlessError::AmountMismatch {
                proven: 1,
                fact: 2,
            },
        )));
        round_response(Response::Error(ApiError::Federated(
            FederatedError::CorrelatedSources {
                independent: 2,
                signers: 3,
            },
        )));
        round_response(Response::Error(ApiError::Federated(FederatedError::Gateway(
            GatewayError::BelowThreshold { got: 2, need: 3 },
        ))));
        round_response(Response::Error(ApiError::Federated(FederatedError::Gateway(
            GatewayError::InvalidFact(CodecError::ZeroAmount),
        ))));
    }

    #[test]
    fn an_unknown_method_is_refused() {
        assert_eq!(
            decode_request("no_such_method", &object(vec![])),
            Err(WireError::UnknownMethod("no_such_method".to_string()))
        );
    }

    #[test]
    fn a_garbage_body_is_refused_at_each_typed_field() {
        assert!(decode_request("get_pool", &object(vec![])).is_err());
        assert!(decode_request(
            "get_pool",
            &object(vec![("asset_id", Json::str("zz"))])
        )
        .is_err());
        assert!(decode_request(
            "get_pool",
            &object(vec![("asset_id", Json::str("ab"))])
        )
        .is_err());
        assert!(decode_request(
            "submit_deposit",
            &object(vec![("proof", object(vec![("kind", Json::str("dogecoin"))]))])
        )
        .is_err());
        assert!(decode_request(
            "submit_deposit",
            &object(vec![(
                "proof",
                object(vec![
                    ("kind", Json::str("federated")),
                    ("envelope", Json::str("00ff")),
                ]),
            )])
        )
        .is_err());
    }
}
