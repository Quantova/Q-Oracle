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
use qlc_cosmos::commit::{BlockIdFlag, Commit, CommitError, CommitSig, Header};
use qlc_cosmos::light::LightError;
use qlc_cosmos::proof::{ExistenceProof, InnerOp, LeafOp, ProofError};
use qlc_cosmos::proto::{BlockId, Timestamp};
use qlc_cosmos::validator::{ValidatorInfo, ValidatorSet};
use qlc_cosmos::CorridorError;
use qlc_ethereum::beacon::{BeaconBlockHeader, SyncAggregate};
use qlc_ethereum::bls::BlsSignature;
use qlc_ethereum::mpt::MptError;
use qlc_ethereum::receipt::ReceiptError;
use qlc_ethereum::{DepositProof as EthDepositProof, EthError, ExecutionCommit, LightClientUpdate};

use crate::json::{from_hex, object, to_hex, Json};

pub const MAX_HEADERS: usize = 2048;

pub const MAX_BRANCH: usize = 64;

pub const MAX_PARTICIPATION: usize = 4096;

pub const MAX_PROOF_NODES: usize = 256;

pub const MAX_VALIDATORS: usize = 4096;

pub const MAX_PROOF_PATH: usize = 256;

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

fn as_i64(j: &Json, name: &'static str) -> Result<i64, WireError> {
    Ok(as_u64(j, name)? as i64)
}

fn as_i32(j: &Json, name: &'static str) -> Result<i32, WireError> {
    Ok(as_u64(j, name)? as i32)
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
        DepositProof::Ethereum {
            update,
            deposit,
            fact,
        } => object(vec![
            ("kind", Json::str("ethereum")),
            ("attested_header", header_json(&update.attested_header)),
            ("finalized_header", header_json(&update.finalized_header)),
            ("finality_branch", roots_json(&update.finality_branch)),
            (
                "participation",
                Json::Array(
                    update
                        .sync_aggregate
                        .participation
                        .iter()
                        .map(|b| Json::Bool(*b))
                        .collect(),
                ),
            ),
            ("signature", hexs(&update.sync_aggregate.signature.0)),
            ("signature_slot", Json::Int(update.signature_slot)),
            ("receipts_root", hexs(&update.execution.receipts_root)),
            ("block_number", Json::Int(update.execution.block_number)),
            ("execution_branch", roots_json(&update.execution.execution_branch)),
            ("receipt_index", Json::Int(deposit.receipt_index)),
            (
                "receipt_proof",
                Json::Array(deposit.receipt_proof.iter().map(|n| hexs(n)).collect()),
            ),
            ("fact", hexs(&fact.encode())),
        ]),
        DepositProof::Cosmos {
            header,
            commit,
            validators,
            proof,
            fact,
        } => object(vec![
            ("kind", Json::str("cosmos")),
            ("header", cosmos_header_json(header)),
            ("commit", commit_json(commit)),
            ("validators", validators_json(validators)),
            ("proof", existence_proof_json(proof)),
            ("fact", hexs(&fact.encode())),
        ]),
    }
}

fn header_json(h: &BeaconBlockHeader) -> Json {
    object(vec![
        ("slot", Json::Int(h.slot)),
        ("proposer_index", Json::Int(h.proposer_index)),
        ("parent_root", hexs(&h.parent_root)),
        ("state_root", hexs(&h.state_root)),
        ("body_root", hexs(&h.body_root)),
    ])
}

fn header_from(j: &Json) -> Result<BeaconBlockHeader, WireError> {
    Ok(BeaconBlockHeader {
        slot: as_u64(field(j, "slot")?, "slot")?,
        proposer_index: as_u64(field(j, "proposer_index")?, "proposer_index")?,
        parent_root: hex_array::<32>(field(j, "parent_root")?, "parent_root")?,
        state_root: hex_array::<32>(field(j, "state_root")?, "state_root")?,
        body_root: hex_array::<32>(field(j, "body_root")?, "body_root")?,
    })
}

fn roots_json(roots: &[[u8; 32]]) -> Json {
    Json::Array(roots.iter().map(|r| hexs(r)).collect())
}

fn roots_from(j: &Json, name: &'static str, max: usize) -> Result<Vec<[u8; 32]>, WireError> {
    let items = j.as_array().ok_or(WireError::BadType(name))?;
    if items.len() > max {
        return Err(WireError::BadField(name));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(hex_array::<32>(item, name)?);
    }
    Ok(out)
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
            if headers_json.len() > MAX_HEADERS {
                return Err(WireError::BadField("headers"));
            }
            let mut headers = Vec::with_capacity(headers_json.len());
            for h in headers_json {
                let bytes = as_hex(h, "headers")?;
                headers.push(BlockHeader::parse(&bytes).map_err(|_| WireError::BadField("headers"))?);
            }
            let branch_json = field(j, "branch")?
                .as_array()
                .ok_or(WireError::BadType("branch"))?;
            if branch_json.len() > MAX_BRANCH {
                return Err(WireError::BadField("branch"));
            }
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
        "ethereum" => {
            let participation_json = field(j, "participation")?
                .as_array()
                .ok_or(WireError::BadType("participation"))?;
            if participation_json.len() > MAX_PARTICIPATION {
                return Err(WireError::BadField("participation"));
            }
            let mut participation = Vec::with_capacity(participation_json.len());
            for p in participation_json {
                participation.push(as_bool(p, "participation")?);
            }
            let receipt_proof_json = field(j, "receipt_proof")?
                .as_array()
                .ok_or(WireError::BadType("receipt_proof"))?;
            if receipt_proof_json.len() > MAX_PROOF_NODES {
                return Err(WireError::BadField("receipt_proof"));
            }
            let mut receipt_proof = Vec::with_capacity(receipt_proof_json.len());
            for n in receipt_proof_json {
                receipt_proof.push(as_hex(n, "receipt_proof")?);
            }
            let update = LightClientUpdate {
                attested_header: header_from(field(j, "attested_header")?)?,
                finalized_header: header_from(field(j, "finalized_header")?)?,
                finality_branch: roots_from(field(j, "finality_branch")?, "finality_branch", MAX_BRANCH)?,
                sync_aggregate: SyncAggregate {
                    participation,
                    signature: BlsSignature(hex_array::<96>(field(j, "signature")?, "signature")?),
                },
                signature_slot: as_u64(field(j, "signature_slot")?, "signature_slot")?,
                execution: ExecutionCommit {
                    receipts_root: hex_array::<32>(field(j, "receipts_root")?, "receipts_root")?,
                    block_number: as_u64(field(j, "block_number")?, "block_number")?,
                    execution_branch: roots_from(
                        field(j, "execution_branch")?,
                        "execution_branch",
                        MAX_BRANCH,
                    )?,
                },
            };
            let deposit = EthDepositProof {
                receipt_index: as_u64(field(j, "receipt_index")?, "receipt_index")?,
                receipt_proof,
            };
            Ok(DepositProof::Ethereum {
                update,
                deposit,
                fact: decode_fact(j)?,
            })
        }
        "cosmos" => Ok(DepositProof::Cosmos {
            header: cosmos_header_from(field(j, "header")?)?,
            commit: commit_from(field(j, "commit")?)?,
            validators: validators_from(field(j, "validators")?)?,
            proof: existence_proof_from(field(j, "proof")?)?,
            fact: decode_fact(j)?,
        }),
        other => Err(WireError::BadProofKind(other.to_string())),
    }
}

fn cosmos_header_json(h: &Header) -> Json {
    object(vec![
        ("version_block", Json::Int(h.version_block)),
        ("version_app", Json::Int(h.version_app)),
        ("chain_id", Json::str(h.chain_id.clone())),
        ("height", Json::Int(h.height as u64)),
        ("time", timestamp_json(&h.time)),
        ("last_block_id", block_id_json(&h.last_block_id)),
        ("last_commit_hash", hexs(&h.last_commit_hash)),
        ("data_hash", hexs(&h.data_hash)),
        ("validators_hash", hexs(&h.validators_hash)),
        ("next_validators_hash", hexs(&h.next_validators_hash)),
        ("consensus_hash", hexs(&h.consensus_hash)),
        ("app_hash", hexs(&h.app_hash)),
        ("last_results_hash", hexs(&h.last_results_hash)),
        ("evidence_hash", hexs(&h.evidence_hash)),
        ("proposer_address", hexs(&h.proposer_address)),
    ])
}

fn cosmos_header_from(j: &Json) -> Result<Header, WireError> {
    Ok(Header {
        version_block: as_u64(field(j, "version_block")?, "version_block")?,
        version_app: as_u64(field(j, "version_app")?, "version_app")?,
        chain_id: as_str(field(j, "chain_id")?, "chain_id")?.to_string(),
        height: as_i64(field(j, "height")?, "height")?,
        time: timestamp_from(field(j, "time")?)?,
        last_block_id: block_id_from(field(j, "last_block_id")?)?,
        last_commit_hash: as_hex(field(j, "last_commit_hash")?, "last_commit_hash")?,
        data_hash: as_hex(field(j, "data_hash")?, "data_hash")?,
        validators_hash: as_hex(field(j, "validators_hash")?, "validators_hash")?,
        next_validators_hash: as_hex(field(j, "next_validators_hash")?, "next_validators_hash")?,
        consensus_hash: as_hex(field(j, "consensus_hash")?, "consensus_hash")?,
        app_hash: as_hex(field(j, "app_hash")?, "app_hash")?,
        last_results_hash: as_hex(field(j, "last_results_hash")?, "last_results_hash")?,
        evidence_hash: as_hex(field(j, "evidence_hash")?, "evidence_hash")?,
        proposer_address: as_hex(field(j, "proposer_address")?, "proposer_address")?,
    })
}

fn timestamp_json(t: &Timestamp) -> Json {
    object(vec![
        ("seconds", Json::Int(t.seconds as u64)),
        ("nanos", Json::Int(t.nanos as u64)),
    ])
}

fn timestamp_from(j: &Json) -> Result<Timestamp, WireError> {
    Ok(Timestamp {
        seconds: as_i64(field(j, "seconds")?, "seconds")?,
        nanos: as_i32(field(j, "nanos")?, "nanos")?,
    })
}

fn block_id_json(b: &BlockId) -> Json {
    object(vec![
        ("hash", hexs(&b.hash)),
        ("part_total", u32j(b.part_total)),
        ("part_hash", hexs(&b.part_hash)),
    ])
}

fn block_id_from(j: &Json) -> Result<BlockId, WireError> {
    Ok(BlockId {
        hash: as_hex(field(j, "hash")?, "hash")?,
        part_total: as_u32(field(j, "part_total")?, "part_total")?,
        part_hash: as_hex(field(j, "part_hash")?, "part_hash")?,
    })
}

fn flag_json(f: BlockIdFlag) -> Json {
    Json::str(match f {
        BlockIdFlag::Absent => "absent",
        BlockIdFlag::Commit => "commit",
        BlockIdFlag::Nil => "nil",
    })
}

fn flag_from(j: &Json) -> Result<BlockIdFlag, WireError> {
    match as_str(j, "flag")? {
        "absent" => Ok(BlockIdFlag::Absent),
        "commit" => Ok(BlockIdFlag::Commit),
        "nil" => Ok(BlockIdFlag::Nil),
        _ => Err(WireError::BadField("flag")),
    }
}

fn commit_sig_json(s: &CommitSig) -> Json {
    object(vec![
        ("flag", flag_json(s.flag)),
        ("validator_address", hexs(&s.validator_address)),
        ("timestamp", timestamp_json(&s.timestamp)),
        ("signature", hexs(&s.signature)),
    ])
}

fn commit_sig_from(j: &Json) -> Result<CommitSig, WireError> {
    Ok(CommitSig {
        flag: flag_from(field(j, "flag")?)?,
        validator_address: hex_array::<20>(field(j, "validator_address")?, "validator_address")?,
        timestamp: timestamp_from(field(j, "timestamp")?)?,
        signature: as_hex(field(j, "signature")?, "signature")?,
    })
}

fn commit_json(c: &Commit) -> Json {
    object(vec![
        ("height", Json::Int(c.height as u64)),
        ("round", Json::Int(c.round as u64)),
        ("block_id", block_id_json(&c.block_id)),
        (
            "signatures",
            Json::Array(c.signatures.iter().map(commit_sig_json).collect()),
        ),
    ])
}

fn commit_from(j: &Json) -> Result<Commit, WireError> {
    let sigs_json = field(j, "signatures")?
        .as_array()
        .ok_or(WireError::BadType("signatures"))?;
    if sigs_json.len() > MAX_VALIDATORS {
        return Err(WireError::BadField("signatures"));
    }
    let mut signatures = Vec::with_capacity(sigs_json.len());
    for s in sigs_json {
        signatures.push(commit_sig_from(s)?);
    }
    Ok(Commit {
        height: as_i64(field(j, "height")?, "height")?,
        round: as_i64(field(j, "round")?, "round")?,
        block_id: block_id_from(field(j, "block_id")?)?,
        signatures,
    })
}

fn validator_json(v: &ValidatorInfo) -> Json {
    object(vec![
        ("pubkey", hexs(&v.pubkey)),
        ("voting_power", Json::Int(v.voting_power)),
    ])
}

fn validator_from(j: &Json) -> Result<ValidatorInfo, WireError> {
    Ok(ValidatorInfo {
        pubkey: hex_array::<32>(field(j, "pubkey")?, "pubkey")?,
        voting_power: as_u64(field(j, "voting_power")?, "voting_power")?,
    })
}

fn validators_json(set: &ValidatorSet) -> Json {
    Json::Array(set.validators.iter().map(validator_json).collect())
}

fn validators_from(j: &Json) -> Result<ValidatorSet, WireError> {
    let items = j.as_array().ok_or(WireError::BadType("validators"))?;
    if items.len() > MAX_VALIDATORS {
        return Err(WireError::BadField("validators"));
    }
    let mut validators = Vec::with_capacity(items.len());
    for item in items {
        validators.push(validator_from(item)?);
    }
    Ok(ValidatorSet::new(validators))
}

fn leaf_op_json(l: &LeafOp) -> Json {
    object(vec![("prefix", hexs(&l.prefix))])
}

fn leaf_op_from(j: &Json) -> Result<LeafOp, WireError> {
    Ok(LeafOp {
        prefix: as_hex(field(j, "prefix")?, "prefix")?,
    })
}

fn inner_op_json(i: &InnerOp) -> Json {
    object(vec![
        ("prefix", hexs(&i.prefix)),
        ("suffix", hexs(&i.suffix)),
    ])
}

fn inner_op_from(j: &Json) -> Result<InnerOp, WireError> {
    Ok(InnerOp {
        prefix: as_hex(field(j, "prefix")?, "prefix")?,
        suffix: as_hex(field(j, "suffix")?, "suffix")?,
    })
}

fn existence_proof_json(p: &ExistenceProof) -> Json {
    object(vec![
        ("key", hexs(&p.key)),
        ("value", hexs(&p.value)),
        ("leaf", leaf_op_json(&p.leaf)),
        (
            "path",
            Json::Array(p.path.iter().map(inner_op_json).collect()),
        ),
    ])
}

fn existence_proof_from(j: &Json) -> Result<ExistenceProof, WireError> {
    let path_json = field(j, "path")?
        .as_array()
        .ok_or(WireError::BadType("path"))?;
    if path_json.len() > MAX_PROOF_PATH {
        return Err(WireError::BadField("path"));
    }
    let mut path = Vec::with_capacity(path_json.len());
    for op in path_json {
        path.push(inner_op_from(op)?);
    }
    Ok(ExistenceProof {
        key: as_hex(field(j, "key")?, "key")?,
        value: as_hex(field(j, "value")?, "value")?,
        leaf: leaf_op_from(field(j, "leaf")?)?,
        path,
    })
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
        ApiError::EthereumVerify(e) => {
            tagged("api", "ethereum_verify", vec![("eth", eth_err_json(e))])
        }
        ApiError::CosmosVerify(e) => {
            tagged("api", "cosmos_verify", vec![("cosmos", corridor_err_json(e))])
        }
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

fn eth_err_json(e: &EthError) -> Json {
    match e {
        EthError::NotBeaconChain => tagged("eth", "not_beacon_chain", vec![]),
        EthError::InvalidParticipationLength { got, expected } => tagged(
            "eth",
            "invalid_participation_length",
            vec![("got", usizej(*got)), ("expected", usizej(*expected))],
        ),
        EthError::InsufficientParticipation { got, needed } => tagged(
            "eth",
            "insufficient_participation",
            vec![("got", usizej(*got)), ("needed", usizej(*needed))],
        ),
        EthError::WrongPeriod => tagged("eth", "wrong_period", vec![]),
        EthError::BadFinalityProof => tagged("eth", "bad_finality_proof", vec![]),
        EthError::BadExecutionProof => tagged("eth", "bad_execution_proof", vec![]),
        EthError::BadSyncCommitteeProof => tagged("eth", "bad_sync_committee_proof", vec![]),
        EthError::BadSignature => tagged("eth", "bad_signature", vec![]),
        EthError::MissingReceipt => tagged("eth", "missing_receipt", vec![]),
        EthError::CapExceeded { amount, cap } => tagged(
            "eth",
            "cap_exceeded",
            vec![("amount", u128s(*amount)), ("cap", u128s(*cap))],
        ),
        EthError::Receipt(r) => tagged("eth", "receipt", vec![("receipt", receipt_err_json(r))]),
        EthError::Mpt(m) => tagged("eth", "mpt", vec![("mpt", mpt_err_json(m))]),
    }
}

fn eth_err_from(j: &Json) -> Result<EthError, WireError> {
    match code_of(j)? {
        "not_beacon_chain" => Ok(EthError::NotBeaconChain),
        "invalid_participation_length" => Ok(EthError::InvalidParticipationLength {
            got: as_usize(field(j, "got")?, "got")?,
            expected: as_usize(field(j, "expected")?, "expected")?,
        }),
        "insufficient_participation" => Ok(EthError::InsufficientParticipation {
            got: as_usize(field(j, "got")?, "got")?,
            needed: as_usize(field(j, "needed")?, "needed")?,
        }),
        "wrong_period" => Ok(EthError::WrongPeriod),
        "bad_finality_proof" => Ok(EthError::BadFinalityProof),
        "bad_execution_proof" => Ok(EthError::BadExecutionProof),
        "bad_sync_committee_proof" => Ok(EthError::BadSyncCommitteeProof),
        "bad_signature" => Ok(EthError::BadSignature),
        "missing_receipt" => Ok(EthError::MissingReceipt),
        "cap_exceeded" => Ok(EthError::CapExceeded {
            amount: as_u128(field(j, "amount")?, "amount")?,
            cap: as_u128(field(j, "cap")?, "cap")?,
        }),
        "receipt" => Ok(EthError::Receipt(receipt_err_from(field(j, "receipt")?)?)),
        "mpt" => Ok(EthError::Mpt(mpt_err_from(field(j, "mpt")?)?)),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn receipt_err_json(e: &ReceiptError) -> Json {
    match e {
        ReceiptError::Malformed => tagged("receipt", "malformed", vec![]),
        ReceiptError::NotSuccessful => tagged("receipt", "not_successful", vec![]),
        ReceiptError::NoDeposit => tagged("receipt", "no_deposit", vec![]),
        ReceiptError::AmountOverflow => tagged("receipt", "amount_overflow", vec![]),
    }
}

fn receipt_err_from(j: &Json) -> Result<ReceiptError, WireError> {
    match code_of(j)? {
        "malformed" => Ok(ReceiptError::Malformed),
        "not_successful" => Ok(ReceiptError::NotSuccessful),
        "no_deposit" => Ok(ReceiptError::NoDeposit),
        "amount_overflow" => Ok(ReceiptError::AmountOverflow),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn mpt_err_json(e: &MptError) -> Json {
    match e {
        MptError::MissingNode => tagged("mpt", "missing_node", vec![]),
        MptError::HashMismatch => tagged("mpt", "hash_mismatch", vec![]),
        MptError::BadNode => tagged("mpt", "bad_node", vec![]),
        MptError::BadRef => tagged("mpt", "bad_ref", vec![]),
    }
}

fn mpt_err_from(j: &Json) -> Result<MptError, WireError> {
    match code_of(j)? {
        "missing_node" => Ok(MptError::MissingNode),
        "hash_mismatch" => Ok(MptError::HashMismatch),
        "bad_node" => Ok(MptError::BadNode),
        "bad_ref" => Ok(MptError::BadRef),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn corridor_err_json(e: &CorridorError) -> Json {
    match e {
        CorridorError::ChainMismatch => tagged("cosmos", "chain_mismatch", vec![]),
        CorridorError::MalformedAppHash => tagged("cosmos", "malformed_app_hash", vec![]),
        CorridorError::Unanchored(l) => {
            tagged("cosmos", "unanchored", vec![("light", light_err_json(l))])
        }
        CorridorError::Commit(c) => {
            tagged("cosmos", "commit", vec![("commit", commit_err_json(c))])
        }
        CorridorError::Proof(p) => tagged("cosmos", "proof", vec![("proof", proof_err_json(p))]),
    }
}

fn corridor_err_from(j: &Json) -> Result<CorridorError, WireError> {
    match code_of(j)? {
        "chain_mismatch" => Ok(CorridorError::ChainMismatch),
        "malformed_app_hash" => Ok(CorridorError::MalformedAppHash),
        "unanchored" => Ok(CorridorError::Unanchored(light_err_from(field(j, "light")?)?)),
        "commit" => Ok(CorridorError::Commit(commit_err_from(field(j, "commit")?)?)),
        "proof" => Ok(CorridorError::Proof(proof_err_from(field(j, "proof")?)?)),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn light_err_json(e: &LightError) -> Json {
    match e {
        LightError::ChainMismatch => tagged("light", "chain_mismatch", vec![]),
        LightError::NotProgressing => tagged("light", "not_progressing", vec![]),
        LightError::UntrustedValidatorSet => tagged("light", "untrusted_validator_set", vec![]),
        LightError::InsufficientOverlap {
            overlap,
            trusted_total,
        } => tagged(
            "light",
            "insufficient_overlap",
            vec![
                ("overlap", u128s(*overlap)),
                ("trusted_total", u128s(*trusted_total)),
            ],
        ),
        LightError::NotAdjacent => tagged("light", "not_adjacent", vec![]),
        LightError::NextValidatorMismatch => tagged("light", "next_validator_mismatch", vec![]),
        LightError::Commit(c) => {
            tagged("light", "commit", vec![("commit", commit_err_json(c))])
        }
    }
}

fn light_err_from(j: &Json) -> Result<LightError, WireError> {
    match code_of(j)? {
        "chain_mismatch" => Ok(LightError::ChainMismatch),
        "not_progressing" => Ok(LightError::NotProgressing),
        "untrusted_validator_set" => Ok(LightError::UntrustedValidatorSet),
        "insufficient_overlap" => Ok(LightError::InsufficientOverlap {
            overlap: as_u128(field(j, "overlap")?, "overlap")?,
            trusted_total: as_u128(field(j, "trusted_total")?, "trusted_total")?,
        }),
        "not_adjacent" => Ok(LightError::NotAdjacent),
        "next_validator_mismatch" => Ok(LightError::NextValidatorMismatch),
        "commit" => Ok(LightError::Commit(commit_err_from(field(j, "commit")?)?)),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn commit_err_json(e: &CommitError) -> Json {
    match e {
        CommitError::HeaderMismatch => tagged("commit", "header_mismatch", vec![]),
        CommitError::NotEnoughVotingPower { signed, total } => tagged(
            "commit",
            "not_enough_voting_power",
            vec![("signed", u128s(*signed)), ("total", u128s(*total))],
        ),
    }
}

fn commit_err_from(j: &Json) -> Result<CommitError, WireError> {
    match code_of(j)? {
        "header_mismatch" => Ok(CommitError::HeaderMismatch),
        "not_enough_voting_power" => Ok(CommitError::NotEnoughVotingPower {
            signed: as_u128(field(j, "signed")?, "signed")?,
            total: as_u128(field(j, "total")?, "total")?,
        }),
        other => Err(WireError::UnknownErrorCode(other.to_string())),
    }
}

fn proof_err_json(e: &ProofError) -> Json {
    match e {
        ProofError::RootMismatch => tagged("proof", "root_mismatch", vec![]),
        ProofError::BadValueLength => tagged("proof", "bad_value_length", vec![]),
    }
}

fn proof_err_from(j: &Json) -> Result<ProofError, WireError> {
    match code_of(j)? {
        "root_mismatch" => Ok(ProofError::RootMismatch),
        "bad_value_length" => Ok(ProofError::BadValueLength),
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
            "ethereum_verify" => Ok(ApiError::EthereumVerify(eth_err_from(field(j, "eth")?)?)),
            "cosmos_verify" => {
                Ok(ApiError::CosmosVerify(corridor_err_from(field(j, "cosmos")?)?))
            }
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
    fn an_ethereum_deposit_round_trips_its_raw_material_and_fact() {
        let header = BeaconBlockHeader {
            slot: 7_100_000,
            proposer_index: 12,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        };
        let update = LightClientUpdate {
            attested_header: header,
            finalized_header: header,
            finality_branch: vec![[0xf0; 32], [0xf1; 32]],
            sync_aggregate: SyncAggregate {
                participation: vec![true, false, true, true],
                signature: BlsSignature([0x9c; 96]),
            },
            signature_slot: 7_100_050,
            execution: ExecutionCommit {
                receipts_root: [0x44; 32],
                block_number: 20_000_000,
                execution_branch: vec![[0xe0; 32]],
            },
        };
        let deposit = EthDepositProof {
            receipt_index: 3,
            receipt_proof: vec![vec![0x01, 0x02], vec![0x03, 0x04, 0x05]],
        };
        round_request(Request::SubmitDeposit(DepositRequest {
            proof: DepositProof::Ethereum {
                update,
                deposit,
                fact: sample_fact(),
            },
        }));
    }

    #[test]
    fn an_oversized_ethereum_participation_array_is_rejected_before_allocation() {
        let participation = Json::Array(vec![Json::Bool(true); MAX_PARTICIPATION + 1]);
        let body = object(vec![(
            "proof",
            object(vec![
                ("kind", Json::str("ethereum")),
                ("participation", participation),
            ]),
        )]);
        assert_eq!(
            decode_request("submit_deposit", &body),
            Err(WireError::BadField("participation"))
        );
    }

    #[test]
    fn a_cosmos_deposit_round_trips_its_raw_material_and_fact() {
        let header = Header {
            version_block: 11,
            version_app: 0,
            chain_id: "cosmoshub-4".to_string(),
            height: 18_500_000,
            time: Timestamp {
                seconds: 1_700_000_000,
                nanos: 9,
            },
            last_block_id: BlockId {
                hash: vec![0xaa; 32],
                part_total: 1,
                part_hash: vec![0xbb; 32],
            },
            last_commit_hash: vec![0x01; 32],
            data_hash: vec![0x02; 32],
            validators_hash: vec![0x03; 32],
            next_validators_hash: vec![0x04; 32],
            consensus_hash: vec![0x05; 32],
            app_hash: vec![0x06; 32],
            last_results_hash: vec![0x07; 32],
            evidence_hash: vec![0x08; 32],
            proposer_address: vec![0x09; 20],
        };
        let commit = Commit {
            height: 18_500_000,
            round: 0,
            block_id: BlockId {
                hash: vec![0xcc; 32],
                part_total: 1,
                part_hash: vec![0xdd; 32],
            },
            signatures: vec![CommitSig {
                flag: BlockIdFlag::Commit,
                validator_address: [0x11; 20],
                timestamp: Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 5,
                },
                signature: vec![0x22; 64],
            }],
        };
        let validators = ValidatorSet::new(vec![ValidatorInfo {
            pubkey: [0x33; 32],
            voting_power: 25,
        }]);
        let proof = ExistenceProof {
            key: vec![0x74, 0x65],
            value: vec![0x55; 64],
            leaf: LeafOp {
                prefix: vec![0x00, 0x02, 0x00],
            },
            path: vec![InnerOp {
                prefix: vec![0x01, 0x0a],
                suffix: vec![0x1b, 0x2c],
            }],
        };
        round_request(Request::SubmitDeposit(DepositRequest {
            proof: DepositProof::Cosmos {
                header,
                commit,
                validators,
                proof,
                fact: sample_fact(),
            },
        }));
    }

    #[test]
    fn oversized_cosmos_arrays_are_rejected_before_allocation() {
        let big_validators = Json::Array(vec![Json::Null; MAX_VALIDATORS + 1]);
        assert_eq!(
            validators_from(&big_validators),
            Err(WireError::BadField("validators"))
        );
        let big_path = object(vec![(
            "path",
            Json::Array(vec![Json::Null; MAX_PROOF_PATH + 1]),
        )]);
        assert_eq!(
            existence_proof_from(&big_path),
            Err(WireError::BadField("path"))
        );
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
        round_response(Response::Error(ApiError::EthereumVerify(EthError::BadSignature)));
        round_response(Response::Error(ApiError::EthereumVerify(
            EthError::InsufficientParticipation { got: 300, needed: 342 },
        )));
        round_response(Response::Error(ApiError::EthereumVerify(EthError::Receipt(
            ReceiptError::NoDeposit,
        ))));
        round_response(Response::Error(ApiError::EthereumVerify(EthError::Mpt(
            MptError::HashMismatch,
        ))));
        round_response(Response::Error(ApiError::CosmosVerify(
            CorridorError::ChainMismatch,
        )));
        round_response(Response::Error(ApiError::CosmosVerify(
            CorridorError::Unanchored(LightError::InsufficientOverlap {
                overlap: 40,
                trusted_total: 100,
            }),
        )));
        round_response(Response::Error(ApiError::CosmosVerify(CorridorError::Commit(
            CommitError::NotEnoughVotingPower {
                signed: 50,
                total: 100,
            },
        ))));
        round_response(Response::Error(ApiError::CosmosVerify(CorridorError::Proof(
            ProofError::RootMismatch,
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
    fn an_oversized_bitcoin_headers_array_is_rejected_before_allocation() {
        let headers = Json::Array(vec![Json::str(""); MAX_HEADERS + 1]);
        let body = object(vec![(
            "proof",
            object(vec![("kind", Json::str("bitcoin")), ("headers", headers)]),
        )]);
        assert_eq!(
            decode_request("submit_deposit", &body),
            Err(WireError::BadField("headers"))
        );
    }

    #[test]
    fn an_oversized_bitcoin_branch_array_is_rejected_before_allocation() {
        let branch = Json::Array(vec![Json::Null; MAX_BRANCH + 1]);
        let body = object(vec![(
            "proof",
            object(vec![
                ("kind", Json::str("bitcoin")),
                ("headers", Json::Array(vec![])),
                ("branch", branch),
            ]),
        )]);
        assert_eq!(
            decode_request("submit_deposit", &body),
            Err(WireError::BadField("branch"))
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
