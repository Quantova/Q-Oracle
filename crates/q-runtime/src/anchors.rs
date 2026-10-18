// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::Path;

use q_exits::{MemberConfig, QuantovaAnchor, ATTEST_PK_BYTES, BEACON_SEED_BYTES};
use q_qbridge::{BitcoinAnchor, BridgeState, CosmosAnchor};
use qlc_bitcoin::{checkpoint_is_pinned, network_params, Checkpoint, Network, U256};
use qlc_cosmos::light::{trusted_state_is_pinned, TrustedState};
use qlc_ethereum::{bootstrap, EthError, LightClientStore};

use crate::exits::{MIN_PAYOUT_WORK_BITS, MIN_PINNED_CHECKPOINT_HEIGHT};
use crate::json::{self, Json};
use crate::wire::{
    as_hex, as_i64, as_str, as_u128, as_u32, as_u64, committee_from, field, header_from, hex_array,
    roots_from, timestamp_from, validators_from, WireError, MAX_BRANCH,
};

pub const ANCHORS_FILE_ENV: &str = "Q_ORACLE_ANCHORS_FILE";

pub const MAX_ANCHORS_FILE: u64 = 4 * 1024 * 1024;

pub const MAX_BRIDGE_SCRIPT: usize = 10_000;

pub const MAX_COMMITTEE_MEMBERS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorFileError {
    Unreadable(String),
    NotARegularFile,
    TooLarge,
    NotOwnerOnly(u32),
    Malformed(String),
    UnknownSection(String),
    BitcoinUnpinned,
    BitcoinWorkFloor,
    EthereumUnknownChain(u64),
    Ethereum(EthError),
    CosmosUnknownChain(String),
    CosmosUnpinned,
    Quantova(String),
}

impl From<WireError> for AnchorFileError {
    fn from(e: WireError) -> AnchorFileError {
        AnchorFileError::Malformed(format!("{e:?}"))
    }
}

#[derive(Default)]
pub struct ProofAnchors {
    pub bitcoin: Option<BitcoinAnchor>,
    pub ethereum: Option<LightClientStore>,
    pub cosmos: Option<CosmosAnchor>,
    pub quantova: Option<QuantovaAnchor>,
}

impl std::fmt::Debug for ProofAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofAnchors")
            .field("bitcoin", &self.bitcoin.is_some())
            .field("ethereum", &self.ethereum.is_some())
            .field("cosmos", &self.cosmos.is_some())
            .field("quantova", &self.quantova.is_some())
            .finish()
    }
}

impl ProofAnchors {
    pub fn is_empty(&self) -> bool {
        self.bitcoin.is_none() && self.ethereum.is_none() && self.cosmos.is_none()
    }

    pub fn install(&mut self, state: &mut BridgeState) {
        if let Some(anchor) = self.bitcoin.take() {
            state.set_bitcoin_anchor(anchor);
        }
        if let Some(store) = self.ethereum.take() {
            state.set_ethereum_anchor(store);
        }
        if let Some(anchor) = self.cosmos.take() {
            state.set_cosmos_anchor(anchor);
        }
    }
}

pub fn read_anchor_file(path: &Path) -> Result<String, AnchorFileError> {
    use std::io::Read;
    let unreadable =
        |e: std::io::Error| AnchorFileError::Unreadable(format!("{}: {e}", path.display()));
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|e| {
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            AnchorFileError::NotARegularFile
        } else {
            unreadable(e)
        }
    })?;
    let meta = file.metadata().map_err(unreadable)?;
    if !meta.file_type().is_file() {
        return Err(AnchorFileError::NotARegularFile);
    }
    if meta.len() > MAX_ANCHORS_FILE {
        return Err(AnchorFileError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(AnchorFileError::NotOwnerOnly(mode));
        }
    }
    let mut text = String::new();
    file.by_ref()
        .take(MAX_ANCHORS_FILE + 1)
        .read_to_string(&mut text)
        .map_err(unreadable)?;
    if text.len() as u64 > MAX_ANCHORS_FILE {
        return Err(AnchorFileError::TooLarge);
    }
    Ok(text)
}

pub fn load_anchor_file(path: &Path) -> Result<ProofAnchors, AnchorFileError> {
    parse_anchors(&read_anchor_file(path)?)
}

pub fn parse_anchors(text: &str) -> Result<ProofAnchors, AnchorFileError> {
    let root = json::parse(text).map_err(AnchorFileError::Malformed)?;
    let Json::Object(entries) = &root else {
        return Err(AnchorFileError::Malformed(
            "the anchor file is not a JSON object".to_string(),
        ));
    };
    let mut anchors = ProofAnchors::default();
    for (key, value) in entries {
        match key.as_str() {
            "bitcoin" => anchors.bitcoin = Some(bitcoin_anchor(value)?),
            "ethereum" => anchors.ethereum = Some(ethereum_anchor(value)?),
            "cosmos" => anchors.cosmos = Some(cosmos_anchor(value)?),
            "quantova" => anchors.quantova = Some(quantova_anchor(value)?),
            other => return Err(AnchorFileError::UnknownSection(other.to_string())),
        }
    }
    Ok(anchors)
}

fn bitcoin_anchor(j: &Json) -> Result<BitcoinAnchor, AnchorFileError> {
    let network = match as_str(field(j, "network")?, "network")? {
        "bitcoin" => Network::Bitcoin,
        "bitcoin_cash" => Network::BitcoinCash,
        other => {
            return Err(AnchorFileError::Malformed(format!(
                "unknown bitcoin network {other}"
            )))
        }
    };
    let height = as_u32(field(j, "checkpoint_height")?, "checkpoint_height")?;
    let hash = hex_array::<32>(field(j, "checkpoint_hash")?, "checkpoint_hash")?;
    let min_work = hex_array::<32>(field(j, "min_work")?, "min_work")?;
    if height < MIN_PINNED_CHECKPOINT_HEIGHT
        || min_work[..32 - MIN_PAYOUT_WORK_BITS / 8]
            .iter()
            .all(|b| *b == 0)
    {
        return Err(AnchorFileError::BitcoinWorkFloor);
    }
    let bridge_script = as_hex(field(j, "bridge_script")?, "bridge_script")?;
    if bridge_script.is_empty() || bridge_script.len() > MAX_BRIDGE_SCRIPT {
        return Err(AnchorFileError::Malformed(
            "the bitcoin bridge script is empty or too long".to_string(),
        ));
    }
    let checkpoint = Checkpoint {
        height,
        hash,
        min_work: U256::from_be_bytes(&min_work),
    };
    if !checkpoint_is_pinned(network, &checkpoint) {
        return Err(AnchorFileError::BitcoinUnpinned);
    }
    Ok(BitcoinAnchor {
        checkpoint,
        params: network_params(network),
        bridge_script,
    })
}

fn ethereum_anchor(j: &Json) -> Result<LightClientStore, AnchorFileError> {
    let chain_id = as_u64(field(j, "chain_id")?, "chain_id")?;
    let mut config = qlc_ethereum::config::all_presets()
        .into_iter()
        .find(|preset| preset.chain_id == chain_id && preset.verifies_beacon_sync_committee())
        .ok_or(AnchorFileError::EthereumUnknownChain(chain_id))?;
    config.deposit_contract = hex_array::<20>(field(j, "deposit_contract")?, "deposit_contract")?;
    if let Some(cap) = j.get("max_deposit_base_units") {
        config.max_deposit_base_units = config
            .max_deposit_base_units
            .min(as_u128(cap, "max_deposit_base_units")?);
    }
    if let Some(depth) = j.get("finality_depth") {
        config.finality_depth = config.finality_depth.max(as_u32(depth, "finality_depth")?);
    }
    bootstrap(
        config,
        as_u64(field(j, "period")?, "period")?,
        hex_array::<32>(field(j, "trusted_block_root")?, "trusted_block_root")?,
        header_from(field(j, "checkpoint_header")?)?,
        committee_from(field(j, "current_sync_committee")?)?,
        roots_from(
            field(j, "current_sync_committee_branch")?,
            "current_sync_committee_branch",
            MAX_BRANCH,
        )?,
    )
    .map_err(AnchorFileError::Ethereum)
}

fn cosmos_anchor(j: &Json) -> Result<CosmosAnchor, AnchorFileError> {
    let chain_id = as_str(field(j, "chain_id")?, "chain_id")?;
    let config = qlc_cosmos::by_chain_id(chain_id)
        .ok_or_else(|| AnchorFileError::CosmosUnknownChain(chain_id.to_string()))?;
    let trusted = TrustedState {
        height: as_i64(field(j, "height")?, "height")?,
        time: timestamp_from(field(j, "time")?)?,
        header_hash: hex_array::<32>(field(j, "header_hash")?, "header_hash")?,
        validators: validators_from(field(j, "validators")?)?,
        next_validators_hash: as_hex(field(j, "next_validators_hash")?, "next_validators_hash")?,
    };
    if !trusted_state_is_pinned(config.chain_id, &trusted) {
        return Err(AnchorFileError::CosmosUnpinned);
    }
    Ok(CosmosAnchor { config, trusted })
}

fn quantova_anchor(j: &Json) -> Result<QuantovaAnchor, AnchorFileError> {
    let genesis = hex_array::<32>(field(j, "genesis_hash")?, "genesis_hash")?;
    if genesis == [0u8; 32] {
        return Err(AnchorFileError::Quantova(
            "the genesis hash is zero".to_string(),
        ));
    }
    let items = field(j, "members")?
        .as_array()
        .ok_or_else(|| AnchorFileError::Malformed("members is not a list".to_string()))?;
    if items.is_empty() || items.len() > MAX_COMMITTEE_MEMBERS {
        return Err(AnchorFileError::Quantova(
            "the committee is empty or too large".to_string(),
        ));
    }
    let mut members = Vec::with_capacity(items.len());
    for item in items {
        let attest_pk = as_hex(field(item, "attest_pk")?, "attest_pk")?;
        if attest_pk.len() != ATTEST_PK_BYTES {
            return Err(AnchorFileError::Quantova(
                "a member attestation key has the wrong length".to_string(),
            ));
        }
        let weight = as_u64(field(item, "weight")?, "weight")?;
        members.push(MemberConfig {
            id: as_u64(field(item, "id")?, "id")?,
            weight,
            stake: match item.get("stake") {
                Some(stake) => as_u64(stake, "stake")?,
                None => weight,
            },
            root_digest: hex_array::<32>(field(item, "root_digest")?, "root_digest")?,
            root_slots: as_u64(field(item, "root_slots")?, "root_slots")?,
            attest_pk,
        });
    }
    QuantovaAnchor::from_config(
        as_u64(field(j, "chain_id")?, "chain_id")?,
        as_u64(field(j, "tau")?, "tau")?,
        as_u64(field(j, "slot")?, "slot")?,
        as_u64(field(j, "budget")?, "budget")?,
        hex_array::<BEACON_SEED_BYTES>(field(j, "beacon_seed")?, "beacon_seed")?,
        members,
    )
    .map(|anchor| anchor.with_genesis(genesis))
    .map_err(|e| AnchorFileError::Quantova(format!("{e:?}")))
}

pub fn anchors_from_env() -> Result<ProofAnchors, AnchorFileError> {
    match std::env::var_os(ANCHORS_FILE_ENV) {
        Some(path) => load_anchor_file(Path::new(&path)),
        None => Ok(ProofAnchors::default()),
    }
}
