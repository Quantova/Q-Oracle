// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::PathBuf;

use q_exits::{
    DeskConfig, ExitConfig, MemberConfig, QuantovaAnchor, RpcBurnSource, ATTEST_PK_BYTES,
    BEACON_SEED_BYTES,
};

pub const EXITS_ENABLED_ENV: &str = "Q_ORACLE_EXITS_ENABLED";
pub const CHAIN_RPC_HOST_ENV: &str = "Q_ORACLE_CHAIN_RPC_HOST";
pub const CHAIN_RPC_PORT_ENV: &str = "Q_ORACLE_CHAIN_RPC_PORT";
pub const DEFAULT_CHAIN_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_CHAIN_RPC_PORT: u16 = 8080;

pub const CHAIN_ID_ENV: &str = "Q_ORACLE_EXITS_CHAIN_ID";
pub const TAU_ENV: &str = "Q_ORACLE_EXITS_TAU";
pub const SLOT_ENV: &str = "Q_ORACLE_EXITS_SLOT";
pub const BUDGET_ENV: &str = "Q_ORACLE_EXITS_BUDGET";
pub const DEST_CHAIN_ENV: &str = "Q_ORACLE_EXITS_DEST_CHAIN";
pub const CORRIDOR_ENV: &str = "Q_ORACLE_EXITS_CORRIDOR";
pub const START_HEIGHT_ENV: &str = "Q_ORACLE_EXITS_START_HEIGHT";
pub const BEACON_SEED_ENV: &str = "Q_ORACLE_EXITS_BEACON_SEED";
pub const COMMITTEE_ENV: &str = "Q_ORACLE_EXITS_COMMITTEE";
pub const VAULTS_ENV: &str = "Q_ORACLE_EXITS_VAULTS";
pub const LEDGER_ENV: &str = "Q_ORACLE_EXITS_LEDGER";
pub const BITCOIN_ENV: &str = "Q_ORACLE_EXITS_BITCOIN";

pub fn parse_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

pub fn exit_config_from_env() -> ExitConfig {
    let raw = std::env::var(EXITS_ENABLED_ENV).ok();
    ExitConfig {
        enabled: parse_enabled(raw.as_deref()),
    }
}

pub fn exits_started(config: &ExitConfig) -> bool {
    config.enabled
}

pub fn burn_source_from_env(config: &ExitConfig) -> Option<RpcBurnSource> {
    if !config.enabled {
        return None;
    }
    let host =
        std::env::var(CHAIN_RPC_HOST_ENV).unwrap_or_else(|_| DEFAULT_CHAIN_RPC_HOST.to_string());
    let port = std::env::var(CHAIN_RPC_PORT_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_CHAIN_RPC_PORT);
    Some(RpcBurnSource::new(host, port))
}

// a vault and its over-collateral the desk locks against
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSeed {
    pub vault_id: u32,
    pub collateral: u128,
}

// pinned bitcoin checkpoint and work floor for a corridor's payout spv (founder launch values)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinCheckpointConfig {
    pub height: u32,
    pub hash: [u8; 32],
    pub min_work: u64,
    pub confirmations: u32,
}

// every trust root the exit service needs before it may move custody
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitTrustConfig {
    pub chain_id: u64,
    pub tau: u64,
    pub slot: u64,
    pub budget: u64,
    pub beacon_seed: [u8; BEACON_SEED_BYTES],
    pub members: Vec<MemberConfig>,
    pub dest_chain: u32,
    pub corridor: u32,
    pub start_height: u64,
    pub vaults: Vec<VaultSeed>,
    pub rpc_host: String,
    pub rpc_port: u16,
    pub ledger_path: PathBuf,
    pub bitcoin: Option<BitcoinCheckpointConfig>,
}

impl ExitTrustConfig {
    // build the committee anchor from the loaded trust roots
    pub fn build_anchor(&self) -> Result<QuantovaAnchor, q_exits::ExitError> {
        QuantovaAnchor::from_config(
            self.chain_id,
            self.tau,
            self.slot,
            self.budget,
            self.beacon_seed,
            self.members.clone(),
        )
    }

    // aligned corridor params: 150% collateral, 110% premium, one day window
    pub fn desk_config(&self) -> DeskConfig {
        DeskConfig::aligned(self.corridor, self.dest_chain as u64)
    }

    // the pool vault the feed opens exits against
    pub fn active_vault(&self) -> u32 {
        self.vaults[0].vault_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitConfigError {
    Missing(&'static str),
    Malformed(&'static str),
    Anchor(q_exits::ExitError),
}

// config source so the loader is testable without the process environment
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return None;
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn req<E: EnvSource>(env: &E, key: &str, what: &'static str) -> Result<String, ExitConfigError> {
    env.get(key)
        .filter(|value| !value.is_empty())
        .ok_or(ExitConfigError::Missing(what))
}

fn req_u64<E: EnvSource>(env: &E, key: &str, what: &'static str) -> Result<u64, ExitConfigError> {
    req(env, key, what)?
        .parse()
        .map_err(|_| ExitConfigError::Malformed(what))
}

fn req_u32<E: EnvSource>(env: &E, key: &str, what: &'static str) -> Result<u32, ExitConfigError> {
    req(env, key, what)?
        .parse()
        .map_err(|_| ExitConfigError::Malformed(what))
}

fn opt_u64<E: EnvSource>(env: &E, key: &str, default: u64) -> Result<u64, ExitConfigError> {
    match env.get(key).filter(|value| !value.is_empty()) {
        Some(value) => value.parse().map_err(|_| ExitConfigError::Malformed("a numeric field")),
        None => Ok(default),
    }
}

fn parse_committee<E: EnvSource>(env: &E) -> Result<Vec<MemberConfig>, ExitConfigError> {
    let raw = req(env, COMMITTEE_ENV, "committee")?;
    let mut members = Vec::new();
    for entry in raw.split(';').filter(|e| !e.trim().is_empty()) {
        let fields: Vec<&str> = entry.split(',').collect();
        if fields.len() != 5 {
            return Err(ExitConfigError::Malformed("committee member"));
        }
        let id = fields[0].trim().parse().map_err(|_| ExitConfigError::Malformed("member id"))?;
        let weight = fields[1].trim().parse().map_err(|_| ExitConfigError::Malformed("member weight"))?;
        let digest_bytes = decode_hex(fields[2]).ok_or(ExitConfigError::Malformed("member root digest"))?;
        let root_digest: [u8; 32] = digest_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ExitConfigError::Malformed("member root digest"))?;
        let root_slots = fields[3].trim().parse().map_err(|_| ExitConfigError::Malformed("member root slots"))?;
        let attest_pk = decode_hex(fields[4]).ok_or(ExitConfigError::Malformed("member attest key"))?;
        if attest_pk.len() != ATTEST_PK_BYTES {
            return Err(ExitConfigError::Malformed("member attest key length"));
        }
        members.push(MemberConfig {
            id,
            weight,
            root_digest,
            root_slots,
            attest_pk,
        });
    }
    if members.is_empty() {
        return Err(ExitConfigError::Missing("committee"));
    }
    Ok(members)
}

fn parse_vaults<E: EnvSource>(env: &E) -> Result<Vec<VaultSeed>, ExitConfigError> {
    let raw = req(env, VAULTS_ENV, "vault registry")?;
    let mut vaults = Vec::new();
    for entry in raw.split(',').filter(|e| !e.trim().is_empty()) {
        let (id, collateral) = entry.split_once(':').ok_or(ExitConfigError::Malformed("vault entry"))?;
        let vault_id = id.trim().parse().map_err(|_| ExitConfigError::Malformed("vault id"))?;
        let collateral = collateral.trim().parse().map_err(|_| ExitConfigError::Malformed("vault collateral"))?;
        vaults.push(VaultSeed { vault_id, collateral });
    }
    if vaults.is_empty() {
        return Err(ExitConfigError::Missing("vault registry"));
    }
    Ok(vaults)
}

fn parse_bitcoin<E: EnvSource>(env: &E) -> Result<Option<BitcoinCheckpointConfig>, ExitConfigError> {
    let raw = match env.get(BITCOIN_ENV).filter(|value| !value.is_empty()) {
        Some(raw) => raw,
        None => return Ok(None),
    };
    let fields: Vec<&str> = raw.split(',').collect();
    if fields.len() != 4 {
        return Err(ExitConfigError::Malformed("bitcoin checkpoint"));
    }
    let height = fields[0].trim().parse().map_err(|_| ExitConfigError::Malformed("bitcoin height"))?;
    let hash_bytes = decode_hex(fields[1]).ok_or(ExitConfigError::Malformed("bitcoin hash"))?;
    let hash: [u8; 32] = hash_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ExitConfigError::Malformed("bitcoin hash"))?;
    let min_work = fields[2].trim().parse().map_err(|_| ExitConfigError::Malformed("bitcoin work floor"))?;
    let confirmations = fields[3].trim().parse().map_err(|_| ExitConfigError::Malformed("bitcoin confirmations"))?;
    Ok(Some(BitcoinCheckpointConfig {
        height,
        hash,
        min_work,
        confirmations,
    }))
}

// off -> Ok(None); on but any root unset -> Err (fail closed); fully set -> Ok(Some)
pub fn parse_exit_config<E: EnvSource>(env: &E) -> Result<Option<ExitTrustConfig>, ExitConfigError> {
    if !parse_enabled(env.get(EXITS_ENABLED_ENV).as_deref()) {
        return Ok(None);
    }
    let chain_id = req_u64(env, CHAIN_ID_ENV, "chain id")?;
    let tau = req_u64(env, TAU_ENV, "tau")?;
    let slot = opt_u64(env, SLOT_ENV, 0)?;
    let budget = req_u64(env, BUDGET_ENV, "committee budget")?;
    let dest_chain = req_u32(env, DEST_CHAIN_ENV, "dest chain")?;
    let corridor = req_u32(env, CORRIDOR_ENV, "corridor")?;
    let start_height = opt_u64(env, START_HEIGHT_ENV, 0)?;
    let seed_bytes = decode_hex(&req(env, BEACON_SEED_ENV, "beacon seed")?)
        .ok_or(ExitConfigError::Malformed("beacon seed"))?;
    let beacon_seed: [u8; BEACON_SEED_BYTES] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ExitConfigError::Malformed("beacon seed length"))?;
    let members = parse_committee(env)?;
    let vaults = parse_vaults(env)?;
    // required when the service runs: never silently defaults to loopback
    let rpc_host = req(env, CHAIN_RPC_HOST_ENV, "chain rpc host")?;
    let rpc_port = req(env, CHAIN_RPC_PORT_ENV, "chain rpc port")?
        .parse()
        .map_err(|_| ExitConfigError::Malformed("chain rpc port"))?;
    let ledger_path = PathBuf::from(req(env, LEDGER_ENV, "replay ledger path")?);
    let bitcoin = parse_bitcoin(env)?;

    let config = ExitTrustConfig {
        chain_id,
        tau,
        slot,
        budget,
        beacon_seed,
        members,
        dest_chain,
        corridor,
        start_height,
        vaults,
        rpc_host,
        rpc_port,
        ledger_path,
        bitcoin,
    };
    // validate the anchor now so a bad committee refuses to start
    config.build_anchor().map_err(ExitConfigError::Anchor)?;
    Ok(Some(config))
}

pub fn load_exit_config() -> Result<Option<ExitTrustConfig>, ExitConfigError> {
    parse_exit_config(&ProcessEnv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn the_flag_is_off_unless_explicitly_enabled() {
        assert!(!parse_enabled(None));
        assert!(!parse_enabled(Some("0")));
        assert!(!parse_enabled(Some("true")));
        assert!(parse_enabled(Some("1")));
    }

    #[test]
    fn the_default_config_does_not_start_exits() {
        assert!(!exits_started(&ExitConfig::default()));
    }

    #[test]
    fn the_burn_source_is_absent_unless_exits_are_enabled() {
        assert!(burn_source_from_env(&ExitConfig::default()).is_none());
        assert!(burn_source_from_env(&ExitConfig { enabled: true }).is_some());
    }

    struct MapEnv(BTreeMap<String, String>);

    impl EnvSource for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn full_env() -> MapEnv {
        let mut map = BTreeMap::new();
        map.insert(EXITS_ENABLED_ENV.into(), "1".into());
        map.insert(CHAIN_ID_ENV.into(), "9000".into());
        map.insert(TAU_ENV.into(), "1".into());
        map.insert(BUDGET_ENV.into(), "100".into());
        map.insert(DEST_CHAIN_ENV.into(), "9000".into());
        map.insert(CORRIDOR_ENV.into(), "1".into());
        map.insert(START_HEIGHT_ENV.into(), "4199999".into());
        map.insert(BEACON_SEED_ENV.into(), "5a".repeat(BEACON_SEED_BYTES));
        map.insert(
            COMMITTEE_ENV.into(),
            format!("1,100,{},64,{}", "11".repeat(32), "00".repeat(ATTEST_PK_BYTES)),
        );
        map.insert(VAULTS_ENV.into(), "1:2000000,2:3000000".into());
        map.insert(CHAIN_RPC_HOST_ENV.into(), "127.0.0.1".into());
        map.insert(CHAIN_RPC_PORT_ENV.into(), "8080".into());
        map.insert(LEDGER_ENV.into(), "/var/lib/q-oracle/exits.led".into());
        MapEnv(map)
    }

    #[test]
    fn a_disabled_source_loads_no_config() {
        let mut map = BTreeMap::new();
        map.insert(EXITS_ENABLED_ENV.into(), "0".into());
        assert_eq!(parse_exit_config(&MapEnv(map)), Ok(None));
        assert_eq!(parse_exit_config(&MapEnv(BTreeMap::new())), Ok(None));
    }

    #[test]
    fn a_fully_configured_source_loads_a_runnable_config() {
        let config = parse_exit_config(&full_env()).expect("a full config loads").expect("exits are on");
        assert_eq!(config.chain_id, 9000);
        assert_eq!(config.tau, 1);
        assert_eq!(config.dest_chain, 9000);
        assert_eq!(config.corridor, 1);
        assert_eq!(config.start_height, 4_199_999);
        assert_eq!(config.members.len(), 1);
        assert_eq!(config.vaults.len(), 2);
        assert_eq!(config.active_vault(), 1);
        assert_eq!(config.desk_config(), DeskConfig::aligned(1, 9000));
        config.build_anchor().expect("the loaded anchor is well formed");
    }

    #[test]
    fn an_enabled_but_unconfigured_source_fails_closed() {
        let mut map = BTreeMap::new();
        map.insert(EXITS_ENABLED_ENV.into(), "1".into());
        assert_eq!(parse_exit_config(&MapEnv(map)), Err(ExitConfigError::Missing("chain id")));
    }

    #[test]
    fn each_missing_trust_root_fails_closed() {
        for (key, expected) in [
            (CHAIN_ID_ENV, ExitConfigError::Missing("chain id")),
            (TAU_ENV, ExitConfigError::Missing("tau")),
            (BUDGET_ENV, ExitConfigError::Missing("committee budget")),
            (DEST_CHAIN_ENV, ExitConfigError::Missing("dest chain")),
            (CORRIDOR_ENV, ExitConfigError::Missing("corridor")),
            (BEACON_SEED_ENV, ExitConfigError::Missing("beacon seed")),
            (COMMITTEE_ENV, ExitConfigError::Missing("committee")),
            (VAULTS_ENV, ExitConfigError::Missing("vault registry")),
            (CHAIN_RPC_HOST_ENV, ExitConfigError::Missing("chain rpc host")),
            (CHAIN_RPC_PORT_ENV, ExitConfigError::Missing("chain rpc port")),
            (LEDGER_ENV, ExitConfigError::Missing("replay ledger path")),
        ] {
            let mut env = full_env();
            env.0.remove(key);
            assert_eq!(parse_exit_config(&env), Err(expected), "removing {key} must fail closed");
        }
    }

    #[test]
    fn a_malformed_committee_key_fails_closed() {
        let mut env = full_env();
        env.0.insert(
            COMMITTEE_ENV.into(),
            format!("1,100,{},64,{}", "11".repeat(32), "00".repeat(ATTEST_PK_BYTES - 1)),
        );
        assert_eq!(parse_exit_config(&env), Err(ExitConfigError::Malformed("member attest key length")));
    }

    #[test]
    fn a_tau_above_the_committee_fails_closed() {
        let mut env = full_env();
        env.0.insert(TAU_ENV.into(), "2".into());
        assert!(matches!(parse_exit_config(&env), Err(ExitConfigError::Anchor(_))));
    }

    #[test]
    fn the_optional_bitcoin_checkpoint_loads_when_present() {
        let mut env = full_env();
        env.0.insert(
            BITCOIN_ENV.into(),
            format!("100,{},1,6", "cc".repeat(32)),
        );
        let config = parse_exit_config(&env).unwrap().unwrap();
        let checkpoint = config.bitcoin.expect("the checkpoint loads");
        assert_eq!(checkpoint.height, 100);
        assert_eq!(checkpoint.confirmations, 6);
    }
}
