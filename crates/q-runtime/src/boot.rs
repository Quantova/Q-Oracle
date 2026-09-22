// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::ErrorKind;
use std::net::{TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use q_exits::{
    BitcoinPayoutWatcher, BitcoinReleaseProof, BurnFeed, ExitConfig, ExitDecision, ExitDesk,
    ExitError, ExitId, FeedError, PayoutWatcher, PersistentJournal, QuantovaBurnSource,
    ReplayStore, RpcBurnSource,
};
use q_federated::SourceEndpoint;
use q_gateway::{Gateway, OperatorSet};
use q_qbridge::BridgeState;
use qlc_bitcoin::{Checkpoint, NetworkParams, U256};

use crate::exits::{load_exit_config, ExitConfigError, ExitTrustConfig};
use crate::http::{serve, SharedState};
use crate::persist::GuardStore;

/// Set to 1 on the first boot only, when there is genuinely no snapshot yet.
pub const INIT_SNAPSHOT_ENV: &str = "Q_ORACLE_INIT_SNAPSHOT";

/// The only corridor with a working payout verifier. q_assets::Network::Bitcoin.
const BITCOIN_CORRIDOR: u32 = 43;

/// Whether settle and slash decisions are signed by the operator quorum and submitted to
/// the chain. They are not, so exits stay refused; this flips only with that leg.
const EXIT_ACK_PATH_WIRED: bool = false;

/// Submitted release proofs waiting to be matched against a pending exit. Bounded so a
/// stream of unmatched proofs cannot grow the queue without limit; the oldest go first.
const MAX_PENDING_RELEASES: usize = 1024;

const EXIT_POLL_INTERVAL: Duration = Duration::from_secs(10);
const EXIT_POLL_SLICE: Duration = Duration::from_millis(100);

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

pub struct ExitService {
    gateway: Option<SharedState>,
    reserves: q_watchtower::StaticReserves,
    desk: ExitDesk,
    feed: BurnFeed,
    source: RpcBurnSource,
    vault_id: u32,
    dest_chain: u32,
    // Everything the settle sweep needs: the corridor's checkpoint and assets, and the
    // queue the RPC surface drops submitted release proofs onto. Absent when no
    // checkpoint is configured, in which case nothing can be proven and the sweep is a
    // no-op; `start_exits_inner` refuses to serve in that state rather than slash.
    settle: Option<SettleInputs>,
}

pub struct SettleInputs {
    corridor: u32,
    // One watcher is bound to one asset, so a corridor backing several needs one each.
    // Building only for the first would silently slash every exit of the others.
    assets: Vec<[u8; 16]>,
    params: NetworkParams,
    checkpoint: Checkpoint,
    confirmation_depth: u32,
    queue: ReleaseQueue,
    held: Vec<BitcoinReleaseProof>,
    expected: ExpectedReleases,
}

/// Release proofs cross from the RPC thread to the exit thread through this.
pub type ReleaseQueue = Arc<Mutex<Vec<BitcoinReleaseProof>>>;

pub type ExpectedReleases = Arc<Mutex<std::collections::BTreeMap<[u8; 32], ([u8; 32], u128)>>>;

const MAX_SEEN_RELEASES: usize = 4096;

/// What a submitted proof is checked against before it is held: the corridor's network,
/// its pinned checkpoint and the depth a payout must be buried under.
pub struct ReleaseGate {
    queue: ReleaseQueue,
    params: NetworkParams,
    checkpoint: Checkpoint,
    confirmation_depth: u32,
    expected: ExpectedReleases,
    seen: Mutex<std::collections::VecDeque<[u8; 32]>>,
}

/// One exit desk per process, so one gate. Set when the exit service is built; absent
/// means exits are not running and a submitted proof has nowhere to go.
static RELEASE_GATE: OnceLock<ReleaseGate> = OnceLock::new();

pub fn release_gate_if_running() -> Option<&'static ReleaseGate> {
    RELEASE_GATE.get()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRefusal {
    Unproven,
    AlreadyHeld,
    Unmatched,
}

/// Accept a submitted release proof only if it proves a payout against the checkpoint.
/// Anything else is refused at the door, so a flood of junk cannot push a vault's real
/// proof out of the queue before the sweep reaches it.
pub fn submit_release(
    gate: &ReleaseGate,
    proof: BitcoinReleaseProof,
) -> Result<(), ReleaseRefusal> {
    let expected = {
        let expected = gate.expected.lock().unwrap_or_else(|e| e.into_inner());
        if expected.is_empty() {
            return Err(ReleaseRefusal::Unmatched);
        }
        expected.clone()
    };
    let proven = proof
        .verify(&gate.params, &gate.checkpoint, gate.confirmation_depth)
        .map_err(|_| ReleaseRefusal::Unproven)?;
    let matches = proven.burn_ref.is_some_and(|burn_ref| {
        expected.get(&burn_ref) == Some(&(proven.beneficiary, proven.amount))
    });
    if !matches {
        return Err(ReleaseRefusal::Unmatched);
    }
    let mut seen = gate.seen.lock().unwrap_or_else(|e| e.into_inner());
    if seen.contains(&proven.foreign_ref) {
        return Err(ReleaseRefusal::AlreadyHeld);
    }
    let mut held = gate.queue.lock().unwrap_or_else(|e| e.into_inner());
    if held.len() >= MAX_PENDING_RELEASES {
        held.remove(0);
    }
    held.push(proof);
    if seen.len() >= MAX_SEEN_RELEASES {
        seen.pop_front();
    }
    seen.push_back(proven.foreign_ref);
    Ok(())
}

impl ExitService {
    pub fn build(cfg: &ExitTrustConfig) -> Result<ExitService, ExitError> {
        let anchor = cfg.build_anchor()?;
        let journal =
            PersistentJournal::open(ReplayStore::new(cfg.ledger_path.with_extension("journal")))?;
        let mut desk = ExitDesk::with_journal(cfg.desk_config(), anchor, Box::new(journal))?;
        for vault in &cfg.vaults {
            desk.register_vault(vault.vault_id, vault.collateral);
        }
        desk.reconstruct()?;
        let mut reserves = q_watchtower::StaticReserves::new();
        for (asset, escrowed) in &cfg.reserves {
            reserves.set(*asset, *escrowed);
        }
        let settle = cfg.bitcoin.as_ref().map(|checkpoint| {
            let pinned = Checkpoint {
                height: checkpoint.height,
                hash: checkpoint.hash,
                min_work: U256::from_be_bytes(&checkpoint.min_work),
            };
            let queue: ReleaseQueue = Arc::new(Mutex::new(Vec::new()));
            let expected: ExpectedReleases = Arc::new(Mutex::new(Default::default()));
            let gate = RELEASE_GATE.get_or_init(|| ReleaseGate {
                queue: queue.clone(),
                params: qlc_bitcoin::BITCOIN,
                checkpoint: pinned.clone(),
                confirmation_depth: checkpoint.confirmations,
                expected: expected.clone(),
                seen: Mutex::new(Default::default()),
            });
            SettleInputs {
                corridor: cfg.corridor,
                assets: cfg.assets.clone(),
                params: qlc_bitcoin::BITCOIN,
                checkpoint: pinned,
                confirmation_depth: checkpoint.confirmations,
                queue: gate.queue.clone(),
                held: Vec::new(),
                expected: gate.expected.clone(),
            }
        });
        Ok(ExitService {
            gateway: None,
            reserves,
            settle,
            desk,
            feed: BurnFeed::new(cfg.start_height, ExitConfig { enabled: true }),
            source: RpcBurnSource::new(cfg.rpc_host.clone(), cfg.rpc_port),
            vault_id: cfg.active_vault(),
            dest_chain: cfg.dest_chain,
        })
    }

    pub fn desk(&self) -> &ExitDesk {
        &self.desk
    }

    pub fn feed_enabled(&self) -> bool {
        self.feed.is_enabled()
    }

    pub fn scanned_through(&self) -> u64 {
        self.feed.scanned_through()
    }

    pub fn vault(&self) -> u32 {
        self.vault_id
    }

    pub fn poll_burns(&mut self, now: u64) -> Result<Vec<ExitId>, FeedError> {
        self.feed
            .drive(&self.source, &mut self.desk, self.vault_id, now)
    }

    pub fn poll_burns_from(
        &mut self,
        source: &dyn QuantovaBurnSource,
        now: u64,
    ) -> Result<Vec<ExitId>, FeedError> {
        self.feed.drive(source, &mut self.desk, self.vault_id, now)
    }

    pub fn settle(
        &mut self,
        id: ExitId,
        watcher: &dyn PayoutWatcher,
        now: u64,
    ) -> Result<ExitDecision, ExitError> {
        self.desk.settle(id, watcher, now)?;
        let statement = self
            .desk
            .exit(id)
            .ok_or(ExitError::UnknownExit)?
            .statement
            .clone();
        Ok(ExitDecision::settle(&statement, self.dest_chain))
    }

    /// Settle every pending exit whose foreign payout has been proven. Runs before the
    /// slash sweep so a proof that lands inside the window settles rather than slashes.
    pub fn sweep_settle(&mut self, now: u64) -> Vec<ExitDecision> {
        let Some(settle) = self.settle.as_mut() else {
            return Vec::new();
        };
        {
            let open: std::collections::BTreeMap<[u8; 32], ([u8; 32], u128)> = self
                .desk
                .settleable(now)
                .into_iter()
                .filter_map(|id| self.desk.exit(id))
                .map(|exit| {
                    let statement = &exit.statement;
                    (
                        statement.burn_ref,
                        (statement.destination, statement.amount),
                    )
                })
                .collect();
            *settle.expected.lock().unwrap_or_else(|e| e.into_inner()) = open;
            let mut queued = settle.queue.lock().unwrap_or_else(|e| e.into_inner());
            settle.held.append(&mut queued);
        }
        while settle.held.len() > MAX_PENDING_RELEASES {
            settle.held.remove(0);
        }
        if settle.held.is_empty() {
            return Vec::new();
        }
        // A watcher owns its proofs for the length of the sweep, so each gets a clone and
        // the held set survives to the next tick. A proof that matched is consumed by the
        // desk's own replay set, so re-offering it settles nothing twice.
        let watchers: Vec<BitcoinPayoutWatcher> = settle
            .assets
            .iter()
            .map(|asset| {
                BitcoinPayoutWatcher::new(
                    settle.corridor,
                    *asset,
                    settle.params,
                    settle.checkpoint.clone(),
                    settle.confirmation_depth,
                    settle.held.clone(),
                )
            })
            .collect();
        let mut decisions = Vec::new();
        for id in self.desk.settleable(now) {
            for watcher in &watchers {
                if let Ok(decision) = self.settle(id, watcher, now) {
                    decisions.push(decision);
                    break;
                }
            }
        }
        decisions
    }

    pub fn sweep_slash(&mut self, now: u64) -> Vec<ExitDecision> {
        let mut decisions = Vec::new();
        for id in self.desk.slashable(now) {
            if self.desk.slash(id, now).is_ok() {
                if let Some(exit) = self.desk.exit(id) {
                    decisions.push(ExitDecision::slash(&exit.statement, self.dest_chain));
                }
            }
        }
        decisions
    }

    pub fn spawn(mut self) -> ExitHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let now = unix_millis();
                let _ = self.poll_burns(now);
                let _ = self.sweep_settle(now);
                let _ = self.sweep_slash(now);
                if let Some(state) = self.gateway.as_ref() {
                    let head = self.feed.scanned_through();
                    let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
                    guard.gateway.advance_to(head);
                    // The independent over mint check, run against the configured escrow.
                    // Any breach pauses the gateway rather than serving another deposit.
                    let breaches =
                        q_watchtower::Watchtower::enforce(&mut guard.gateway, &self.reserves);
                    for breach in &breaches {
                        eprintln!("q-oracle: reserve shortfall, gateway paused: {breach:?}");
                    }
                }
                let mut waited = Duration::ZERO;
                while waited < EXIT_POLL_INTERVAL && !flag.load(Ordering::SeqCst) {
                    thread::sleep(EXIT_POLL_SLICE);
                    waited += EXIT_POLL_SLICE;
                }
            }
        });
        ExitHandle {
            stop,
            thread: Some(thread),
        }
    }
}

pub struct ExitHandle {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ExitHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn start_exits_for(gateway: Option<SharedState>) -> std::io::Result<Option<ExitHandle>> {
    start_exits_inner(load_exit_config(), gateway)
}

#[cfg(test)]
pub(crate) fn start_exits_with(
    loaded: Result<Option<ExitTrustConfig>, ExitConfigError>,
) -> std::io::Result<Option<ExitHandle>> {
    start_exits_inner(loaded, None)
}

pub(crate) fn start_exits_inner(
    loaded: Result<Option<ExitTrustConfig>, ExitConfigError>,
    gateway: Option<SharedState>,
) -> std::io::Result<Option<ExitHandle>> {
    match loaded {
        Ok(None) => Ok(None),
        Ok(Some(cfg)) => {
            // The reserve shortfall breaker audits minted totals against foreign escrow.
            // With no escrow figures it cannot run, and exits would be served with the one
            // independent check on over minting absent, so refuse to start instead.
            if cfg.reserves.is_empty() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "exits are configured but no foreign reserves are, so the reserve \
                     shortfall breaker cannot run; refusing to serve exits",
                ));
            }
            // An exit only leaves the desk two ways: settled against a proven foreign
            // payout, or slashed at the deadline. Settlement needs a payout verifier for
            // the corridor, and only Bitcoin has one. EvmReleaseProof::verify is a stub
            // that always returns EvmCorridorDisabled, so on any other corridor every
            // exit would run to its deadline and slash, destroying the user's funds on
            // this side with no payout on the far side. Refuse rather than serve that.
            if cfg.corridor != BITCOIN_CORRIDOR {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "exits are configured on a corridor with no payout verifier, so every \
                     exit would slash instead of settle; refusing to serve exits",
                ));
            }
            if cfg.bitcoin.is_none() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "the bitcoin exit corridor has no checkpoint configured, so no payout \
                     can be proven and every exit would slash; refusing to serve exits",
                ));
            }
            // A settled or slashed exit only resolves on chain through a quorum signed exit
            // acknowledgement submitted to the bridge settle address. Nothing signs one or
            // submits one: the decisions this service reaches are dropped. The chain then
            // keeps every burn outstanding, and a slash, which pays the holder nothing here
            // because the chain's own slash is what restores the burned tokens, leaves the
            // holder with neither the tokens nor a payout. Refuse until that path exists.
            if !EXIT_ACK_PATH_WIRED {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "no exit acknowledgement reaches the chain, so a slashed exit would leave \
                     the holder with nothing; refusing to serve exits",
                ));
            }
            let mut service = ExitService::build(&cfg).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("the exit trust configuration is unusable, refusing to start: {e:?}"),
                )
            })?;
            service.gateway = gateway;
            Ok(Some(service.spawn()))
        }
        Err(e) => Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("exits are enabled but the trust configuration is incomplete, refusing to start: {e:?}"),
        )),
    }
}

pub const DEST_CHAIN: u32 = 9000;

pub const DEST_CHAIN_ID: u64 = 0;

pub const DEFAULT_EPOCH_CAP: u128 = 1_000_000_000_000_000_000_000_000;

pub const OPERATORS_ENV: &str = "Q_ORACLE_OPERATORS";
pub const QUORUM_ENV: &str = "Q_ORACLE_QUORUM";
pub const DEST_CHAIN_ID_ENV: &str = "Q_ORACLE_DEST_CHAIN_ID";
pub const ERA_ENV: &str = "Q_ORACLE_ERA";
pub const SOURCES_ENV: &str = "Q_ORACLE_SOURCES";

#[derive(Debug)]
pub enum BootConfigError {
    Missing(&'static str),
    Malformed(&'static str),
    EmptyOperatorSet,
    QuorumBelowFloor { got: usize, floor: usize },
    QuorumAboveSize { got: usize, size: usize },
}

/// An operator set and a quorum read from configuration. An empty set leaves every
/// quorum gated control unsatisfiable while still serving, so this refuses instead.
pub fn boot_from_env() -> Result<BridgeState, BootConfigError> {
    let mut state = boot_from_config(
        std::env::var(OPERATORS_ENV).ok().as_deref(),
        std::env::var(QUORUM_ENV).ok().as_deref(),
        std::env::var(DEST_CHAIN_ID_ENV).ok().as_deref(),
        std::env::var(ERA_ENV).ok().as_deref(),
    )?;
    declare_sources_from(&mut state, std::env::var(SOURCES_ENV).ok().as_deref())?;
    Ok(state)
}

/// corridor:operator:endpoint triples. The federated admission gate refuses any signer
/// that is not declared here, and nothing else populates the registry, so without this
/// every federated corridor is closed and the failure reads as `undeclared_source`.
pub fn declare_sources_from(
    state: &mut BridgeState,
    raw: Option<&str>,
) -> Result<(), BootConfigError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let mut parts = entry.split(':');
        let corridor = parts
            .next()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or(BootConfigError::Malformed("source corridor"))?;
        let operator_id = parts
            .next()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or(BootConfigError::Malformed("source operator"))?;
        let endpoint = parts
            .next()
            .and_then(decode_hex)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or(BootConfigError::Malformed("source endpoint"))?;
        declare_operator_source(state, corridor, operator_id, SourceEndpoint(endpoint));
    }
    Ok(())
}

pub fn boot_from_config(
    operators_raw: Option<&str>,
    quorum_raw: Option<&str>,
    dest_raw: Option<&str>,
    era_raw: Option<&str>,
) -> Result<BridgeState, BootConfigError> {
    let raw = operators_raw.ok_or(BootConfigError::Missing(OPERATORS_ENV))?;
    let mut operators: Vec<(u32, Vec<u8>)> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (id, key) = entry
            .split_once(':')
            .ok_or(BootConfigError::Malformed(OPERATORS_ENV))?;
        let id: u32 = id
            .parse()
            .map_err(|_| BootConfigError::Malformed("operator id"))?;
        let key = decode_hex(key).ok_or(BootConfigError::Malformed("operator key"))?;
        operators.push((id, key));
    }
    if operators.is_empty() {
        return Err(BootConfigError::EmptyOperatorSet);
    }
    let quorum: usize = quorum_raw
        .ok_or(BootConfigError::Missing(QUORUM_ENV))?
        .trim()
        .parse()
        .map_err(|_| BootConfigError::Malformed(QUORUM_ENV))?;
    let floor = q_gateway::gateway::supermajority_floor(operators.len());
    if quorum < floor {
        return Err(BootConfigError::QuorumBelowFloor { got: quorum, floor });
    }
    if quorum > operators.len() {
        return Err(BootConfigError::QuorumAboveSize {
            got: quorum,
            size: operators.len(),
        });
    }
    let dest_chain_id: u64 = dest_raw
        .ok_or(BootConfigError::Missing(DEST_CHAIN_ID_ENV))?
        .trim()
        .parse()
        .map_err(|_| BootConfigError::Malformed(DEST_CHAIN_ID_ENV))?;
    // An all zero era separates nothing: it is the same era before and after every restart
    // and every wipe, so an accepted attestation stays replayable for ever. It is one of
    // only two controls against a second mint, so it has to be set, and set to a value.
    let era: [u8; 32] = decode_hex(era_raw.ok_or(BootConfigError::Missing(ERA_ENV))?)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BootConfigError::Malformed(ERA_ENV))?;
    if era == [0u8; 32] {
        return Err(BootConfigError::Malformed(ERA_ENV));
    }

    let mut set = OperatorSet::new(quorum);
    for (id, key) in operators {
        let pk: qtv_crypto::ml_dsa::PublicKey = key
            .try_into()
            .map_err(|_| BootConfigError::Malformed("operator key length"))?;
        if !set.register(id, pk) {
            return Err(BootConfigError::Malformed("duplicate operator"));
        }
    }
    Ok(boot_with(set, dest_chain_id, era, DEFAULT_EPOCH_CAP))
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let text = input.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod boot_config_tests {
    use super::*;

    // Distinct keys: one key under two ids is refused, which is its own protection.
    fn key(tag: u8) -> String {
        format!("{tag:02x}").repeat(qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES)
    }

    fn three() -> String {
        format!("1:{},2:{},3:{}", key(0xa1), key(0xb2), key(0xc3))
    }

    // Serving with no operators leaves every quorum gated control unsatisfiable while the
    // gateway still answers. Refusing to come up is the only safe reading of that config.
    #[test]
    fn an_empty_operator_set_refuses_to_boot() {
        let Err(err) = boot_from_config(Some(""), Some("3"), Some("9000"), Some(&"ab".repeat(32)))
        else {
            panic!("an empty operator set must refuse");
        };
        assert!(matches!(err, BootConfigError::EmptyOperatorSet), "{err:?}");
    }

    #[test]
    fn a_missing_operator_set_refuses_to_boot() {
        let Err(err) = boot_from_config(None, Some("3"), Some("9000"), Some(&"ab".repeat(32)))
        else {
            panic!("a missing operator set must refuse");
        };
        assert!(matches!(err, BootConfigError::Missing(_)), "{err:?}");
    }

    // A quorum under the supermajority floor is a minority that can mint on its own.
    #[test]
    fn a_quorum_below_the_supermajority_floor_refuses_to_boot() {
        let operators = three();
        let Err(err) = boot_from_config(
            Some(&operators),
            Some("1"),
            Some("9000"),
            Some(&"ab".repeat(32)),
        ) else {
            panic!("a quorum of one over three must refuse");
        };
        assert!(
            matches!(err, BootConfigError::QuorumBelowFloor { .. }),
            "{err:?}"
        );
    }

    // An all zero era separates nothing, so it is refused like a missing one.
    #[test]
    fn an_all_zero_era_is_refused() {
        let operators = three();
        let Err(err) = boot_from_config(
            Some(&operators),
            Some("2"),
            Some("9000"),
            Some(&"00".repeat(32)),
        ) else {
            panic!("an all zero era must refuse");
        };
        assert!(matches!(err, BootConfigError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn a_missing_era_is_refused() {
        let operators = three();
        let Err(err) = boot_from_config(Some(&operators), Some("2"), Some("9000"), None) else {
            panic!("a missing era must refuse");
        };
        assert!(matches!(err, BootConfigError::Missing(_)), "{err:?}");
    }

    #[test]
    fn a_configured_set_at_the_floor_boots() {
        let operators = three();
        assert!(boot_from_config(
            Some(&operators),
            Some("2"),
            Some("9000"),
            Some(&"ab".repeat(32))
        )
        .is_ok());
    }
}

pub fn boot() -> BridgeState {
    boot_with(
        OperatorSet::new(0),
        DEST_CHAIN_ID,
        [0u8; 32],
        DEFAULT_EPOCH_CAP,
    )
}

pub fn boot_with(
    operators: OperatorSet,
    dest_chain_id: u64,
    era: [u8; 32],
    epoch_cap: u128,
) -> BridgeState {
    let mut gateway = Gateway::new(DEST_CHAIN, dest_chain_id, operators, epoch_cap);
    gateway.set_era(era);
    BridgeState::seeded(gateway)
}

#[cfg(test)]
pub(crate) const CONFIGURED_DEST_CHAIN_ID: u64 = 0x5100_0000_0000_9000;

#[cfg(test)]
pub(crate) fn boot_configured() -> BridgeState {
    boot_with(
        OperatorSet::new(0),
        CONFIGURED_DEST_CHAIN_ID,
        [0u8; 32],
        DEFAULT_EPOCH_CAP,
    )
}

pub fn declare_operator_source(
    state: &mut BridgeState,
    corridor: u32,
    operator_id: u32,
    endpoint: SourceEndpoint,
) {
    state.sources.declare(corridor, operator_id, endpoint);
}

pub fn shared(state: BridgeState) -> SharedState {
    Arc::new(RwLock::new(state))
}

/// Whether this boot starts the snapshot from nothing. Only when the file is absent AND
/// the operator said this is the first boot; an absent file otherwise is refused.
pub(crate) fn snapshot_is_first_boot(
    path: &std::path::Path,
    init_requested: bool,
) -> std::io::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    if !init_requested {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!(
                "no guard snapshot at {}, so the replay set would start empty; set \
                 {INIT_SNAPSHOT_ENV}=1 only for the very first boot",
                path.display()
            ),
        ));
    }
    Ok(true)
}

/// Once reserves are given at all, they must cover every pool and name only real ones.
/// A mistyped asset id would otherwise leave the real asset with no escrow bound while the
/// configuration looks complete.
pub(crate) fn reserves_cover(
    registered: &[[u8; 16]],
    reserves: &[([u8; 16], u128)],
) -> std::io::Result<()> {
    if let Some((unknown, _)) = reserves
        .iter()
        .find(|(asset, _)| !registered.contains(asset))
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "a foreign reserve names asset {} which no pool registers, refusing to start",
                hex16(unknown)
            ),
        ));
    }
    if let Some(bare) = registered
        .iter()
        .find(|asset| !reserves.iter().any(|(a, _)| a == *asset))
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "pool {} has no foreign reserve, so it would mint with no escrow bound; \
                 refusing to start",
                hex16(bare)
            ),
        ));
    }
    Ok(())
}

/// Bound the deposit mint path by the foreign escrow. Minting past what is held on the far
/// side is refused before the mint rather than detected after it.
pub(crate) fn apply_reserves(state: &SharedState, reserves: &[([u8; 16], u128)]) {
    let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
    for (asset, escrowed) in reserves {
        guard.gateway.set_escrow(*asset, *escrowed);
    }
}

pub fn run<A: ToSocketAddrs>(addr: A, snapshot: Option<PathBuf>) -> std::io::Result<()> {
    // The state comes up first so the exit loop can carry the destination chain height
    // into the gateway. Without a clock every height relative control, the deposit freeze
    // included, is measured against zero and never elapses.
    // The replay set and the minted ledger live in memory. Without a snapshot they are
    // lost on restart and an already accepted attestation mints a second time, so the
    // snapshot is not optional for a serving oracle.
    let Some(path) = snapshot else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "no guard snapshot is configured, so the replay set would not survive a \
             restart and an accepted attestation could mint twice; refusing to serve",
        ));
    };
    // A snapshot that is simply not there, a volume not mounted, a path changed in a
    // redeploy, would otherwise boot an empty replay set and admit every envelope accepted
    // before it a second time. Only a first boot, said so explicitly, starts from nothing.
    let first_boot = snapshot_is_first_boot(
        &path,
        std::env::var(INIT_SNAPSHOT_ENV).as_deref() == Ok("1"),
    )?;
    let store = Some(GuardStore::new(path));
    let state = shared(restore(&store)?);
    if first_boot {
        if let Some(store) = store.as_ref() {
            let encoded = state
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .gateway
                .encode_guard();
            store.save(&encoded)?;
        }
    }
    let reserves = crate::exits::load_reserves().map_err(|e| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("the foreign reserve figures are unusable, refusing to start: {e:?}"),
        )
    })?;
    if reserves.is_empty() {
        eprintln!(
            "q-oracle: no foreign reserves are configured, so deposits mint against the \
             asset caps alone with no escrow bound"
        );
    } else {
        let registered = state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .gateway
            .registered_assets();
        reserves_cover(&registered, &reserves)?;
    }
    apply_reserves(&state, &reserves);
    // Without a chain head the gateway clock stands at zero: a watchdog freeze never lifts,
    // a fact never expires, and the epoch caps never roll. Refuse rather than serve on it.
    let chain_rpc = std::env::var(crate::clock::CHAIN_RPC_ENV).map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "no chain head endpoint is configured, so every height bound control would \
             stand still; refusing to serve",
        )
    })?;
    let (host, port) = crate::clock::parse_chain_rpc(&chain_rpc).ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "the chain head endpoint is not host:port, refusing to start",
        )
    })?;
    let _clock = crate::clock::spawn_clock(state.clone(), RpcBurnSource::new(host, port));
    let _exits = start_exits_for(Some(state.clone()))?;
    run_with(addr, state, store.map(Arc::new))
}

pub(crate) fn restore(store: &Option<GuardStore>) -> std::io::Result<BridgeState> {
    // Serving with an empty operator set makes every quorum gated control permanently
    // unsatisfiable while the gateway still answers, so refuse to come up instead.
    let state = boot_from_env().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the operator configuration is missing or unusable, refusing to serve: {e:?}"),
        )
    })?;
    restore_into(state, store)
}

pub(crate) fn restore_into(
    state: BridgeState,
    store: &Option<GuardStore>,
) -> std::io::Result<BridgeState> {
    let mut state = state;
    if let Some(store) = store {
        if let Some(bytes) = store.load()? {
            state.gateway.rehydrate_guard(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("the guard snapshot is corrupt and was refused: {e:?}"),
                )
            })?;
            for asset in state.gateway.minted_assets_without_a_cap() {
                eprintln!(
                    "q-oracle: restored a minted total for asset {} with no registered cap, \
                     its pool did not survive the restart and it cannot mint until re registered",
                    hex16(&asset)
                );
            }
        }
    }
    Ok(state)
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn run_with<A: ToSocketAddrs>(
    addr: A,
    state: SharedState,
    store: Option<Arc<GuardStore>>,
) -> std::io::Result<()> {
    {
        let guard = state.read().unwrap_or_else(|e| e.into_inner());
        if !guard.gateway.governance_configured() {
            eprintln!(
                "q-oracle: serving with governance unset, pool creation is open until it is set"
            );
        }
    }
    let listener = TcpListener::bind(addr)?;
    serve(listener, state, store);
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_coinbase(
        txid: [u8; 32],
    ) -> (
        [u8; 32],
        Vec<u8>,
        Vec<qlc_bitcoin::MerkleStep>,
        Vec<qlc_bitcoin::MerkleStep>,
    ) {
        let mut coinbase = Vec::new();
        coinbase.extend_from_slice(&1u32.to_le_bytes());
        coinbase.push(0x01);
        coinbase.extend_from_slice(&[0u8; 32]);
        coinbase.extend_from_slice(&[0xff; 4]);
        coinbase.push(0x04);
        coinbase.extend_from_slice(&[0x03, 0x01, 0x00, 0x00]);
        coinbase.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        coinbase.push(0x01);
        coinbase.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        coinbase.push(0x01);
        coinbase.push(0x51);
        coinbase.extend_from_slice(&0u32.to_le_bytes());
        let coinbase_id = qlc_bitcoin::double_sha256(&coinbase);
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(&coinbase_id);
        pair[32..].copy_from_slice(&txid);
        (
            qlc_bitcoin::double_sha256(&pair),
            coinbase,
            vec![qlc_bitcoin::MerkleStep {
                hash: coinbase_id,
                sibling_on_left: true,
            }],
            vec![qlc_bitcoin::MerkleStep {
                hash: txid,
                sibling_on_left: false,
            }],
        )
    }
    use q_airlock::{AttestationEnvelope, SignerSig};
    use q_assets::Network;
    use q_codec::{
        attest_context, AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION,
    };
    use q_federated::derive_asset_id;
    use q_qbridge::{
        handle, BitcoinAnchor, BitcoinProofMaterial, DepositOutcome, DepositProof, DepositRequest,
        ListPoolsRequest, Request, Response,
    };
    use qlc_bitcoin::tx::Transaction;
    use qlc_bitcoin::{BlockHeader, Checkpoint, Network as BtcNetwork, NetworkParams, U256};
    use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

    const TEST_DEST_ID: u64 = 0x0000_002a_0000_2328;

    const EASY: NetworkParams = NetworkParams {
        network: BtcNetwork::Bitcoin,
        name: "Crafted",
        magic: [0xfa, 0xbf, 0xb5, 0xda],
        pow_limit_bits: 0x207f_ffff,
        target_timespan: 1_209_600,
        target_spacing: 600,
        confirmation_depth: 6,
        requires_pinned_checkpoint: false,
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

    fn crafted_bitcoin(
        bridge: &[u8],
        recipient: [u8; 32],
        amount: u64,
    ) -> (BitcoinProofMaterial, BitcoinAnchor, [u8; 32]) {
        let raw = raw_deposit_tx(&[(amount, bridge.to_vec()), (0, op_return(recipient))]);
        let txid = Transaction::parse(&raw).unwrap().txid();
        let (root, coinbase_tx, branch, coinbase_branch) = with_coinbase(txid);
        let mut headers = vec![mine([0u8; 32], root)];
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
            branch,
            raw_tx: raw,
            coinbase_tx,
            coinbase_branch,
        };
        (
            material,
            BitcoinAnchor {
                checkpoint,
                params: EASY,
                bridge_script: bridge.to_vec(),
            },
            txid,
        )
    }

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
        match handle(
            &mut state,
            Request::ListPools(ListPoolsRequest { network_id: None }),
        ) {
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
        let sig = ml_dsa::sign(
            &op.sk,
            &fact.attest_preimage(TEST_DEST_ID),
            &attest_context(&[0u8; 32]),
            &[0u8; 32],
        )
        .unwrap();
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
        let mut state = boot_with(set, TEST_DEST_ID, [0u8; 32], DEFAULT_EPOCH_CAP);
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
            signatures: vec![
                attest(&ops[0], &fact),
                attest(&ops[1], &fact),
                attest(&ops[2], &fact),
            ],
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
        let mut state = boot_configured();
        let asset = derive_asset_id(Network::Bitcoin, "BTC").0;
        let bridge = p2pkh([0x11; 20]);
        let recipient = [0x42u8; 32];
        let (material, anchor, txid) = crafted_bitcoin(&bridge, recipient, 250_000);
        state.set_bitcoin_anchor(anchor);
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
                proof: DepositProof::Bitcoin { material, fact },
            }),
        ) {
            Response::DepositAdmitted(DepositOutcome::AdmittedPendingChainMint(mint)) => {
                assert_eq!(mint.amount, 250_000);
                assert_eq!(mint.source_ref, txid);
                assert!(
                    state.gateway.is_reference_used(&txid),
                    "the trustless admission binds the reference so it cannot be replayed"
                );
            }
            other => panic!("expected a trustless admission, got {other:?}"),
        }
    }

    fn temp_snapshot(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "q-oracle-boot-{tag}-{}-{nanos}.snap",
            std::process::id()
        ));
        path
    }

    #[test]
    fn a_simulated_restart_reloads_the_guard_and_keeps_the_replay_window_closed() {
        let path = temp_snapshot("restart");
        let store = GuardStore::new(path.clone());
        let asset = derive_asset_id(Network::Bitcoin, "BTC").0;

        let mut state = boot();
        state
            .gateway
            .admit_trustless(asset, [0x11; 32], 1, Network::Bitcoin.id())
            .expect("a seeded corridor admits the reference");
        store
            .save(&state.gateway.encode_guard())
            .expect("the admission is persisted");
        drop(state);

        let restored =
            restore_into(boot(), &Some(store)).expect("a present snapshot rehydrates the guard");
        assert!(
            restored.gateway.is_reference_used(&[0x11; 32]),
            "the reserved reference survives the restart"
        );
        assert_eq!(restored.gateway.minted_of_asset(&asset), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_corrupt_snapshot_refuses_to_start_rather_than_serving_an_empty_guard() {
        let path = temp_snapshot("corrupt");
        std::fs::write(&path, b"\xff\xff\xff not a guard snapshot").unwrap();
        let result = restore_into(boot(), &Some(GuardStore::new(path.clone())));
        let err = match result {
            Ok(_) => panic!("a corrupt snapshot must fail closed rather than start"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_absent_snapshot_starts_a_fresh_guard() {
        let path = temp_snapshot("absent");
        let restored =
            restore_into(boot(), &Some(GuardStore::new(path))).expect("first run starts fresh");
        assert!(!restored.gateway.is_reference_used(&[0x11; 32]));
    }

    use crate::exits::{BitcoinCheckpointConfig, VaultSeed};
    use q_exits::{
        BurnWatchError, FinalizedBlock, MemberConfig, ATTEST_PK_BYTES, BEACON_SEED_BYTES,
    };

    fn temp_ledger(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "q-oracle-exitsvc-{tag}-{}-{nanos}.led",
            std::process::id()
        ));
        path
    }

    fn full_exit_config(ledger: PathBuf) -> ExitTrustConfig {
        ExitTrustConfig {
            chain_id: 9000,
            tau: 1,
            slot: 0,
            budget: 100,
            beacon_seed: [0x5a; BEACON_SEED_BYTES],
            members: vec![MemberConfig {
                id: 1,
                weight: 100,
                stake: 100,
                root_digest: [0x11; 32],
                root_slots: 64,
                attest_pk: vec![0u8; ATTEST_PK_BYTES],
            }],
            dest_chain: 9000,
            corridor: 1,
            start_height: 4_199_999,
            vaults: vec![VaultSeed {
                vault_id: 1,
                collateral: 2_000_000,
            }],
            rpc_host: "127.0.0.1".to_string(),
            rpc_port: 8080,
            ledger_path: ledger,
            bitcoin: None,
            assets: vec![[0xa1; 16]],
            max_exit_amount: 0,
            reserves: vec![([0xa1; 16], 1_000_000_000)],
        }
    }

    struct EmptyChain {
        head: u64,
    }

    impl QuantovaBurnSource for EmptyChain {
        fn finalized_height(&self) -> Result<u64, BurnWatchError> {
            Ok(self.head)
        }

        fn finalized_block(&self, _height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError> {
            Ok(None)
        }
    }

    #[test]
    fn a_configured_service_constructs_the_desk_and_drives_the_feed() {
        let path = temp_ledger("drive");
        let cfg = full_exit_config(path.clone());
        let mut service = ExitService::build(&cfg).expect("a full config builds a service");
        assert!(
            service.feed_enabled(),
            "the feed is enabled when exits are configured"
        );
        assert_eq!(service.vault(), 1, "the pool vault is the active vault");
        assert_eq!(
            service.desk().free_collateral(1),
            2_000_000,
            "the vault collateral is registered"
        );
        assert_eq!(
            service.scanned_through(),
            4_199_999,
            "the feed starts at the configured height"
        );

        let opened = service
            .poll_burns_from(&EmptyChain { head: 4_200_004 }, 10)
            .expect("the enabled feed drives");
        assert!(opened.is_empty(), "an empty chain opens no exits");
        assert_eq!(
            service.scanned_through(),
            4_200_004,
            "the feed advanced across the empty range"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_disabled_runtime_starts_no_exit_service() {
        let handle = start_exits_with(Ok(None)).expect("a disabled runtime starts cleanly");
        assert!(
            handle.is_none(),
            "a default disabled runtime starts no exit service"
        );
    }

    #[test]
    fn a_corridor_with_no_payout_verifier_refuses_to_serve_exits() {
        let mut cfg = full_exit_config(temp_ledger("nopayout"));
        cfg.reserves = vec![([0xa1; 16], 1_000_000_000)];
        cfg.bitcoin = Some(BitcoinCheckpointConfig {
            height: 1,
            hash: [0x11; 32],
            min_work: [0x01; 32],
            confirmations: 6,
        });
        // Corridor 1 is not Bitcoin, and EvmReleaseProof::verify is a disabled stub, so
        // no exit on this corridor could ever settle. Serving would slash every one.
        assert_ne!(cfg.corridor, BITCOIN_CORRIDOR);
        let refused = start_exits_inner(Ok(Some(cfg)), None);
        assert!(refused.is_err(), "a corridor that cannot settle is refused");
        assert_eq!(refused.err().unwrap().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn the_bitcoin_corridor_without_a_checkpoint_refuses_to_serve_exits() {
        let mut cfg = full_exit_config(temp_ledger("nocheckpoint"));
        cfg.corridor = BITCOIN_CORRIDOR;
        cfg.reserves = vec![([0xa1; 16], 1_000_000_000)];
        cfg.bitcoin = None;
        let refused = start_exits_inner(Ok(Some(cfg)), None);
        assert!(
            refused.is_err(),
            "no checkpoint means no payout can be proven, so exits are refused"
        );
        assert_eq!(refused.err().unwrap().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_service_without_a_checkpoint_settles_nothing_rather_than_panicking() {
        let mut cfg = full_exit_config(temp_ledger("nosweep"));
        cfg.bitcoin = None;
        let mut service = ExitService::build(&cfg).expect("the desk still builds");
        assert!(
            service.sweep_settle(1).is_empty(),
            "with no checkpoint the sweep is a no-op"
        );
    }

    #[test]
    fn a_release_proof_that_proves_nothing_never_enters_the_queue() {
        let gate = ReleaseGate {
            queue: Arc::new(Mutex::new(Vec::new())),
            params: qlc_bitcoin::BITCOIN,
            checkpoint: Checkpoint {
                height: 100,
                hash: [0x11; 32],
                min_work: U256::ONE,
            },
            confirmation_depth: 6,
            expected: Arc::new(Mutex::new(
                [([0x42; 32], ([0x43; 32], 1u128))].into_iter().collect(),
            )),
            seen: Mutex::new(Default::default()),
        };
        let junk = BitcoinReleaseProof {
            headers: vec![qlc_bitcoin::BlockHeader {
                version: 1,
                prev_block: [0; 32],
                merkle_root: [0; 32],
                timestamp: 0,
                bits: 0,
                nonce: 0,
            }],
            start_height: 100,
            release_height: 100,
            branch: Vec::new(),
            raw_tx: vec![0u8; 60],
            coinbase_tx: Vec::new(),
            coinbase_branch: Vec::new(),
        };
        for _ in 0..(MAX_PENDING_RELEASES + 1) {
            assert_eq!(
                submit_release(&gate, junk.clone()),
                Err(ReleaseRefusal::Unproven)
            );
        }
        assert!(
            gate.queue.lock().unwrap().is_empty(),
            "a flood of junk cannot push a real proof out of the queue"
        );
    }

    #[test]
    fn reserves_must_cover_every_pool_and_name_only_real_ones() {
        let pools = [[0xa1; 16], [0xb2; 16]];
        assert!(reserves_cover(&pools, &[([0xa1; 16], 10), ([0xb2; 16], 20)]).is_ok());
        assert!(
            reserves_cover(&pools, &[([0xa1; 16], 10)]).is_err(),
            "a pool left out would mint with no escrow bound"
        );
        assert!(
            reserves_cover(
                &pools,
                &[([0xa1; 16], 10), ([0xb2; 16], 20), ([0xc3; 16], 5)]
            )
            .is_err(),
            "a reserve for an asset no pool registers is a typo, not a bound"
        );
    }

    #[test]
    fn a_missing_snapshot_is_refused_unless_this_is_the_first_boot() {
        let path = temp_ledger("nosnapshot").with_extension("guard");
        let _ = std::fs::remove_file(&path);
        assert!(
            snapshot_is_first_boot(&path, false).is_err(),
            "an absent snapshot would boot an empty replay set"
        );
        assert!(snapshot_is_first_boot(&path, true).unwrap());
        std::fs::write(&path, b"x").unwrap();
        assert!(
            !snapshot_is_first_boot(&path, true).unwrap(),
            "a snapshot that exists is never treated as a first boot"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reserves_bound_the_deposit_mint_with_exits_off() {
        let asset = [0xa1; 16];
        let state = shared(boot_configured());
        {
            let mut guard = state.write().unwrap();
            guard.gateway.register_corridor(1, 6);
            guard.gateway.register_asset_cap(asset, 1_000_000_000);
            guard.gateway.advance_to(10_000);
        }
        apply_reserves(&state, &[(asset, 1_000)]);
        let mut guard = state.write().unwrap();
        assert!(guard
            .gateway
            .admit_trustless(asset, [1; 32], 1_000, 1)
            .is_ok());
        assert!(
            matches!(
                guard.gateway.admit_trustless(asset, [2; 32], 1, 1),
                Err(q_gateway::GatewayError::EscrowExceeded { .. })
            ),
            "the escrow bound holds on the deposit path without any exit configuration"
        );
    }

    #[test]
    fn a_complete_bitcoin_exit_configuration_is_refused_while_no_ack_reaches_the_chain() {
        let mut cfg = full_exit_config(temp_ledger("noack"));
        cfg.corridor = BITCOIN_CORRIDOR;
        cfg.reserves = vec![([0xa1; 16], 1_000_000_000)];
        cfg.bitcoin = Some(BitcoinCheckpointConfig {
            height: 1,
            hash: [0x11; 32],
            min_work: [0x01; 32],
            confirmations: 6,
        });
        let refused = start_exits_inner(Ok(Some(cfg)), None);
        assert!(
            refused.is_err(),
            "every prerequisite is met, but a slash would still leave the holder with nothing"
        );
        assert_eq!(refused.err().unwrap().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn an_enabled_but_unconfigured_runtime_refuses_to_start() {
        let refused = start_exits_with(Err(ExitConfigError::Missing("chain id")));
        assert!(
            refused.is_err(),
            "an enabled but half configured runtime fails closed"
        );
        assert_eq!(refused.err().unwrap().kind(), ErrorKind::InvalidInput);
    }
}
