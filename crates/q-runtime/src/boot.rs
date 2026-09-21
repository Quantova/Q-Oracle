// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::ErrorKind;
use std::net::{TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use q_exits::{
    BurnFeed, ExitConfig, ExitDecision, ExitDesk, ExitError, ExitId, FeedError, PayoutWatcher,
    PersistentJournal, QuantovaBurnSource, ReplayStore, RpcBurnSource,
};
use q_federated::SourceEndpoint;
use q_gateway::{Gateway, OperatorSet};
use q_qbridge::BridgeState;

use crate::exits::{load_exit_config, ExitConfigError, ExitTrustConfig};
use crate::http::{serve, SharedState};
use crate::persist::GuardStore;

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
        Ok(ExitService {
            gateway: None,
            reserves,
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

pub fn start_exits() -> std::io::Result<Option<ExitHandle>> {
    start_exits_with(load_exit_config())
}

pub(crate) fn start_exits_for(gateway: Option<SharedState>) -> std::io::Result<Option<ExitHandle>> {
    start_exits_inner(load_exit_config(), gateway)
}

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
    boot_from_config(
        std::env::var(OPERATORS_ENV).ok().as_deref(),
        std::env::var(QUORUM_ENV).ok().as_deref(),
        std::env::var(DEST_CHAIN_ID_ENV).ok().as_deref(),
        std::env::var(ERA_ENV).ok().as_deref(),
    )
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
    let era: [u8; 32] = match era_raw {
        Some(raw) => decode_hex(raw)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(BootConfigError::Malformed(ERA_ENV))?,
        None => [0u8; 32],
    };

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
    if !text.len().is_multiple_of(2) {
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
        let Err(err) = boot_from_config(Some(""), Some("3"), Some("9000"), None) else {
            panic!("an empty operator set must refuse");
        };
        assert!(matches!(err, BootConfigError::EmptyOperatorSet), "{err:?}");
    }

    #[test]
    fn a_missing_operator_set_refuses_to_boot() {
        let Err(err) = boot_from_config(None, Some("3"), Some("9000"), None) else {
            panic!("a missing operator set must refuse");
        };
        assert!(matches!(err, BootConfigError::Missing(_)), "{err:?}");
    }

    // A quorum under the supermajority floor is a minority that can mint on its own.
    #[test]
    fn a_quorum_below_the_supermajority_floor_refuses_to_boot() {
        let operators = three();
        let Err(err) = boot_from_config(Some(&operators), Some("1"), Some("9000"), None) else {
            panic!("a quorum of one over three must refuse");
        };
        assert!(
            matches!(err, BootConfigError::QuorumBelowFloor { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_configured_set_at_the_floor_boots() {
        let operators = three();
        assert!(boot_from_config(Some(&operators), Some("2"), Some("9000"), None).is_ok());
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

pub fn run<A: ToSocketAddrs>(addr: A, snapshot: Option<PathBuf>) -> std::io::Result<()> {
    // The state comes up first so the exit loop can carry the destination chain height
    // into the gateway. Without a clock every height relative control, the deposit freeze
    // included, is measured against zero and never elapses.
    let store = snapshot.map(|path| GuardStore::new(path));
    let state = shared(restore(&store)?);
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

    use crate::exits::VaultSeed;
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
    fn an_enabled_but_unconfigured_runtime_refuses_to_start() {
        let refused = start_exits_with(Err(ExitConfigError::Missing("chain id")));
        assert!(
            refused.is_err(),
            "an enabled but half configured runtime fails closed"
        );
        assert_eq!(refused.err().unwrap().kind(), ErrorKind::InvalidInput);
    }
}
