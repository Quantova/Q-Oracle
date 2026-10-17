// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use q_airlock::SignerSig;
use q_gateway::{Gateway, GatewayError, RESERVE_MAX_AGE};
use q_watchtower::{Breach, StaticReserves, Watchtower};

use crate::anchors::{read_anchor_file, AnchorFileError};
use crate::http::SharedState;
use crate::json::{self, Json};
use crate::persist::GuardStore;
use crate::wire::{as_u128, as_u64, field, hex_array, signer_sigs_from};

pub const RESERVE_REPORTS_ENV: &str = "Q_ORACLE_RESERVE_REPORTS";
pub const RESERVE_MAX_AGE_ENV: &str = "Q_ORACLE_RESERVE_MAX_AGE";
pub const MAX_RESERVE_REPORTS: usize = 1024;

const RESERVE_POLL: Duration = Duration::from_secs(15);
const RESERVE_SLICE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveReport {
    pub asset_id: [u8; 16],
    pub escrowed: u128,
    pub at_height: u64,
    pub signatures: Vec<SignerSig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveSourceError {
    File(AnchorFileError),
    Malformed(String),
    BadMaxAge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveSource {
    pub path: PathBuf,
    pub max_age: u64,
}

pub fn reserve_source_from(
    path: Option<&std::ffi::OsStr>,
    max_age: Option<&str>,
) -> Result<Option<ReserveSource>, ReserveSourceError> {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let max_age = match max_age.map(str::trim).filter(|v| !v.is_empty()) {
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|age| (1..=RESERVE_MAX_AGE).contains(age))
            .ok_or(ReserveSourceError::BadMaxAge)?,
        None => RESERVE_MAX_AGE,
    };
    Ok(Some(ReserveSource {
        path: PathBuf::from(path),
        max_age,
    }))
}

pub fn reserve_source_from_env() -> Result<Option<ReserveSource>, ReserveSourceError> {
    reserve_source_from(
        std::env::var_os(RESERVE_REPORTS_ENV).as_deref(),
        std::env::var(RESERVE_MAX_AGE_ENV).ok().as_deref(),
    )
}

pub fn parse_reserve_reports(text: &str) -> Result<Vec<ReserveReport>, ReserveSourceError> {
    let malformed = |e: crate::wire::WireError| ReserveSourceError::Malformed(format!("{e:?}"));
    let root = json::parse(text).map_err(ReserveSourceError::Malformed)?;
    let items = field(&root, "reports")
        .map_err(malformed)?
        .as_array()
        .ok_or_else(|| ReserveSourceError::Malformed("reports is not a list".to_string()))?;
    if items.len() > MAX_RESERVE_REPORTS {
        return Err(ReserveSourceError::Malformed(
            "too many reserve reports".to_string(),
        ));
    }
    let mut reports = Vec::with_capacity(items.len());
    for item in items {
        reports.push(report_from(item).map_err(malformed)?);
    }
    Ok(reports)
}

fn report_from(j: &Json) -> Result<ReserveReport, crate::wire::WireError> {
    Ok(ReserveReport {
        asset_id: hex_array::<16>(field(j, "asset_id")?, "asset_id")?,
        escrowed: as_u128(field(j, "escrowed")?, "escrowed")?,
        at_height: as_u64(field(j, "at_height")?, "at_height")?,
        signatures: signer_sigs_from(field(j, "signatures")?)?,
    })
}

pub fn load_reserve_reports(path: &Path) -> Result<Vec<ReserveReport>, ReserveSourceError> {
    parse_reserve_reports(&read_anchor_file(path).map_err(ReserveSourceError::File)?)
}

pub fn enforce_reserves(gateway: &mut Gateway) -> Vec<Breach> {
    let mut reserves = StaticReserves::new();
    let minted: Vec<[u8; 16]> = gateway.minted_by_asset().keys().copied().collect();
    for asset_id in minted {
        if let Some(escrowed) = gateway.escrow_of(&asset_id) {
            reserves.set(asset_id, escrowed);
        }
    }
    Watchtower::enforce(gateway, &reserves)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReserveTick {
    pub accepted: usize,
    pub refused: Vec<([u8; 16], GatewayError)>,
    pub breaches: Vec<Breach>,
    pub stale: Vec<[u8; 16]>,
    pub source_error: Option<ReserveSourceError>,
}

pub fn apply_reserve_reports(
    state: &SharedState,
    reports: &[ReserveReport],
    tick: &mut ReserveTick,
) {
    for report in reports {
        {
            let guard = state.read().unwrap_or_else(|e| e.into_inner());
            if guard
                .gateway
                .reserve_reported_at(&report.asset_id)
                .is_some_and(|last| report.at_height <= last)
            {
                continue;
            }
            if let Err(err) = guard.gateway.precheck_reserve(
                report.asset_id,
                report.escrowed,
                report.at_height,
                &report.signatures,
            ) {
                tick.refused.push((report.asset_id, err));
                continue;
            }
        }
        let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
        match guard.gateway.attest_reserve(
            report.asset_id,
            report.escrowed,
            report.at_height,
            &report.signatures,
        ) {
            Ok(_) => tick.accepted += 1,
            Err(err) => tick.refused.push((report.asset_id, err)),
        }
    }
}

pub struct ReserveWatch {
    source: ReserveSource,
    store: Option<Arc<GuardStore>>,
}

impl ReserveWatch {
    pub fn new(source: ReserveSource, store: Option<Arc<GuardStore>>) -> ReserveWatch {
        ReserveWatch { source, store }
    }

    pub fn arm(&self, state: &SharedState) {
        state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .gateway
            .require_reserve_reports(self.source.max_age);
    }

    pub fn tick(&self, state: &SharedState) -> ReserveTick {
        let mut tick = ReserveTick::default();
        match load_reserve_reports(&self.source.path) {
            Ok(reports) => apply_reserve_reports(state, &reports, &mut tick),
            Err(err) => tick.source_error = Some(err),
        }
        let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
        let rev_before = guard.gateway.guard_revision();
        tick.breaches = enforce_reserves(&mut guard.gateway);
        tick.stale = guard.gateway.stale_reserves();
        if guard.gateway.guard_revision() != rev_before {
            if let Some(store) = self.store.as_deref() {
                if let Err(e) = store.save(&guard.gateway.encode_guard()) {
                    eprintln!("q-oracle: the reserve breaker tripped but could not be saved: {e}");
                }
            }
        }
        tick
    }

    pub fn spawn(self, state: SharedState) -> ReserveHandle {
        self.arm(&state);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::spawn(move || {
            let mut reported_stale: Vec<[u8; 16]> = Vec::new();
            let mut source_failing = false;
            while !flag.load(Ordering::SeqCst) {
                let tick = self.tick(&state);
                for breach in &tick.breaches {
                    eprintln!("q-oracle: reserve shortfall, gateway paused: {breach:?}");
                }
                for (asset_id, err) in &tick.refused {
                    eprintln!(
                        "q-oracle: a reserve report for asset {} was refused: {err:?}",
                        hex(asset_id)
                    );
                }
                match &tick.source_error {
                    Some(err) if !source_failing => {
                        eprintln!("q-oracle: the reserve report source is unusable: {err:?}");
                        source_failing = true;
                    }
                    Some(_) => {}
                    None => source_failing = false,
                }
                if tick.stale != reported_stale {
                    for asset_id in &tick.stale {
                        eprintln!(
                            "q-oracle: no fresh signed reserve report for asset {}, it mints nothing until one arrives",
                            hex(asset_id)
                        );
                    }
                    reported_stale = tick.stale;
                }
                let mut waited = Duration::ZERO;
                while waited < RESERVE_POLL && !flag.load(Ordering::SeqCst) {
                    thread::sleep(RESERVE_SLICE);
                    waited += RESERVE_SLICE;
                }
            }
        });
        ReserveHandle {
            stop,
            thread: Some(thread),
        }
    }
}

pub struct ReserveHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ReserveHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
