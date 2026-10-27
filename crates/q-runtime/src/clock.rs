// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use q_exits::{QuantovaAnchor, RpcBurnSource};

use crate::http::SharedState;

pub const CHAIN_RPC_ENV: &str = "Q_ORACLE_CHAIN_RPC";
pub const EXPECTED_HEAD_ENV: &str = "Q_ORACLE_EXPECTED_HEAD";
pub const EXPECTED_EPOCH_ENV: &str = "Q_ORACLE_EXPECTED_EPOCH";
pub const MAX_BLOCKS_PER_SEC_ENV: &str = "Q_ORACLE_MAX_BLOCKS_PER_SEC";
pub const MIN_EPOCH_SECS_ENV: &str = "Q_ORACLE_MIN_EPOCH_SECS";

const CLOCK_POLL: Duration = Duration::from_secs(5);
const CLOCK_SLICE: Duration = Duration::from_millis(100);
const MAX_BLOCKS_PER_SEC: u64 = 20;
const CLOCK_SLACK_BLOCKS: u64 = 240;
const MIN_EPOCH_GAP: Duration = Duration::from_secs(6 * 60 * 60);
const GENESIS_UNIX_SECS: u64 = 1_735_689_600;

fn max_blocks_per_sec() -> u64 {
    static RATE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *RATE.get_or_init(|| {
        std::env::var(MAX_BLOCKS_PER_SEC_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(MAX_BLOCKS_PER_SEC, |rate| rate.clamp(1, MAX_BLOCKS_PER_SEC))
    })
}

fn min_epoch_gap() -> Duration {
    static GAP: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *GAP.get_or_init(|| {
        if crate::exits::mainnet_configured() {
            return MIN_EPOCH_GAP;
        }
        std::env::var(MIN_EPOCH_SECS_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(MIN_EPOCH_GAP, |secs| Duration::from_secs(secs.max(60)))
    })
}

fn wall_clock_head_cap() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(GENESIS_UNIX_SECS)
        .saturating_mul(max_blocks_per_sec())
        .saturating_add(CLOCK_SLACK_BLOCKS)
}

pub trait ChainHead {
    fn head_and_epoch(&self) -> Result<(u64, Option<u64>), String>;
}

impl ChainHead for RpcBurnSource {
    fn head_and_epoch(&self) -> Result<(u64, Option<u64>), String> {
        self.finalized_head_and_epoch()
            .map_err(|e| format!("{e:?}"))
    }
}

pub struct CertifiedHead {
    source: RpcBurnSource,
    anchor: QuantovaAnchor,
}

impl CertifiedHead {
    pub fn new(source: RpcBurnSource, anchor: QuantovaAnchor) -> CertifiedHead {
        CertifiedHead { source, anchor }
    }
}

impl ChainHead for CertifiedHead {
    fn head_and_epoch(&self) -> Result<(u64, Option<u64>), String> {
        self.source
            .certified_head_and_epoch(&self.anchor)
            .map_err(|e| format!("{e:?}"))
    }
}

pub fn parse_chain_rpc(raw: &str) -> Option<(String, u16)> {
    let (host, port) = raw.trim().rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((host.to_string(), port))
}

pub fn bounded_head(last: Option<(u64, Duration)>, reported: u64) -> u64 {
    match last {
        None => reported,
        Some((height, elapsed)) => {
            let allowed = elapsed
                .as_secs()
                .saturating_mul(max_blocks_per_sec())
                .saturating_add(CLOCK_SLACK_BLOCKS);
            reported.min(height.saturating_add(allowed))
        }
    }
}

pub struct ChainClock<H: ChainHead> {
    head: H,
    origin: Option<(u64, Instant)>,
    epoch_moved: Option<Instant>,
    fresh: bool,
    first_boot: Option<(u64, u64)>,
}

impl<H: ChainHead> ChainClock<H> {
    pub fn new(head: H) -> ChainClock<H> {
        ChainClock {
            head,
            origin: None,
            epoch_moved: None,
            fresh: false,
            first_boot: None,
        }
    }

    pub fn with_first_boot(head: H, expected_head: u64, expected_epoch: u64) -> ChainClock<H> {
        ChainClock {
            first_boot: Some((expected_head, expected_epoch)),
            ..ChainClock::new(head)
        }
    }

    pub fn tick(&mut self, state: &SharedState) -> Result<u64, String> {
        let (reported, epoch) = self.head.head_and_epoch()?;
        let now = Instant::now();
        let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
        let (origin_height, origin_at) = match self.origin {
            Some(origin) => origin,
            None => {
                let restored = guard.gateway.current_height();
                self.fresh = restored == 0;
                if self.fresh {
                    let (expected_head, _) = self.first_boot.ok_or_else(|| {
                        format!(
                            "a first boot with no saved height needs {EXPECTED_HEAD_ENV} set to the \
                             current chain height, the clock will not take an unsigned head on trust"
                        )
                    })?;
                    guard
                        .gateway
                        .advance_to(reported.min(expected_head).min(wall_clock_head_cap()));
                }
                let origin = (guard.gateway.current_height(), now);
                self.origin = Some(origin);
                origin
            }
        };
        let head = bounded_head(
            Some((origin_height, now.duration_since(origin_at))),
            reported,
        )
        .min(wall_clock_head_cap());
        guard.gateway.advance_to(head);
        if let Some(epoch) = epoch {
            let current = guard.gateway.current_epoch();
            let spaced = self
                .epoch_moved
                .is_none_or(|at| now.duration_since(at) >= min_epoch_gap());
            let first_epoch = self.first_boot.map_or(0, |(_, e)| e);
            let first_boot_catch_up =
                self.fresh && self.epoch_moved.is_none() && epoch > current && epoch <= first_epoch;
            let established = !self.fresh || self.epoch_moved.is_some();
            if first_boot_catch_up || (established && epoch > current && spaced) {
                guard.gateway.advance_epoch_to(epoch);
                self.epoch_moved = Some(now);
            }
        }
        let accepted = guard.gateway.current_height();
        drop(guard);
        Ok(accepted)
    }
}

pub struct ClockHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ClockHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn_clock<H: ChainHead + Send + 'static>(state: SharedState, head: H) -> ClockHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = thread::spawn(move || {
        let expected = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let mut clock = match expected(EXPECTED_HEAD_ENV) {
            Some(height) => {
                ChainClock::with_first_boot(head, height, expected(EXPECTED_EPOCH_ENV).unwrap_or(0))
            }
            None => ChainClock::new(head),
        };
        let mut failing = false;
        while !flag.load(Ordering::SeqCst) {
            match clock.tick(&state) {
                Ok(_) => failing = false,
                Err(e) => {
                    if !failing {
                        eprintln!("q-oracle: the chain clock cannot read the head: {e}");
                    }
                    failing = true;
                }
            }
            let mut waited = Duration::ZERO;
            while waited < CLOCK_POLL && !flag.load(Ordering::SeqCst) {
                thread::sleep(CLOCK_SLICE);
                waited += CLOCK_SLICE;
            }
        }
    });
    ClockHandle {
        stop,
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::{apply_reserves, boot_configured, shared};
    use std::cell::RefCell;

    struct Scripted(RefCell<Vec<(u64, Option<u64>)>>);

    impl ChainHead for Scripted {
        fn head_and_epoch(&self) -> Result<(u64, Option<u64>), String> {
            let mut left = self.0.borrow_mut();
            if left.is_empty() {
                return Err("exhausted".to_string());
            }
            Ok(left.remove(0))
        }
    }

    #[test]
    fn the_clock_carries_the_chain_head_into_the_gateway() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::with_first_boot(
            Scripted(RefCell::new(vec![(120, Some(0)), (125, Some(0))])),
            1_000,
            0,
        );
        assert_eq!(clock.tick(&state).unwrap(), 120);
        assert_eq!(clock.tick(&state).unwrap(), 125);
        assert_eq!(state.read().unwrap().gateway.current_height(), 125);
    }

    #[test]
    fn a_head_that_goes_backwards_never_rewinds_the_clock() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::with_first_boot(
            Scripted(RefCell::new(vec![(500, None), (10, None)])),
            1_000,
            0,
        );
        clock.tick(&state).unwrap();
        assert_eq!(clock.tick(&state).unwrap(), 500);
    }

    #[test]
    fn a_leap_past_real_time_is_taken_only_as_far_as_time_allows() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::with_first_boot(
            Scripted(RefCell::new(vec![(1_000, None), (u64::MAX, None)])),
            1_000,
            0,
        );
        clock.tick(&state).unwrap();
        let moved = clock.tick(&state).unwrap();
        assert!(moved > 1_000, "the clock still advances");
        assert!(
            moved <= 1_000 + CLOCK_SLACK_BLOCKS + MAX_BLOCKS_PER_SEC,
            "but one answer cannot carry it to the end of time"
        );
    }

    #[test]
    fn the_chain_epoch_rolls_the_epoch_caps() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::with_first_boot(
            Scripted(RefCell::new(vec![(10, Some(3)), (11, Some(2))])),
            1_000,
            3,
        );
        clock.tick(&state).unwrap();
        assert_eq!(state.read().unwrap().gateway.current_epoch(), 3);
        clock.tick(&state).unwrap();
        assert_eq!(
            state.read().unwrap().gateway.current_epoch(),
            3,
            "an older epoch from a lagging node changes nothing"
        );
    }

    #[test]
    fn a_restarted_clock_bounds_its_first_answer_from_the_restored_height() {
        let state = shared(boot_configured());
        state.write().unwrap().gateway.advance_to(5_000);
        let mut clock = ChainClock::new(Scripted(RefCell::new(vec![(u64::MAX, None)])));
        let moved = clock.tick(&state).unwrap();
        assert!(moved <= 5_000 + CLOCK_SLACK_BLOCKS + MAX_BLOCKS_PER_SEC);
    }

    #[test]
    fn a_restarted_clock_catches_up_across_several_epochs_and_resets_the_counters() {
        let asset = [0xa1; 16];
        let state = shared(boot_configured());
        {
            let mut guard = state.write().unwrap();
            guard.gateway.register_corridor(1, 6);
            guard.gateway.register_asset_cap(asset, 1_000_000_000);
            guard.gateway.advance_to(10_000);
        }
        apply_reserves(&state, &[(asset, 10_000)]);
        {
            let mut guard = state.write().unwrap();
            guard
                .gateway
                .admit_trustless(asset, [1; 32], 1_000, 1)
                .unwrap();
            assert_eq!(guard.gateway.current_epoch(), 0);
            assert_eq!(guard.gateway.epoch_minted(), 1_000);
        }
        let mut clock = ChainClock::new(Scripted(RefCell::new(vec![
            (10_001, Some(5)),
            (10_002, Some(6)),
        ])));
        clock.tick(&state).unwrap();
        {
            let guard = state.read().unwrap();
            assert_eq!(
                guard.gateway.current_epoch(),
                5,
                "the local epoch catches up to the reported epoch in one tick"
            );
            assert_eq!(
                guard.gateway.epoch_minted(),
                0,
                "the per epoch mint counters reset across the whole jump"
            );
        }
        clock.tick(&state).unwrap();
        assert_eq!(
            state.read().unwrap().gateway.current_epoch(),
            5,
            "a further step inside the gap is still rate limited"
        );
    }

    #[test]
    fn the_endpoint_parses_as_host_and_port() {
        assert_eq!(
            parse_chain_rpc("127.0.0.1:8645"),
            Some(("127.0.0.1".to_string(), 8645))
        );
        assert_eq!(parse_chain_rpc("node:0"), None);
        assert_eq!(parse_chain_rpc(":8645"), None);
        assert_eq!(parse_chain_rpc("nohost"), None);
    }
}
