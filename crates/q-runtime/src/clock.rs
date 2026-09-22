// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use q_exits::RpcBurnSource;

use crate::http::SharedState;

/// Where the Quantova node answers `finalized_head`, as `host:port`. Every height relative
/// control in the gateway, the watchdog window, freeze expiry and fact expiry, is measured
/// against the height this feeds in; without it the clock stands at zero for good.
pub const CHAIN_RPC_ENV: &str = "Q_ORACLE_CHAIN_RPC";

const CLOCK_POLL: Duration = Duration::from_secs(5);
const CLOCK_SLICE: Duration = Duration::from_millis(100);
// A node that reports a height far past what real time allows is not believed at once:
// the clock moves at most this fast, so a lying endpoint cannot lift every freeze and
// expire every fact in one answer. An honest chain far ahead is caught up over time.
const MAX_BLOCKS_PER_SEC: u64 = 4;
const CLOCK_SLACK_SECS: u64 = 60;

pub trait ChainHead {
    fn head_and_epoch(&self) -> Result<(u64, Option<u64>), String>;
}

impl ChainHead for RpcBurnSource {
    fn head_and_epoch(&self) -> Result<(u64, Option<u64>), String> {
        self.finalized_head_and_epoch()
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

/// The height the clock may move to, given the last height it accepted and how long ago.
pub fn bounded_head(last: Option<(u64, Duration)>, reported: u64) -> u64 {
    match last {
        None => reported,
        Some((height, elapsed)) => {
            let allowed = elapsed
                .as_secs()
                .saturating_add(CLOCK_SLACK_SECS)
                .saturating_mul(MAX_BLOCKS_PER_SEC);
            reported.min(height.saturating_add(allowed))
        }
    }
}

pub struct ChainClock<H: ChainHead> {
    head: H,
    last: Option<(u64, Instant)>,
}

impl<H: ChainHead> ChainClock<H> {
    pub fn new(head: H) -> ChainClock<H> {
        ChainClock { head, last: None }
    }

    /// One poll. Moves the gateway forward, never back, and follows the chain's epoch.
    pub fn tick(&mut self, state: &SharedState) -> Result<u64, String> {
        let (reported, epoch) = self.head.head_and_epoch()?;
        let now = Instant::now();
        let head = bounded_head(
            self.last
                .map(|(height, at)| (height, now.duration_since(at))),
            reported,
        );
        let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
        guard.gateway.advance_to(head);
        if let Some(epoch) = epoch {
            guard.gateway.advance_epoch_to(epoch);
        }
        let accepted = guard.gateway.current_height();
        drop(guard);
        self.last = Some((accepted, now));
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
        let mut clock = ChainClock::new(head);
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
    use crate::boot::{boot_configured, shared};
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
        let mut clock =
            ChainClock::new(Scripted(RefCell::new(vec![(120, Some(0)), (125, Some(0))])));
        assert_eq!(clock.tick(&state).unwrap(), 120);
        assert_eq!(clock.tick(&state).unwrap(), 125);
        assert_eq!(state.read().unwrap().gateway.current_height(), 125);
    }

    #[test]
    fn a_head_that_goes_backwards_never_rewinds_the_clock() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::new(Scripted(RefCell::new(vec![(500, None), (10, None)])));
        clock.tick(&state).unwrap();
        assert_eq!(clock.tick(&state).unwrap(), 500);
    }

    #[test]
    fn a_leap_past_real_time_is_taken_only_as_far_as_time_allows() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::new(Scripted(RefCell::new(vec![
            (1_000, None),
            (u64::MAX, None),
        ])));
        clock.tick(&state).unwrap();
        let moved = clock.tick(&state).unwrap();
        assert!(moved > 1_000, "the clock still advances");
        assert!(
            moved <= 1_000 + (CLOCK_SLACK_SECS + 1) * MAX_BLOCKS_PER_SEC,
            "but one answer cannot carry it to the end of time"
        );
    }

    #[test]
    fn the_chain_epoch_rolls_the_epoch_caps() {
        let state = shared(boot_configured());
        let mut clock = ChainClock::new(Scripted(RefCell::new(vec![(10, Some(3)), (11, Some(2))])));
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
