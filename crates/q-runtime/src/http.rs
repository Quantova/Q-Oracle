// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Result as IoResult, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use q_qbridge::{
    commit_deposit, handle, handle_read, verify_deposit, BridgeState, Request, Response,
};

use crate::json::{self, object, Json};
use crate::persist::GuardStore;
use crate::watch::{persist_or_rollback, Durability};
use crate::wire::{decode_request, encode_response};

pub const MAX_BODY: usize = 2 * 1024 * 1024;

pub const MAX_HEAD: usize = 16 * 1024;

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub const REQUEST_DEADLINE: Duration = Duration::from_secs(8);

pub const MAX_CONNECTIONS: usize = 512;

pub const MAX_CONNECTIONS_PER_IP: usize = 32;

pub const RATE_WINDOW: Duration = Duration::from_secs(1);

pub const MAX_ADMITS_PER_WINDOW: usize = 256;

pub const MAX_ADMITS_PER_IP_PER_WINDOW: usize = 16;

pub type SharedState = Arc<RwLock<BridgeState>>;

enum Admit {
    Ok,
    TotalFull,
    IpFull,
}

#[derive(Default)]
struct Limiter {
    inner: Mutex<LimiterInner>,
}

#[derive(Default)]
struct LimiterInner {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl Limiter {
    fn try_admit(&self, ip: IpAddr, total_cap: usize, per_ip_cap: usize) -> Admit {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.total >= total_cap {
            return Admit::TotalFull;
        }
        let count = inner.per_ip.entry(ip).or_insert(0);
        if *count >= per_ip_cap {
            return Admit::IpFull;
        }
        *count += 1;
        inner.total += 1;
        Admit::Ok
    }

    fn release(&self, ip: IpAddr) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = inner.per_ip.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                inner.per_ip.remove(&ip);
            }
        }
        inner.total = inner.total.saturating_sub(1);
    }
}

#[derive(Default)]
struct RateLimiter {
    inner: Mutex<RateInner>,
}

#[derive(Default)]
struct RateInner {
    window_start: Option<Instant>,
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl RateLimiter {
    fn allow(
        &self,
        ip: IpAddr,
        now: Instant,
        window: Duration,
        total_cap: usize,
        per_ip_cap: usize,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = inner
            .window_start
            .map(|start| now.saturating_duration_since(start) >= window)
            .unwrap_or(true);
        if elapsed {
            inner.window_start = Some(now);
            inner.total = 0;
            inner.per_ip.clear();
        }
        if inner.total >= total_cap {
            return false;
        }
        let count = inner.per_ip.entry(ip).or_insert(0);
        if *count >= per_ip_cap {
            return false;
        }
        *count += 1;
        inner.total += 1;
        true
    }
}

pub fn serve(listener: TcpListener, state: SharedState, store: Option<Arc<GuardStore>>) {
    thread::spawn(move || {
        let limiter = Arc::new(Limiter::default());
        let rate = RateLimiter::default();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let ip = stream
                .peer_addr()
                .map(|addr| addr.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            if !rate.allow(
                ip,
                Instant::now(),
                RATE_WINDOW,
                MAX_ADMITS_PER_WINDOW,
                MAX_ADMITS_PER_IP_PER_WINDOW,
            ) {
                stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                let _ = write_error(&mut stream, 429, "rate_limited", "too many requests, slow down");
                continue;
            }
            match limiter.try_admit(ip, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP) {
                Admit::Ok => {}
                Admit::TotalFull => {
                    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                    let _ = write_error(&mut stream, 503, "busy", "the oracle is at its connection limit");
                    continue;
                }
                Admit::IpFull => {
                    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                    let _ = write_error(
                        &mut stream,
                        429,
                        "too_many",
                        "too many open connections from this address",
                    );
                    continue;
                }
            }
            let state = state.clone();
            let limiter = limiter.clone();
            let store = store.clone();
            thread::spawn(move || {
                let _slot = SlotGuard { limiter, ip };
                let _ = handle_connection(stream, state, store);
            });
        }
    });
}

struct SlotGuard {
    limiter: Arc<Limiter>,
    ip: IpAddr,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    state: SharedState,
    store: Option<Arc<GuardStore>>,
) -> IoResult<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut head_budget = MAX_HEAD;
    let request_line = match read_capped_line(&mut reader, &mut head_budget, deadline) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()),
        Err(e) => return head_read_error(&mut stream, &e),
    };
    let mut parts = request_line.split_whitespace();
    let verb = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let header = match read_capped_line(&mut reader, &mut head_budget, deadline) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(e) => return head_read_error(&mut stream, &e),
        };
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = header_value(trimmed, "content-length") {
            content_length = value.parse().unwrap_or(0);
        }
    }

    if verb.eq_ignore_ascii_case("OPTIONS") {
        return write_response(&mut stream, 204, "");
    }
    if !verb.eq_ignore_ascii_case("POST") {
        return write_error(&mut stream, 405, "method_not_allowed", "the RPC accepts POST");
    }
    if content_length > MAX_BODY {
        return write_error(&mut stream, 413, "too_large", "the request body is too large");
    }

    // Grow the buffer only as bytes actually arrive rather than pre-sizing to the declared
    // Content-Length, so a tiny request cannot force a full MAX_BODY zeroed allocation it never
    // fills. The initial capacity is capped, and the loop still stops at content_length.
    let mut body = Vec::with_capacity(content_length.min(64 * 1024));
    let mut chunk = [0u8; 8192];
    while body.len() < content_length {
        let now = Instant::now();
        if now >= deadline {
            return write_error(&mut stream, 408, "timeout", "the request exceeded its time budget");
        }
        let remaining = deadline
            .saturating_duration_since(now)
            .min(IO_TIMEOUT)
            .max(Duration::from_millis(1));
        stream.set_read_timeout(Some(remaining)).ok();
        let want = (content_length - body.len()).min(chunk.len());
        match reader.read(&mut chunk[..want]) {
            Ok(0) => return Ok(()),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(ref e) if is_timeout(e) => {
                return write_error(&mut stream, 408, "timeout", "the request exceeded its time budget")
            }
            Err(e) => return Err(e),
        }
    }
    let Ok(body_text) = std::str::from_utf8(&body) else {
        return write_error(&mut stream, 400, "bad_request", "the request body is not valid UTF-8");
    };

    let Some(method) = path.strip_prefix("/v1/") else {
        return write_error(&mut stream, 404, "unknown_method", "methods live under /v1/");
    };

    if method == "health" {
        let revision = {
            let guard = state.read().unwrap_or_else(|e| e.into_inner());
            guard.gateway.guard_revision()
        };
        let body = object(vec![
            ("status", Json::str("ok")),
            ("revision", Json::Int(revision)),
        ])
        .render();
        return write_response(&mut stream, 200, &body);
    }

    if method == "create_pool" {
        return write_error(
            &mut stream,
            403,
            "not_permitted",
            "pool creation is not exposed over the public API; the asset registry is provisioned at boot",
        );
    }

    let parsed = if body_text.trim().is_empty() {
        Json::Object(Vec::new())
    } else {
        match json::parse(body_text) {
            Ok(value) => value,
            Err(e) => {
                return write_error(&mut stream, 400, "bad_request", &format!("the body is not JSON, {e}"))
            }
        }
    };

    let request = match decode_request(method, &parsed) {
        Ok(request) => request,
        Err(err) => {
            let (code, error, message) = err.http();
            return write_error(&mut stream, code, error, &message);
        }
    };

    let response = match route(&state, store.as_deref(), request) {
        Ok(response) => response,
        Err(RouteFail::Panicked) => {
            return write_error(&mut stream, 500, "internal_error", "the request handler failed")
        }
        Err(RouteFail::PersistFailed) => {
            return write_error(
                &mut stream,
                500,
                "internal_error",
                "the admission could not be persisted",
            )
        }
    };
    write_response(&mut stream, 200, &encode_response(&response).render())
}

enum RouteFail {
    Panicked,
    PersistFailed,
}

fn persist_if_advanced(
    guard: &BridgeState,
    store: Option<&GuardStore>,
    rev_before: u64,
) -> Result<(), RouteFail> {
    if guard.gateway.guard_revision() != rev_before {
        if let Some(store) = store {
            if store.save(&guard.gateway.encode_guard()).is_err() {
                return Err(RouteFail::PersistFailed);
            }
        }
    }
    Ok(())
}

fn route(
    state: &SharedState,
    store: Option<&GuardStore>,
    request: Request,
) -> Result<Response, RouteFail> {
    {
        let guard = state.read().unwrap_or_else(|e| e.into_inner());
        if let Some(response) = handle_read(&guard, &request) {
            return Ok(response);
        }
    }
    match request {
        Request::SubmitDeposit(deposit) => {
            let verified = {
                let guard = state.read().unwrap_or_else(|e| e.into_inner());
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    verify_deposit(&guard, &deposit)
                }))
                .map_err(|_| RouteFail::Panicked)?
            };
            let plan = match verified {
                Ok(plan) => plan,
                Err(err) => return Ok(Response::Error(err)),
            };
            let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
            let rev_before = guard.gateway.guard_revision();
            let snapshot = guard.gateway.encode_guard();
            let committed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                commit_deposit(&mut guard, plan)
            }))
            .map_err(|_| RouteFail::Panicked)?;
            match committed {
                Ok(outcome) => match persist_or_rollback(&mut guard, store, rev_before, &snapshot) {
                    Durability::PersistFailed => Err(RouteFail::PersistFailed),
                    _ => Ok(Response::DepositAdmitted(outcome)),
                },
                Err(err) => Ok(Response::Error(err)),
            }
        }
        other => {
            let mut guard = state.write().unwrap_or_else(|e| e.into_inner());
            let rev_before = guard.gateway.guard_revision();
            let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle(&mut guard, other)
            }))
            .map_err(|_| RouteFail::Panicked)?;
            persist_if_advanced(&guard, store, rev_before)?;
            Ok(response)
        }
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn head_read_error(stream: &mut TcpStream, e: &std::io::Error) -> IoResult<()> {
    if is_timeout(e) {
        write_error(stream, 408, "timeout", "the request exceeded its time budget")
    } else {
        write_error(stream, 431, "head_too_large", "the request head is too large")
    }
}

fn read_capped_line<R: BufRead>(
    reader: &mut R,
    budget: &mut usize,
    deadline: Instant,
) -> IoResult<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request exceeded its time budget",
            ));
        }
        if reader.read(&mut byte)? == 0 {
            return Ok(if line.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&line).into_owned())
            });
        }
        if *budget == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the request head exceeded its budget",
            ));
        }
        *budget -= 1;
        if byte[0] == b'\n' {
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        line.push(byte[0]);
    }
}

fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    if key.trim().eq_ignore_ascii_case(name) {
        Some(value.trim())
    } else {
        None
    }
}

fn write_error(stream: &mut TcpStream, code: u16, error: &str, message: &str) -> IoResult<()> {
    let body = object(vec![
        ("error", Json::str(error)),
        ("message", Json::str(message)),
    ])
    .render();
    write_response(stream, code, &body)
}

fn write_response(stream: &mut TcpStream, code: u16, body: &str) -> IoResult<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        reason = reason(code),
        len = body.len(),
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_ID: u64 = 0x0000_002a_0000_2328;
    use q_gateway::{Gateway, OperatorSet};
    use std::io::Cursor;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn the_limiter_caps_connections_per_address_and_frees_them_on_release() {
        let limiter = Limiter::default();
        let peer = ip(7);
        for _ in 0..3 {
            assert!(matches!(limiter.try_admit(peer, 100, 3), Admit::Ok));
        }
        assert!(
            matches!(limiter.try_admit(peer, 100, 3), Admit::IpFull),
            "the fourth connection from one address is refused"
        );
        limiter.release(peer);
        assert!(
            matches!(limiter.try_admit(peer, 100, 3), Admit::Ok),
            "a released slot is reusable"
        );
    }

    #[test]
    fn the_rate_limiter_caps_admissions_per_window_and_reopens_after_it() {
        let rate = RateLimiter::default();
        let window = Duration::from_secs(1);
        let t0 = Instant::now();
        let peer = ip(5);
        for _ in 0..3 {
            assert!(rate.allow(peer, t0, window, 100, 3));
        }
        assert!(
            !rate.allow(peer, t0, window, 100, 3),
            "a fourth admit inside the window is refused"
        );
        assert!(
            rate.allow(ip(6), t0, window, 100, 3),
            "a different address still admits inside the global cap"
        );
        let t1 = t0 + window;
        assert!(
            rate.allow(peer, t1, window, 100, 3),
            "a fresh window reopens the per address allowance"
        );
    }

    #[test]
    fn the_rate_limiter_caps_the_global_admissions_per_window() {
        let rate = RateLimiter::default();
        let window = Duration::from_secs(1);
        let t0 = Instant::now();
        assert!(rate.allow(ip(1), t0, window, 2, 10));
        assert!(rate.allow(ip(2), t0, window, 2, 10));
        assert!(
            !rate.allow(ip(3), t0, window, 2, 10),
            "the global window cap holds even with per address room left"
        );
    }

    #[test]
    fn the_limiter_caps_the_total_across_addresses() {
        let limiter = Limiter::default();
        assert!(matches!(limiter.try_admit(ip(1), 2, 10), Admit::Ok));
        assert!(matches!(limiter.try_admit(ip(2), 2, 10), Admit::Ok));
        assert!(
            matches!(limiter.try_admit(ip(3), 2, 10), Admit::TotalFull),
            "the global cap holds even with per address room left"
        );
        limiter.release(ip(1));
        assert!(matches!(limiter.try_admit(ip(3), 2, 10), Admit::Ok));
    }

    #[test]
    fn a_capped_line_reads_a_normal_line_and_draws_down_the_budget() {
        let raw = b"POST /v1/list_pools HTTP/1.1\r\n".to_vec();
        let spent = raw.len();
        let mut reader = Cursor::new(raw);
        let mut budget = MAX_HEAD;
        let far = Instant::now() + Duration::from_secs(3600);
        let line = read_capped_line(&mut reader, &mut budget, far).unwrap().unwrap();
        assert_eq!(line, "POST /v1/list_pools HTTP/1.1\r");
        assert_eq!(budget, MAX_HEAD - spent, "every byte read draws down the budget");
    }

    #[test]
    fn a_capped_line_refuses_a_line_that_exhausts_the_budget() {
        let mut reader = Cursor::new(vec![b'a'; 100]);
        let mut budget = 16usize;
        let far = Instant::now() + Duration::from_secs(3600);
        assert!(
            read_capped_line(&mut reader, &mut budget, far).is_err(),
            "an endless line is refused once the budget is spent"
        );
    }

    #[test]
    fn a_read_past_its_deadline_is_aborted() {
        let mut reader = Cursor::new(b"POST /v1/list_pools HTTP/1.1\r\n".to_vec());
        let mut budget = MAX_HEAD;
        let deadline = Instant::now();
        let err = read_capped_line(&mut reader, &mut budget, deadline).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "a request that overruns its wall clock budget is aborted"
        );
    }

    fn serve_seeded() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let gateway = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000_000);
        let state: SharedState = Arc::new(RwLock::new(BridgeState::seeded(gateway)));
        serve(listener, state, None);
        port
    }

    fn round_trip(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).ok();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn a_well_formed_post_is_routed_and_answered_over_the_socket() {
        let port = serve_seeded();
        let response = round_trip(
            port,
            "POST /v1/list_pools HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"result\":\"pools\""), "{response}");
    }

    #[test]
    fn a_health_probe_returns_ok_over_the_socket() {
        let port = serve_seeded();
        let response = round_trip(
            port,
            "POST /v1/health HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"status\":\"ok\""), "{response}");
        assert!(response.contains("\"revision\""), "{response}");
    }

    #[test]
    fn create_pool_is_refused_over_the_public_socket() {
        let port = serve_seeded();
        let body = "{\"network_id\":1,\"identifier\":\"EVIL\",\"decimals\":18,\"per_asset_cap\":\"1\",\"per_epoch_cap\":\"1\"}";
        let response = round_trip(
            port,
            &format!(
                "POST /v1/create_pool HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            ),
        );
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("\"error\":\"not_permitted\""), "{response}");
    }

    #[test]
    fn an_oversized_head_is_refused_over_the_socket() {
        let port = serve_seeded();
        let giant = "x".repeat(MAX_HEAD + 1024);
        let response = round_trip(port, &format!("POST /v1/list_pools HTTP/1.1\r\nBig: {giant}\r\n\r\n"));
        assert!(response.starts_with("HTTP/1.1 431"), "{response}");
    }

    #[test]
    fn an_oversized_body_is_refused_over_the_socket() {
        let port = serve_seeded();
        let response = round_trip(
            port,
            &format!("POST /v1/list_pools HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1),
        );
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    }

    #[test]
    fn an_unknown_method_path_is_a_not_found_over_the_socket() {
        let port = serve_seeded();
        let response = round_trip(port, "POST /v1/does_not_exist HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}");
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[test]
    fn a_non_post_verb_is_refused_over_the_socket() {
        let port = serve_seeded();
        let response = round_trip(port, "GET /v1/list_pools HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 405"), "{response}");
    }

    #[test]
    fn a_poisoned_state_lock_still_serves_the_next_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let gateway = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000_000);
        let state: SharedState = Arc::new(RwLock::new(BridgeState::seeded(gateway)));

        let poisoner = state.clone();
        let _ = thread::spawn(move || {
            let _held = poisoner.write().unwrap();
            panic!("poison the bridge state lock");
        })
        .join();

        serve(listener, state, None);
        let response = round_trip(
            port,
            "POST /v1/list_pools HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "a recovered lock still answers, got {response}"
        );
    }

    #[test]
    fn a_panicking_connection_thread_releases_its_slot() {
        let limiter = Arc::new(Limiter::default());
        let peer = ip(9);
        assert!(matches!(limiter.try_admit(peer, 100, 1), Admit::Ok));
        let held = limiter.clone();
        let _ = thread::spawn(move || {
            let _slot = SlotGuard { limiter: held, ip: peer };
            panic!("the connection handler unwound");
        })
        .join();
        assert!(
            matches!(limiter.try_admit(peer, 100, 1), Admit::Ok),
            "the per address slot is freed when the thread unwinds"
        );
    }
}
