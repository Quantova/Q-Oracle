// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_runtime::json;
use q_runtime::wire::decode_request;

const METHODS: &[&str] = &[
    "create_pool",
    "pools",
    "pool",
    "submit_deposit",
    "request_exit",
    "finalize_exit",
    "freeze",
    "resume",
    "status",
    "not_a_method",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn the_json_parser_never_panics_on_arbitrary_text() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let alphabet: Vec<char> = "{}[]\",:0123456789.eE+-truefalsnul \\/\u{80}\u{7ff}\u{10000}"
        .chars()
        .collect();
    for _ in 0..200_000u64 {
        let len = (rng.next() % 96) as usize;
        let text: String = (0..len)
            .map(|_| alphabet[(rng.next() as usize) % alphabet.len()])
            .collect();
        let _ = json::parse(&text);
    }
}

#[test]
fn a_deeply_nested_body_is_refused_rather_than_overflowing_the_stack() {
    for depth in [63usize, 64, 65, 500, 20_000] {
        let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let parsed = json::parse(&text);
        if depth > 64 {
            assert!(
                parsed.is_err(),
                "a body nested {depth} deep must be refused, a recursive descent parser that \
                 accepts it can be driven to a stack overflow by one request"
            );
        }
    }
}

#[test]
fn an_unbalanced_or_truncated_body_is_refused_not_accepted() {
    for text in ["[", "{", "{\"a\":", "[1,", "\"unterminated", "{\"a\":1}}", "[]]"] {
        assert!(
            json::parse(text).is_err(),
            "the parser accepted malformed input: {text}"
        );
    }
}

#[test]
fn the_wire_accepts_only_whole_unsigned_numbers() {
    assert!(json::parse("{\"network_id\":1}").is_ok());
    assert!(
        json::parse("{\"network_id\":-1}").is_err(),
        "the wire carries no negative number, so the parser must refuse one rather than wrap it"
    );
    assert!(
        json::parse("{\"network_id\":1.5}").is_err(),
        "the wire carries no fractional number"
    );
    assert!(json::parse("{\"network_id\":18446744073709551615}").is_ok());
    assert!(
        json::parse("{\"network_id\":18446744073709551616}").is_err(),
        "a number past u64 must be refused, not truncated"
    );
}

#[test]
fn every_method_survives_an_arbitrary_parsed_body() {
    let mut rng = Rng(0x2545F4914F6CDD1D);
    let bodies = [
        "{}",
        "[]",
        "null",
        "0",
        "\"\"",
        "{\"network_id\":true}",
        "{\"network_id\":-1}",
        "{\"identifier\":[]}",
        "{\"amount\":\"not a number\"}",
        "{\"network_id\":18446744073709551615}",
    ];
    for _ in 0..20_000u64 {
        let method = METHODS[(rng.next() as usize) % METHODS.len()];
        let body = bodies[(rng.next() as usize) % bodies.len()];
        let Ok(parsed) = json::parse(body) else {
            continue;
        };
        let _ = decode_request(method, &parsed);
    }
}
