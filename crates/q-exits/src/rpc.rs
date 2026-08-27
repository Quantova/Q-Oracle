// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use qtv_attest::{Attestation, Block, Certificate, Envelope, Parent};
use qtv_codec::Decoder;
use qtv_crypto::ml_dsa::{Signature, SIGNATURE_BYTES};
use qtv_sampler::onetime::{MerklePath, NODE_BYTES, PREIMAGE_BYTES};
use qtv_sampler::sortition::Credential;

use crate::watch::{BurnWatchError, FinalizedBlock, QuantovaBurnSource};

const PARENT_GENESIS: u8 = 0;
const PARENT_VALUE: u8 = 1;
const STAGE_ONE: u8 = 1;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

pub struct RpcBurnSource {
    host: String,
    port: u16,
    timeout: Duration,
}

impl RpcBurnSource {
    pub fn new(host: impl Into<String>, port: u16) -> RpcBurnSource {
        RpcBurnSource {
            host: host.into(),
            port,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(host: impl Into<String>, port: u16, timeout: Duration) -> RpcBurnSource {
        RpcBurnSource {
            host: host.into(),
            port,
            timeout,
        }
    }

    pub fn burn_heights_after(&self, cursor: u64) -> Result<Vec<u64>, BurnWatchError> {
        let body = format!("{{\"cursor\":{cursor}}}");
        let (status, text) = self.request("burn_heights_after", &body)?;
        if status != 200 {
            return Err(BurnWatchError::Rpc(format!(
                "burn_heights_after returned status {status}"
            )));
        }
        decode_heights_after(&text)
    }

    fn request(&self, method: &str, body: &str) -> Result<(u16, String), BurnWatchError> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(io_err)?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();
        let head = format!(
            "POST /v1/{method} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.host,
            body.len()
        );
        stream.write_all(head.as_bytes()).map_err(io_err)?;
        stream.write_all(body.as_bytes()).map_err(io_err)?;
        stream.flush().ok();

        let deadline = Instant::now() + self.timeout;
        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            if Instant::now() >= deadline {
                return Err(BurnWatchError::Rpc("the response timed out".to_string()));
            }
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if raw.len() + n > MAX_RESPONSE {
                        return Err(BurnWatchError::Rpc("the response exceeds the cap".to_string()));
                    }
                    raw.extend_from_slice(&buf[..n]);
                }
                Err(err) => return Err(io_err(err)),
            }
        }
        split_response(&raw)
    }
}

impl QuantovaBurnSource for RpcBurnSource {
    fn finalized_height(&self) -> Result<u64, BurnWatchError> {
        let (status, text) = self.request("finalized_head", "{}")?;
        if status != 200 {
            return Err(BurnWatchError::Rpc(format!(
                "finalized_head returned status {status}"
            )));
        }
        decode_finalized_head(&text)
    }

    fn finalized_block(&self, height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError> {
        let body = format!("{{\"height\":{height}}}");
        let (status, text) = self.request("burn_block", &body)?;
        match status {
            200 => decode_finalized_block(&text).map(Some),
            404 => Ok(None),
            other => Err(BurnWatchError::Rpc(format!(
                "burn_block returned status {other}"
            ))),
        }
    }
}

pub fn decode_finalized_head(body: &str) -> Result<u64, BurnWatchError> {
    let value = parse_json(body)?;
    value
        .get("head")
        .and_then(Json::as_u64)
        .ok_or_else(|| BurnWatchError::Rpc("finalized_head has no head field".to_string()))
}

pub fn decode_heights_after(body: &str) -> Result<Vec<u64>, BurnWatchError> {
    let value = parse_json(body)?;
    let items = value
        .get("heights")
        .and_then(Json::as_array)
        .ok_or_else(|| BurnWatchError::Rpc("burn_heights_after has no heights field".to_string()))?;
    let mut heights = Vec::with_capacity(items.len());
    for item in items {
        heights.push(
            item.as_u64()
                .ok_or_else(|| BurnWatchError::Rpc("a height is not a whole number".to_string()))?,
        );
    }
    Ok(heights)
}

pub fn decode_finalized_block(body: &str) -> Result<FinalizedBlock, BurnWatchError> {
    let value = parse_json(body)?;
    let header_hex = value
        .get("header_bytes")
        .and_then(Json::as_str)
        .ok_or_else(|| BurnWatchError::Rpc("burn_block has no header_bytes field".to_string()))?;
    let header_bytes = decode_hex(header_hex)?;

    let cert_hex = value
        .get("certificate")
        .and_then(Json::as_str)
        .ok_or_else(|| BurnWatchError::Rpc("burn_block has no certificate field".to_string()))?;
    let certificate = decode_certificate(&decode_hex(cert_hex)?)?;

    let leaves = value
        .get("events")
        .and_then(Json::as_array)
        .ok_or_else(|| BurnWatchError::Rpc("burn_block has no events field".to_string()))?;
    let mut events = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let hex = leaf
            .as_str()
            .ok_or_else(|| BurnWatchError::Rpc("an event leaf is not a hex string".to_string()))?;
        events.push(decode_hex(hex)?);
    }

    Ok(FinalizedBlock {
        header_bytes,
        certificate,
        events,
    })
}

fn decode_certificate(bytes: &[u8]) -> Result<Certificate, BurnWatchError> {
    let mut decoder = Decoder::new(bytes);
    let envelope = decode_envelope(&mut decoder)?;
    let certificate = match decoder.get_u8().map_err(codec_err)? {
        STAGE_ONE => {
            let count = decoder.get_u64().map_err(codec_err)?;
            let mut attestations = Vec::new();
            for _ in 0..count {
                attestations.push(decode_attestation(&mut decoder)?);
            }
            Certificate::new(envelope, attestations)
        }
        stage => return Err(BurnWatchError::Rpc(format!("unknown certificate stage {stage}"))),
    };
    decoder.finish().map_err(codec_err)?;
    Ok(certificate)
}

fn decode_envelope(decoder: &mut Decoder<'_>) -> Result<Envelope, BurnWatchError> {
    let height = decoder.get_u64().map_err(codec_err)?;
    let slot = decoder.get_u64().map_err(codec_err)?;
    let block = decode_block(decoder)?;
    let committee: [u8; 32] = read_array(decoder)?;
    Ok(Envelope {
        height,
        slot,
        block,
        committee,
    })
}

fn decode_block(decoder: &mut Decoder<'_>) -> Result<Block, BurnWatchError> {
    let height = decoder.get_u64().map_err(codec_err)?;
    let val = read_value(decoder)?;
    let parent_tag = decoder.get_u8().map_err(codec_err)?;
    let parent_value = read_value(decoder)?;
    let parent = match parent_tag {
        PARENT_GENESIS => Parent::Genesis,
        PARENT_VALUE => Parent::Value(parent_value),
        other => return Err(BurnWatchError::Rpc(format!("unknown parent tag {other}"))),
    };
    let cost = decoder.get_u64().map_err(codec_err)?;
    Ok(Block {
        height,
        val,
        parent,
        cost,
    })
}

fn decode_attestation(decoder: &mut Decoder<'_>) -> Result<Attestation, BurnWatchError> {
    let from = decoder.get_u64().map_err(codec_err)?;
    let height = decoder.get_u64().map_err(codec_err)?;
    let slot = decoder.get_u64().map_err(codec_err)?;
    let view = decoder.get_u64().map_err(codec_err)?;
    let committee: [u8; 32] = read_array(decoder)?;
    let block = decode_block(decoder)?;
    let membership = decode_credential(decoder)?;
    let sig: Signature = read_array::<SIGNATURE_BYTES>(decoder)?;
    Ok(Attestation {
        from,
        height,
        slot,
        view,
        committee,
        block,
        membership,
        sig,
    })
}

fn decode_credential(decoder: &mut Decoder<'_>) -> Result<Credential, BurnWatchError> {
    let position = decoder.get_u64().map_err(codec_err)?;
    let preimage: [u8; PREIMAGE_BYTES] = read_array(decoder)?;
    let count = decoder.get_u64().map_err(codec_err)?;
    let mut siblings = Vec::new();
    for _ in 0..count {
        let sibling: [u8; NODE_BYTES] = read_array(decoder)?;
        siblings.push(sibling);
    }
    Ok(Credential {
        position,
        preimage,
        path: MerklePath { siblings },
    })
}

fn read_array<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], BurnWatchError> {
    let bytes = decoder.get_bytes().map_err(codec_err)?;
    bytes
        .try_into()
        .map_err(|_| BurnWatchError::Rpc("a fixed field has the wrong length".to_string()))
}

fn read_value(decoder: &mut Decoder<'_>) -> Result<[u8; 32], BurnWatchError> {
    let mut value = [0u8; 32];
    for slot in value.iter_mut() {
        *slot = decoder.get_u8().map_err(codec_err)?;
    }
    Ok(value)
}

fn codec_err(_: qtv_codec::Error) -> BurnWatchError {
    BurnWatchError::Rpc("the certificate bytes are malformed".to_string())
}

fn io_err(err: std::io::Error) -> BurnWatchError {
    BurnWatchError::Rpc(format!("the chain rpc is unreachable, {err}"))
}

fn split_response(raw: &[u8]) -> Result<(u16, String), BurnWatchError> {
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| BurnWatchError::Rpc("the response has no header terminator".to_string()))?;
    let head = &raw[..separator];
    let body = &raw[separator + 4..];
    let first_line = head
        .split(|&b| b == b'\n')
        .next()
        .ok_or_else(|| BurnWatchError::Rpc("the response has no status line".to_string()))?;
    let line = String::from_utf8_lossy(first_line);
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| BurnWatchError::Rpc("the response has no status code".to_string()))?;
    Ok((status, String::from_utf8_lossy(body).into_owned()))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, BurnWatchError> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err(BurnWatchError::Rpc("hex has an odd length".to_string()));
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
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, BurnWatchError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(BurnWatchError::Rpc("a byte is not a hex digit".to_string())),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(n) => Some(*n),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 64;

fn parse_json(input: &str) -> Result<Json, BurnWatchError> {
    let mut parser = JsonParser {
        chars: input.chars().collect(),
        pos: 0,
        depth: 0,
    };
    parser.skip_ws();
    let value = parser.value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return Err(BurnWatchError::Rpc("trailing bytes after the json value".to_string()));
    }
    Ok(value)
}

struct JsonParser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl JsonParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Json, BurnWatchError> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.nested(Self::object),
            Some('[') => self.nested(Self::array),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') | Some('f') => self.boolean(),
            Some('n') => self.null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            _ => Err(BurnWatchError::Rpc("expected a json value".to_string())),
        }
    }

    fn nested(
        &mut self,
        parse_container: fn(&mut Self) -> Result<Json, BurnWatchError>,
    ) -> Result<Json, BurnWatchError> {
        if self.depth >= MAX_DEPTH {
            return Err(BurnWatchError::Rpc("the json nests too deep".to_string()));
        }
        self.depth += 1;
        let result = parse_container(self);
        self.depth -= 1;
        result
    }

    fn object(&mut self) -> Result<Json, BurnWatchError> {
        self.next();
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.next();
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(BurnWatchError::Rpc("expected a string key".to_string()));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.next() != Some(':') {
                return Err(BurnWatchError::Rpc("expected a colon after a key".to_string()));
            }
            let value = self.value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err(BurnWatchError::Rpc("expected a comma or a brace".to_string())),
            }
        }
        Ok(Json::Object(fields))
    }

    fn array(&mut self) -> Result<Json, BurnWatchError> {
        self.next();
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.next();
            return Ok(Json::Array(items));
        }
        loop {
            let value = self.value()?;
            items.push(value);
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err(BurnWatchError::Rpc("expected a comma or a bracket".to_string())),
            }
        }
        Ok(Json::Array(items))
    }

    fn string(&mut self) -> Result<String, BurnWatchError> {
        self.next();
        let mut s = String::new();
        loop {
            match self.next() {
                Some('"') => return Ok(s),
                Some('\\') => match self.next() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('b') => s.push('\u{0008}'),
                    Some('f') => s.push('\u{000c}'),
                    Some('u') => s.push(self.unicode_escape()?),
                    _ => return Err(BurnWatchError::Rpc("bad escape in a string".to_string())),
                },
                Some(c) => s.push(c),
                None => return Err(BurnWatchError::Rpc("a string was not closed".to_string())),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, BurnWatchError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let digit = self
                .next()
                .and_then(|c| c.to_digit(16))
                .ok_or_else(|| BurnWatchError::Rpc("bad unicode escape".to_string()))?;
            code = code * 16 + digit;
        }
        char::from_u32(code).ok_or_else(|| BurnWatchError::Rpc("bad code point".to_string()))
    }

    fn number(&mut self) -> Result<Json, BurnWatchError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.next();
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.next();
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<u64>()
            .map(Json::Int)
            .map_err(|_| BurnWatchError::Rpc("a number is not a whole number the wire accepts".to_string()))
    }

    fn boolean(&mut self) -> Result<Json, BurnWatchError> {
        if self.literal("true") {
            Ok(Json::Bool(true))
        } else if self.literal("false") {
            Ok(Json::Bool(false))
        } else {
            Err(BurnWatchError::Rpc("expected true or false".to_string()))
        }
    }

    fn null(&mut self) -> Result<Json, BurnWatchError> {
        if self.literal("null") {
            Ok(Json::Null)
        } else {
            Err(BurnWatchError::Rpc("expected null".to_string()))
        }
    }

    fn literal(&mut self, word: &str) -> bool {
        let end = self.pos + word.len();
        if end <= self.chars.len() && self.chars[self.pos..end].iter().collect::<String>() == word {
            self.pos = end;
            true
        } else {
            false
        }
    }
}
