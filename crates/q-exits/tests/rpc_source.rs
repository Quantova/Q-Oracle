// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use q_exits::{
    decode_finalized_block, BurnWatchError, BurnWatcher, FinalizedBlock, MemberConfig,
    QuantovaAnchor, QuantovaBurnSource, RpcBurnSource,
};

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attestation, Attester, Block, Certificate, Envelope, Parent};
use qtv_block::{event_root, Header};
use qtv_codec::{to_bytes, Encoder};
use qtv_sampler::beacon::Beacon;

const CHAIN_ID: u64 = 9000;
const HEIGHT: u64 = 4_200_000;
const SLOT: u64 = 0;
const BUDGET: u64 = 300;
const TAU: u64 = 3;
const ASSET: [u8; 16] = [0xa1; 16];
const HOLDER: [u8; 32] = [0x33; 32];
const BENEFICIARY: [u8; 32] = [0x55; 32];
const AMOUNT: u128 = 500;
const BURN_REF: [u8; 32] = [0x11; 32];

const STAGE_ONE: u8 = 1;
const PARENT_GENESIS: u8 = 0;
const PARENT_VALUE: u8 = 1;

fn attesters() -> [Attester; 3] {
    [Attester::new(1, 100), Attester::new(2, 100), Attester::new(3, 100)]
}

fn committee(members: &[Attester]) -> qtv_attest::CommitteeCommitment {
    let refs: Vec<&Attester> = members.iter().collect();
    qtv_attest::CommitteeCommitment::from_attesters_with_budget(SLOT, &refs, BUDGET)
}

fn member_configs(members: &[Attester]) -> Vec<MemberConfig> {
    members
        .iter()
        .map(|a| MemberConfig {
            id: a.id(),
            weight: a.weight(),
            root_digest: a.root().digest,
            root_slots: a.root().slots,
            attest_pk: a.attest_public_key().to_vec(),
        })
        .collect()
}

fn burn_leaf() -> Vec<u8> {
    let mut data = Encoder::new();
    data.put_bytes(&ASSET);
    data.put_bytes(&HOLDER);
    data.put_u128(AMOUNT);
    data.put_bytes(&BENEFICIARY);
    data.put_u64(CHAIN_ID);
    data.put_u64(0);
    data.put_u64(1);
    data.put_bytes(&BURN_REF);

    let mut leaf = Encoder::new();
    leaf.put_bytes(b"qtv/native");
    leaf.put_bytes(b"QBBN");
    leaf.put_bytes(&data.into_bytes());
    leaf.into_bytes()
}

fn leaves() -> Vec<Vec<u8>> {
    vec![vec![0xde; 8], burn_leaf(), vec![0xad; 12]]
}

fn header_at(height: u64, leaves: &[Vec<u8>]) -> Header {
    Header::new(
        height,
        [0u8; 32],
        [0x01; 32],
        [0u8; 32],
        event_root(leaves),
        [0u8; 32],
        "qtv1proposer".to_string(),
        1,
    )
}

fn finalized_certificate(members: &[Attester], height: u64, block: Block, beacon: &Beacon) -> Certificate {
    let commitment = committee(members);
    let atts: Vec<_> = members
        .iter()
        .map(|a| a.attest(CHAIN_ID, height, SLOT, 0, commitment.digest(), block, beacon))
        .collect();
    aggregate(CHAIN_ID, height, SLOT, block, &commitment, beacon, &atts, TAU)
        .expect("a full committee finalizes")
}

fn anchor(members: &[Attester], beacon: &Beacon) -> QuantovaAnchor {
    QuantovaAnchor::from_config(CHAIN_ID, TAU, SLOT, BUDGET, *beacon.seed(), member_configs(members))
        .expect("the pinned anchor is well formed")
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn encode_block(encoder: &mut Encoder, block: &Block) {
    encoder.put_u64(block.height);
    for &byte in &block.val {
        encoder.put_u8(byte);
    }
    match block.parent {
        Parent::Genesis => {
            encoder.put_u8(PARENT_GENESIS);
            for _ in 0..32 {
                encoder.put_u8(0);
            }
        }
        Parent::Value(value) => {
            encoder.put_u8(PARENT_VALUE);
            for &byte in &value {
                encoder.put_u8(byte);
            }
        }
    }
    encoder.put_u64(block.cost);
}

fn encode_credential(encoder: &mut Encoder, credential: &qtv_sampler::sortition::Credential) {
    encoder.put_u64(credential.position);
    encoder.put_bytes(&credential.preimage);
    encoder.put_u64(credential.path.siblings.len() as u64);
    for sibling in &credential.path.siblings {
        encoder.put_bytes(sibling);
    }
}

fn encode_attestation(encoder: &mut Encoder, attestation: &Attestation) {
    encoder.put_u64(attestation.from);
    encoder.put_u64(attestation.height);
    encoder.put_u64(attestation.slot);
    encoder.put_u64(attestation.view);
    encoder.put_bytes(&attestation.committee);
    encode_block(encoder, &attestation.block);
    encode_credential(encoder, &attestation.membership);
    encoder.put_bytes(&attestation.sig);
}

fn encode_envelope(encoder: &mut Encoder, envelope: &Envelope) {
    encoder.put_u64(envelope.height);
    encoder.put_u64(envelope.slot);
    encode_block(encoder, &envelope.block);
    encoder.put_bytes(&envelope.committee);
}

fn certificate_to_bytes(certificate: &Certificate) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encode_envelope(&mut encoder, &certificate.envelope);
    encoder.put_u8(STAGE_ONE);
    encoder.put_u64(certificate.attestations.len() as u64);
    for attestation in &certificate.attestations {
        encode_attestation(&mut encoder, attestation);
    }
    encoder.into_bytes()
}

fn burn_block_json(height: u64, header_bytes: &[u8], cert_bytes: &[u8], leaves: &[Vec<u8>]) -> String {
    let events: Vec<String> = leaves.iter().map(|leaf| format!("\"{}\"", to_hex(leaf))).collect();
    format!(
        "{{\"height\":{height},\"header_bytes\":\"{}\",\"certificate\":\"{}\",\"events\":[{}]}}",
        to_hex(header_bytes),
        to_hex(cert_bytes),
        events.join(",")
    )
}

fn material() -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, [Attester; 3], Beacon) {
    let members = attesters();
    let beacon = Beacon::genesis();
    let leaves = leaves();
    let header = header_at(HEIGHT, &leaves);
    let block = Block::new(HEIGHT, header.hash(), Parent::Genesis);
    let certificate = finalized_certificate(&members, HEIGHT, block, &beacon);
    (to_bytes(&header), certificate_to_bytes(&certificate), leaves, members, beacon)
}

fn clone_block(block: &FinalizedBlock) -> FinalizedBlock {
    FinalizedBlock {
        header_bytes: block.header_bytes.clone(),
        certificate: block.certificate.clone(),
        events: block.events.clone(),
    }
}

struct OneBlock {
    head: u64,
    block: FinalizedBlock,
}

impl QuantovaBurnSource for OneBlock {
    fn finalized_height(&self) -> Result<u64, BurnWatchError> {
        Ok(self.head)
    }

    fn finalized_block(&self, height: u64) -> Result<Option<FinalizedBlock>, BurnWatchError> {
        if height == HEIGHT {
            Ok(Some(clone_block(&self.block)))
        } else {
            Ok(None)
        }
    }
}

#[test]
fn a_decoded_burn_block_reproduces_the_event_root_and_verifies() {
    let (header_bytes, cert_bytes, leaves, members, beacon) = material();
    let json = burn_block_json(HEIGHT, &header_bytes, &cert_bytes, &leaves);

    let decoded = decode_finalized_block(&json).expect("the chain json decodes");
    assert_eq!(decoded.header_bytes, header_bytes);
    assert_eq!(decoded.events, leaves);

    let source = OneBlock { head: HEIGHT, block: decoded };
    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&source).expect("the poll assembles the burn");
    assert_eq!(proofs.len(), 1, "the decoded block surfaces exactly one burn");

    let anchor = anchor(&members, &beacon);
    let burn = proofs[0].verify(&anchor).expect("the decoded proof verifies");
    assert_eq!(burn.burn_ref, BURN_REF);
    assert_eq!(burn.amount, AMOUNT);
    assert_eq!(burn.beneficiary, BENEFICIARY);
    assert_eq!(burn.finalized_height, HEIGHT);
}

fn read_request(stream: &mut TcpStream) -> (String, String) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok();
    let path = request_line.split_whitespace().nth(1).unwrap_or("").to_string();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            if key.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok();
    (path, String::from_utf8_lossy(&body).into_owned())
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).ok();
    stream.flush().ok();
}

fn requested_height(body: &str) -> u64 {
    let marker = "\"height\":";
    match body.find(marker) {
        Some(at) => body[at + marker.len()..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0),
        None => 0,
    }
}

fn serve(block_json: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (path, body) = read_request(&mut stream);
            if path == "/v1/finalized_head" {
                respond(&mut stream, 200, "OK", &format!("{{\"head\":{HEIGHT}}}"));
            } else if path == "/v1/burn_heights_after" {
                respond(
                    &mut stream,
                    200,
                    "OK",
                    &format!("{{\"cursor\":0,\"count\":1,\"heights\":[{HEIGHT}]}}"),
                );
            } else if path == "/v1/burn_block" {
                if requested_height(&body) == HEIGHT {
                    respond(&mut stream, 200, "OK", &block_json);
                } else {
                    respond(
                        &mut stream,
                        404,
                        "Not Found",
                        "{\"error\":\"not_found\",\"message\":\"no archived burn block\"}",
                    );
                }
            } else {
                respond(&mut stream, 404, "Not Found", "{\"error\":\"unknown_method\"}");
            }
        }
    });
    port
}

#[test]
fn the_rpc_source_polls_the_gateway_and_verifies_end_to_end() {
    let (header_bytes, cert_bytes, leaves, members, beacon) = material();
    let block_json = burn_block_json(HEIGHT, &header_bytes, &cert_bytes, &leaves);
    let port = serve(block_json);

    let source = RpcBurnSource::new("127.0.0.1", port);
    assert_eq!(source.finalized_height().expect("head"), HEIGHT);
    assert_eq!(source.burn_heights_after(0).expect("heights"), vec![HEIGHT]);
    assert!(
        source.finalized_block(HEIGHT - 1).expect("absent").is_none(),
        "a non-burn height comes back as a not found"
    );

    let mut watcher = BurnWatcher::new(HEIGHT - 1);
    let proofs = watcher.poll(&source).expect("the poll over the socket succeeds");
    assert_eq!(proofs.len(), 1);

    let anchor = anchor(&members, &beacon);
    let burn = proofs[0].verify(&anchor).expect("the served proof verifies");
    assert_eq!(burn.burn_ref, BURN_REF);
    assert_eq!(burn.amount, AMOUNT);
    assert_eq!(burn.finalized_height, HEIGHT);
}
