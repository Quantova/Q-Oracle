// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_isolation::{admit, Refused, ALL_CROSSINGS, CROSSING_KIND_COUNT};

fn refused(bytes: &[u8]) {
    assert!(admit(bytes).is_err(), "foreign bytes must not cross");
}

fn secp256k1_der_signature() -> Vec<u8> {
    vec![
        0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0x02, 0x20, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
    ]
}

fn ed25519_signature() -> Vec<u8> {
    (0..64).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect()
}

fn secp256k1_uncompressed_public_key() -> Vec<u8> {
    let mut pk = vec![0x04u8];
    pk.extend_from_slice(&[0x7fu8; 64]);
    pk
}

fn secp256k1_compressed_even_public_key() -> Vec<u8> {
    let mut pk = vec![0x02u8];
    pk.extend_from_slice(&[0x5cu8; 32]);
    pk
}

fn secp256k1_compressed_odd_public_key() -> Vec<u8> {
    let mut pk = vec![0x03u8];
    pk.extend_from_slice(&[0x5cu8; 32]);
    pk
}

fn ed25519_public_key() -> Vec<u8> {
    (0..32).map(|i| (i as u8).wrapping_mul(11).wrapping_add(0x40)).collect()
}

fn bls12_381_g1_compressed() -> Vec<u8> {
    let mut g1 = vec![0xa0u8];
    g1.extend_from_slice(&[0x33u8; 47]);
    g1
}

fn bls12_381_g2_compressed() -> Vec<u8> {
    let mut g2 = vec![0x80u8];
    g2.extend_from_slice(&[0x21u8; 95]);
    g2
}

fn ethereum_rlp_header() -> Vec<u8> {
    let mut rlp = vec![0xf9u8, 0x02, 0x1a];
    rlp.extend_from_slice(&[0x88u8; 512]);
    rlp
}

fn tendermint_protobuf_header() -> Vec<u8> {
    let mut header = vec![0x0au8, 0x20];
    header.extend_from_slice(&[0x66u8; 200]);
    header
}

fn keccak256_root() -> Vec<u8> {
    (0..32).map(|i| (i as u8).wrapping_mul(13).wrapping_add(0x91)).collect()
}

fn blake2b_hash() -> Vec<u8> {
    (0..64).map(|i| (i as u8).wrapping_mul(17).wrapping_add(0x2c)).collect()
}

fn merkle_root_leading_attestation_tag() -> Vec<u8> {
    let mut root = vec![0x01u8];
    root.extend_from_slice(&[0xcdu8; 31]);
    root
}

fn merkle_root_leading_stark_tag() -> Vec<u8> {
    let mut root = vec![0x02u8];
    root.extend_from_slice(&[0xefu8; 31]);
    root
}

#[test]
fn a_foreign_signature_is_refused() {
    refused(&secp256k1_der_signature());
    refused(&ed25519_signature());
    assert_eq!(admit(&secp256k1_der_signature()), Err(Refused::Foreign));
}

#[test]
fn a_foreign_public_key_is_refused() {
    refused(&secp256k1_uncompressed_public_key());
    refused(&secp256k1_compressed_even_public_key());
    refused(&secp256k1_compressed_odd_public_key());
    refused(&ed25519_public_key());
    refused(&bls12_381_g1_compressed());
    refused(&bls12_381_g2_compressed());
    assert_eq!(admit(&secp256k1_uncompressed_public_key()), Err(Refused::Foreign));
}

#[test]
fn a_foreign_header_is_refused() {
    refused(&ethereum_rlp_header());
    refused(&tendermint_protobuf_header());
    assert_eq!(admit(&ethereum_rlp_header()), Err(Refused::Foreign));
}

#[test]
fn a_foreign_hash_is_refused() {
    refused(&keccak256_root());
    refused(&blake2b_hash());
}

#[test]
fn a_foreign_root_is_refused() {
    refused(&keccak256_root());
    refused(&merkle_root_leading_attestation_tag());
    refused(&merkle_root_leading_stark_tag());
}

#[test]
fn a_leading_tag_collision_does_not_let_a_foreign_root_cross() {
    assert_eq!(
        admit(&merkle_root_leading_attestation_tag()),
        Err(Refused::Malformed)
    );
    assert_eq!(
        admit(&merkle_root_leading_stark_tag()),
        Err(Refused::Malformed)
    );
}

#[test]
fn the_crossing_alphabet_holds_no_foreign_kind() {
    assert_eq!(CROSSING_KIND_COUNT, 2);
    assert_eq!(ALL_CROSSINGS.len(), 2);
    for kind in ALL_CROSSINGS {
        assert!(kind.tag() == 0x01 || kind.tag() == 0x02);
    }
}
