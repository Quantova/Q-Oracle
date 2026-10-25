// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::Certificate;
use qtv_block::{header_from_bytes, verify_inclusion, MerkleProof};
use qtv_codec::{Decoder, Encoder};

use crate::anchor::QuantovaAnchor;
use crate::errors::ExitError;

pub const NATIVE_EVENT_SOURCE: &[u8] = b"qtv/native";
pub const EVENT_BRIDGE_BURN: &[u8] = b"QBBN";
const BRIDGE_BURN_REF_DOMAIN: &[u8] = b"qtv/bridge/burn-ref/v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBurn {
    pub asset_id: [u8; 16],
    pub holder: [u8; 32],
    pub destination: [u8; 32],
    pub amount: u128,
    pub burn_ref: [u8; 32],
    pub dest_chain: u64,
    pub finalized_height: u64,
}

pub struct ProofOfBurn {
    pub header_bytes: Vec<u8>,
    pub certificate: Certificate,
    pub leaf: Vec<u8>,
    pub inclusion: MerkleProof,
}

impl ProofOfBurn {
    pub fn verify(&self, anchor: &QuantovaAnchor) -> Result<AuthenticatedBurn, ExitError> {
        let header = header_from_bytes(&self.header_bytes).map_err(|_| ExitError::HeaderDecode)?;

        if self.certificate.envelope.block.val != header.hash() {
            return Err(ExitError::HeaderMismatch);
        }
        if self.certificate.envelope.block.height != header.height()
            || self.certificate.envelope.height != header.height()
        {
            return Err(ExitError::HeightMismatch);
        }

        let verdict = self.certificate.verify_with_trusted_commitment(
            anchor.binding(),
            &anchor.commitment_at(self.certificate.envelope.slot),
            anchor.beacon(),
            anchor.tau(),
        );
        if !verdict.is_verified() {
            return Err(ExitError::NotFinalized);
        }

        if (self.certificate.attesters().len() as u64) < anchor.tau() {
            return Err(ExitError::NotFinalized);
        }

        if !verify_inclusion(header.event_root(), &self.leaf, &self.inclusion) {
            return Err(ExitError::BadInclusion);
        }

        parse_burn_leaf(&self.leaf, header.height(), Some(&anchor.genesis()))
    }

    pub fn claimed_height(&self) -> u64 {
        header_from_bytes(&self.header_bytes)
            .map(|header| header.height())
            .unwrap_or(self.certificate.envelope.height)
    }

    pub fn claimed_burn_ref(&self) -> Option<[u8; 32]> {
        parse_burn_leaf(&self.leaf, 0, None)
            .ok()
            .map(|burn| burn.burn_ref)
    }

    pub fn leaf_digest(&self) -> [u8; 32] {
        leaf_digest(&self.leaf)
    }
}

pub fn leaf_digest(leaf: &[u8]) -> [u8; 32] {
    qtv_crypto::sha3::sha3_256(leaf)
}

fn parse_burn_leaf(
    leaf: &[u8],
    finalized_height: u64,
    genesis: Option<&[u8; 32]>,
) -> Result<AuthenticatedBurn, ExitError> {
    let mut outer = Decoder::new(leaf);
    let contract = outer.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let selector = outer.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let data = outer.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    outer.finish().map_err(|_| ExitError::LeafDecode)?;

    if contract != NATIVE_EVENT_SOURCE || selector != EVENT_BRIDGE_BURN {
        return Err(ExitError::NotABurnLeaf);
    }

    let mut fields = Decoder::new(data);
    let asset_id = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let holder = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let amount = fields.get_u128().map_err(|_| ExitError::LeafDecode)?;
    let destination = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let dest_chain = fields.get_u64().map_err(|_| ExitError::LeafDecode)?;
    let sender_nonce = fields.get_u64().map_err(|_| ExitError::LeafDecode)?;
    let event_index = fields.get_u64().map_err(|_| ExitError::LeafDecode)?;
    let burn_ref = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    fields.finish().map_err(|_| ExitError::LeafDecode)?;

    let asset_id = <[u8; 16]>::try_from(asset_id).map_err(|_| ExitError::LeafDecode)?;
    let holder = <[u8; 32]>::try_from(holder).map_err(|_| ExitError::LeafDecode)?;
    let destination = <[u8; 32]>::try_from(destination).map_err(|_| ExitError::LeafDecode)?;
    let burn_ref = <[u8; 32]>::try_from(burn_ref).map_err(|_| ExitError::LeafDecode)?;
    if let Some(genesis) = genesis {
        let mut derived = Encoder::new();
        derived.put_bytes(BRIDGE_BURN_REF_DOMAIN);
        derived.put_u64(dest_chain);
        derived.put_bytes(genesis);
        derived.put_bytes(&asset_id);
        derived.put_bytes(&holder);
        derived.put_u128(amount);
        derived.put_bytes(&destination);
        derived.put_u64(sender_nonce);
        derived.put_u64(event_index);
        if qtv_crypto::sha3::sha3_256(&derived.into_bytes()) != burn_ref {
            return Err(ExitError::BurnRefUnbound);
        }
    }

    Ok(AuthenticatedBurn {
        asset_id,
        holder,
        destination,
        amount,
        burn_ref,
        dest_chain,
        finalized_height,
    })
}
