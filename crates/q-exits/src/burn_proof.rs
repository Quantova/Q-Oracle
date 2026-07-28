// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::Certificate;
use qtv_block::{header_from_bytes, verify_inclusion, MerkleProof};
use qtv_codec::Decoder;

use crate::anchor::QuantovaAnchor;
use crate::errors::ExitError;

pub const NATIVE_EVENT_SOURCE: &[u8] = b"qtv/native";
pub const EVENT_BRIDGE_BURN: &[u8] = b"QBBN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBurn {
    pub asset_id: [u8; 16],
    pub beneficiary: [u8; 32],
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

        let verdict = self.certificate.verify(
            anchor.chain_id(),
            anchor.commitment(),
            anchor.beacon(),
            anchor.tau(),
        );
        if !verdict.is_verified() {
            return Err(ExitError::NotFinalized);
        }

        if !verify_inclusion(header.event_root(), &self.leaf, &self.inclusion) {
            return Err(ExitError::BadInclusion);
        }

        parse_burn_leaf(&self.leaf, header.height())
    }
}

fn parse_burn_leaf(leaf: &[u8], finalized_height: u64) -> Result<AuthenticatedBurn, ExitError> {
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
    let _holder = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let amount = fields.get_u128().map_err(|_| ExitError::LeafDecode)?;
    let destination = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    let dest_chain = fields.get_u64().map_err(|_| ExitError::LeafDecode)?;
    let _sender_nonce = fields.get_u64().map_err(|_| ExitError::LeafDecode)?;
    let _event_index = fields.get_u64().map_err(|_| ExitError::LeafDecode)?;
    let burn_ref = fields.get_bytes().map_err(|_| ExitError::LeafDecode)?;
    fields.finish().map_err(|_| ExitError::LeafDecode)?;

    let asset_id = <[u8; 16]>::try_from(asset_id).map_err(|_| ExitError::LeafDecode)?;
    let beneficiary = <[u8; 32]>::try_from(destination).map_err(|_| ExitError::LeafDecode)?;
    let burn_ref = <[u8; 32]>::try_from(burn_ref).map_err(|_| ExitError::LeafDecode)?;

    Ok(AuthenticatedBurn {
        asset_id,
        beneficiary,
        amount,
        burn_ref,
        dest_chain,
        finalized_height,
    })
}
