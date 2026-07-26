#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The qbridge runtime endpoint layer.
//!
//! `handle` is the whole runtime as a pure function of `(BridgeState, Request)`. There is no socket,
//! no async runtime, and no networking dependency in this crate. A thin HTTP server attaches at one
//! seam: decode a request frame into [`Request`], call [`handle`], encode the returned [`Response`]
//! into a response frame. Wire encoding lives with that server, not here, so the runtime stays
//! testable without a live chain.
//!
//! A deposit on a proof-backed corridor is admitted, not minted, here. The authoritative on-chain
//! mint stays at the seam documented in `q_federated::trustless`: a proof-backed deposit must not
//! mint without the corridor's STARK verified on chain, a founder-level gateway change. This layer
//! never opens a no-quorum mint entry point.

pub mod endpoints;

pub use endpoints::{
    commit_deposit, handle, handle_read, verify_deposit, ApiError, BitcoinAnchor,
    BitcoinProofMaterial, BridgeState, DepositOutcome, DepositPlan, DepositProof, DepositRequest,
    DepositStatusRequest, DepositStatusView, GetPoolRequest, ListPoolsRequest, PoolView, Request,
    Response,
};
