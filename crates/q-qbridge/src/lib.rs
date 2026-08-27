#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod endpoints;

pub use endpoints::{
    commit_deposit, handle, handle_read, verify_deposit, ApiError, BitcoinAnchor,
    BitcoinProofMaterial, BridgeState, DepositOutcome, DepositPlan, DepositProof, DepositRequest,
    DepositStatusRequest, DepositStatusView, GetPoolRequest, ListPoolsRequest, PoolView, Request,
    Response,
};
