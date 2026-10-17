#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod endpoints;

pub use endpoints::{
    commit_deposit, handle, handle_read, install_ethereum_rotation, install_ethereum_store,
    precheck, precheck_ethereum_rotation, prepare_deposit, rotate_ethereum_store, verify_deposit,
    verify_prepared, ApiError, BitcoinAnchor, BitcoinProofMaterial, BridgeState, CosmosAnchor,
    DepositOutcome, DepositPlan, DepositProof, DepositRequest, DepositStatusRequest,
    DepositStatusView, EmergencyFreezeRequest, GetPoolRequest, ListPoolsRequest, PoolView,
    PreparedDeposit, ReportReorgRequest, Request, Response, ResumeSourceRequest,
    SetCorridorTierRequest, WatchdogFreezeRequest,
};
