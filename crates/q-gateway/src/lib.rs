#![forbid(unsafe_code)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::items_after_test_module)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod errors;
pub mod gateway;
pub mod operators;

pub use errors::GatewayError;
pub use gateway::{
    attestation_message, batch_message, freeze_message, lift_message, reorg_message,
    reserve_message, tier_message, unpause_message, AdminRecord, CorridorConfig, ExitTicket,
    Gateway, MintReceipt, BASE_TIER, BATCH_DOMAIN, EMERGENCY_FREEZE_MAX_WINDOW, FREEZE_DOMAIN,
    LIFT_DOMAIN, REORG_DOMAIN, RESERVE_DOMAIN, RESERVE_MAX_AGE, TIER_DOMAIN, UNPAUSE_DOMAIN,
    WATCHDOG_DOMAIN, WATCHDOG_MAX_WINDOW,
};
pub use operators::{verified_quorum, verify_quorum, OperatorSet};
