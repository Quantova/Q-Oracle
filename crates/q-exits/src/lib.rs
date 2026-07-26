#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


pub mod anchor;
pub mod burn_proof;
pub mod desk;
pub mod errors;
pub mod release;

pub use anchor::{MemberConfig, QuantovaAnchor, ATTEST_PK_BYTES, BEACON_SEED_BYTES};
pub use burn_proof::{
    AuthenticatedBurn, ProofOfBurn, EVENT_BRIDGE_BURN, NATIVE_EVENT_SOURCE,
};
pub use desk::{CustodyConfig, Release, ReleaseDesk};
pub use errors::ExitError;
pub use release::{
    OperatorQuorum, OperatorSig, ReleaseAuthorization, ReleaseTerms, RELEASE_DOMAIN,
    RELEASE_VERSION,
};
