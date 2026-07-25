#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


pub mod certificate;
pub mod errors;
pub mod exits;
pub mod payout;
pub mod vault;

pub use certificate::{
    ExitCertificate, ExitProver, ExitStatement, ExitVerifier, HashStark, EXIT_PROOF_DOMAIN,
    EXIT_STATEMENT_DOMAIN, EXIT_STATEMENT_VERSION,
};
pub use errors::ExitError;
pub use exits::{
    DeskConfig, Exit, ExitDesk, ExitId, ExitState, Release, SlashOutcome, BPS_DEN,
};
pub use payout::{
    BitcoinPayoutWatcher, BitcoinReleaseProof, EvmPayoutWatcher, EvmReleaseProof,
    PayoutAttestation, PayoutProofError, PayoutWatcher, VerifiedPayout, PAYOUT_DOMAIN,
    PAYOUT_VERSION,
};
pub use vault::{Vault, VaultBook};
