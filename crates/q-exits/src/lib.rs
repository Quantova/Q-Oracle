#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


pub mod anchor;
pub mod burn_proof;
pub mod errors;
pub mod exits;
pub mod feed;
pub mod ledger;
pub mod payout;
pub mod rpc;
pub mod store;
pub mod vault;
pub mod watch;

pub use anchor::{MemberConfig, QuantovaAnchor, ATTEST_PK_BYTES, BEACON_SEED_BYTES};
pub use burn_proof::{
    AuthenticatedBurn, ProofOfBurn, EVENT_BRIDGE_BURN, NATIVE_EVENT_SOURCE,
};
pub use errors::ExitError;
pub use exits::{
    DeskConfig, Exit, ExitDesk, ExitId, ExitState, ExitStatement, Release, SlashOutcome, BPS_DEN,
    EXIT_STATEMENT_VERSION,
};
pub use feed::{BurnFeed, ExitConfig, FeedError};
pub use ledger::{
    MemoryLedger, PersistentLedger, ReplayLedger, LEDGER_VERSION, MAX_LEDGER_ENTRIES,
};
pub use payout::{
    BitcoinPayoutWatcher, BitcoinReleaseProof, EvmPayoutWatcher, EvmReleaseProof,
    PayoutAttestation, PayoutProofError, PayoutWatcher, VerifiedPayout, PAYOUT_DOMAIN,
    PAYOUT_VERSION,
};
pub use rpc::{
    decode_finalized_block, decode_finalized_head, decode_heights_after, RpcBurnSource,
};
pub use store::ReplayStore;
pub use vault::{Vault, VaultBook};
pub use watch::{
    is_bridge_burn_leaf, BurnWatchError, BurnWatcher, FinalizedBlock, QuantovaBurnSource,
    MAX_BURNS_PER_BLOCK, MAX_HEIGHTS_PER_POLL,
};
