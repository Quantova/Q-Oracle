#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


pub mod anchor;
pub mod authorizer;
pub mod burn_proof;
pub mod desk;
pub mod errors;
pub mod ledger;
pub mod orchestrator;
pub mod payout;
pub mod release;
pub mod rpc;
pub mod store;
pub mod watch;

pub use anchor::{MemberConfig, QuantovaAnchor, ATTEST_PK_BYTES, BEACON_SEED_BYTES};
pub use authorizer::{
    OperatorAuthorizer, ReleaseAggregator, ReleaseSigner, SoftReleaseSigner,
};
pub use burn_proof::{
    AuthenticatedBurn, ProofOfBurn, EVENT_BRIDGE_BURN, NATIVE_EVENT_SOURCE,
};
pub use desk::{CustodyConfig, Release, ReleaseDesk};
pub use errors::ExitError;
pub use ledger::{
    MemoryLedger, PersistentLedger, ReplayLedger, LEDGER_VERSION, MAX_LEDGER_ENTRIES,
};
pub use orchestrator::{ExitConfig, ReleasePipeline};
pub use payout::{FailClosedPayout, PayoutCustody, PayoutExecutor, PayoutReceipt};
pub use release::{
    OperatorQuorum, OperatorSig, ReleaseAuthorization, ReleaseTerms, RELEASE_DOMAIN,
    RELEASE_VERSION,
};
pub use rpc::{
    decode_finalized_block, decode_finalized_head, decode_heights_after, RpcBurnSource,
};
pub use store::ReplayStore;
pub use watch::{
    is_bridge_burn_leaf, BurnWatchError, BurnWatcher, FinalizedBlock, QuantovaBurnSource,
    MAX_BURNS_PER_BLOCK, MAX_HEIGHTS_PER_POLL,
};
