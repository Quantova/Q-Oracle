#![forbid(unsafe_code)]

pub mod errors;
pub mod gateway;
pub mod operators;

pub use errors::GatewayError;
pub use gateway::{
    attestation_message, CorridorConfig, ExitTicket, Gateway, MintReceipt, BASE_TIER, BATCH_DOMAIN,
    FREEZE_DOMAIN, REORG_DOMAIN, TIER_DOMAIN, WATCHDOG_DOMAIN, WATCHDOG_MAX_WINDOW,
};
pub use operators::{verify_quorum, OperatorSet};
