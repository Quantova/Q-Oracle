#![forbid(unsafe_code)]

pub mod errors;
pub mod gateway;
pub mod operators;

pub use errors::GatewayError;
pub use gateway::{
    attestation_message, CorridorConfig, Gateway, MintReceipt, REORG_DOMAIN,
};
pub use operators::{verify_quorum, OperatorSet};
