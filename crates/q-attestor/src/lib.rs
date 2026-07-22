#![forbid(unsafe_code)]

pub mod aggregator;
pub mod operator;
pub mod signer;
pub mod translator;
pub mod watcher;

pub use aggregator::{Aggregator, AggregatorError};
pub use operator::{HaltReason, Operator, OperatorError, OperatorState, SignedObservation};
pub use signer::{AttestationSigner, SoftSigner};
pub use translator::translate;
pub use watcher::{CorridorContext, FinalityPolicy, ObservedLock, Watcher, WatcherError};
