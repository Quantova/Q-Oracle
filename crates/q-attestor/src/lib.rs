#![forbid(unsafe_code)]

pub mod aggregator;
pub mod operator;
pub mod signer;
pub mod translator;
pub mod watcher;

pub use aggregator::{Aggregator, AggregatorError};
pub use operator::{HaltReason, Operator, OperatorError, OperatorState, SignedObservation};
pub use signer::{
    AttestationSigner, EnclaveSigner, ObjectHandle, Pkcs11Backend, Pkcs11Error, Pkcs11Module,
    SessionHandle, SigningBackend, SlotId, SoftBackend, SoftSigner, SoftwareHsm,
};
pub use translator::{
    attest, corridor_stark, corridor_statement, package, translate, verify_corridor_stark,
    OutboundEnvelope, MESSAGE_TTL_BLOCKS,
};
pub use watcher::{CorridorContext, FinalityPolicy, ObservedLock, Watcher, WatcherError, WatcherSet};

#[cfg(test)]
mod exports {
    use crate::{AttestationSigner, EnclaveSigner, SoftBackend, WatcherSet};

    #[test]
    fn the_crate_root_surface_is_reachable() {
        let signer = EnclaveSigner::new(SoftBackend::from_seed(0, &[0u8; 32]));
        assert_eq!(signer.operator_id(), 0);
        assert!(WatcherSet::new().chains().is_empty());
    }
}
