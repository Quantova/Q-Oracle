use q_codec::CodecError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    GlobalPause,
    WrongDirection,
    WrongDestination,
    CorridorNotOpen(u32),
    CorridorInactive(u32),
    SourcePaused(u32),
    InsufficientFinality { got: u32, need: u32 },
    AssetNotRegistered,
    AssetCapExceeded { minted: u128, cap: u128, add: u128 },
    EpochCapExceeded { minted: u128, cap: u128, add: u128 },
    ReplayedReference,
    UnknownOperator(u32),
    BadSignature(u32),
    BelowThreshold { got: usize, need: usize },
    ThinQuorum { quorum: usize, size: usize },
    ProveNothing,
    InvalidFact(CodecError),
    Unauthorized,
}

impl From<CodecError> for GatewayError {
    fn from(e: CodecError) -> GatewayError {
        GatewayError::InvalidFact(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_error_maps_to_invalid_fact() {
        let e: GatewayError = CodecError::ZeroAmount.into();
        assert_eq!(e, GatewayError::InvalidFact(CodecError::ZeroAmount));
    }

    #[test]
    fn thin_quorum_reports_the_requested_size() {
        let e = GatewayError::ThinQuorum { quorum: 3, size: 9 };
        assert_ne!(e, GatewayError::ThinQuorum { quorum: 6, size: 9 });
    }
}
