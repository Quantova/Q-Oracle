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
    ProveNothing,
    InvalidFact(CodecError),
    Unauthorized,
}

impl From<CodecError> for GatewayError {
    fn from(e: CodecError) -> GatewayError {
        GatewayError::InvalidFact(e)
    }
}
