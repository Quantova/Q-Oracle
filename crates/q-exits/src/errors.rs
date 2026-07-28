// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_codec::CodecError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitError {
    UnsafeParams,
    BadVersion(u8),
    ZeroAmount,
    ZeroAsset,
    ZeroBeneficiary,
    ZeroBurnRef,
    ZeroCorridor,
    ReplayedExit,
    UnknownVault(u32),
    ThinVault { have: u128, need: u128 },
    UnknownExit,
    NotPending,
    WindowExpired { now: u64, deadline: u64 },
    WindowOpen { now: u64, deadline: u64 },
    PayoutMismatch,
    PayoutUnproven,
    ReplayedPayout,
    WrongDestination { got: u64, expected: u64 },
    Overflow,
    InvalidArtifact(CodecError),
    UnsetAnchor,
    BadPublicKeyLen,
    TauAboveCommittee,
    HeaderDecode,
    HeaderMismatch,
    HeightMismatch,
    NotFinalized,
    BadInclusion,
    NotABurnLeaf,
    LeafDecode,
    PersistFailed,
    ExitsDisabled,
}

impl From<CodecError> for ExitError {
    fn from(e: CodecError) -> ExitError {
        ExitError::InvalidArtifact(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_error_maps_to_invalid_artifact() {
        let e: ExitError = CodecError::ZeroAmount.into();
        assert_eq!(e, ExitError::InvalidArtifact(CodecError::ZeroAmount));
    }

    #[test]
    fn a_thin_vault_reports_have_and_need() {
        let e = ExitError::ThinVault { have: 140, need: 150 };
        assert_ne!(e, ExitError::ThinVault { have: 150, need: 150 });
    }

    #[test]
    fn an_expired_window_differs_from_an_open_window() {
        let a = ExitError::WindowExpired { now: 20, deadline: 10 };
        let b = ExitError::WindowOpen { now: 5, deadline: 10 };
        assert_ne!(a, b);
    }
}
