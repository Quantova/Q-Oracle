// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitError {
    UnsetAnchor,
    UnsetCustody,
    BadPublicKeyLen,
    ZeroThreshold,
    ThresholdAboveRoster,
    TauAboveCommittee,
    HeaderDecode,
    HeaderMismatch,
    HeightMismatch,
    NotFinalized,
    BadInclusion,
    NotABurnLeaf,
    LeafDecode,
    ZeroAmount,
    ZeroAsset,
    ZeroBeneficiary,
    ZeroBurnRef,
    BurnMismatch,
    BelowThreshold { have: usize, need: usize },
    UnknownOperator(u32),
    BadSignature(u32),
    ReplayedBurn,
    PersistFailed,
    TermsMismatch,
    PayoutUnconfigured,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_below_threshold_reports_have_and_need() {
        let e = ExitError::BelowThreshold { have: 1, need: 2 };
        assert_ne!(e, ExitError::BelowThreshold { have: 2, need: 2 });
    }

    #[test]
    fn an_unknown_operator_carries_its_id() {
        assert_ne!(ExitError::UnknownOperator(1), ExitError::UnknownOperator(2));
    }
}
