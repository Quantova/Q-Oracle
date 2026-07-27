// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{ExitConfig, FailClosedPayout};

pub const EXITS_ENABLED_ENV: &str = "Q_ORACLE_EXITS_ENABLED";

pub fn parse_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

pub fn exit_config_from_env() -> ExitConfig {
    let raw = std::env::var(EXITS_ENABLED_ENV).ok();
    ExitConfig {
        enabled: parse_enabled(raw.as_deref()),
    }
}

pub fn exits_started(config: &ExitConfig) -> bool {
    config.enabled
}

pub fn default_payout_executor() -> FailClosedPayout {
    FailClosedPayout::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_exits::{ExitError, PayoutExecutor, Release, ReleaseAuthorization, ReleaseTerms};

    #[test]
    fn the_flag_is_off_unless_explicitly_enabled() {
        assert!(!parse_enabled(None));
        assert!(!parse_enabled(Some("0")));
        assert!(!parse_enabled(Some("true")));
        assert!(parse_enabled(Some("1")));
    }

    #[test]
    fn the_default_config_does_not_start_exits() {
        assert!(!exits_started(&ExitConfig::default()));
    }

    #[test]
    fn the_default_boot_payout_executor_refuses_without_custody() {
        let executor = default_payout_executor();
        let release = Release {
            vault: [0x99; 32],
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
            finalized_height: 1,
        };
        let authorization = ReleaseAuthorization {
            terms: ReleaseTerms {
                asset_id: [0xa1; 16],
                amount: 500,
                beneficiary: [0x55; 32],
                burn_ref: [0x11; 32],
            },
            signatures: Vec::new(),
        };
        assert_eq!(
            executor.execute(&release, &authorization),
            Err(ExitError::PayoutUnconfigured)
        );
    }
}
