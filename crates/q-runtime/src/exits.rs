// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_exits::{ExitConfig, RpcBurnSource};

pub const EXITS_ENABLED_ENV: &str = "Q_ORACLE_EXITS_ENABLED";
pub const CHAIN_RPC_HOST_ENV: &str = "Q_ORACLE_CHAIN_RPC_HOST";
pub const CHAIN_RPC_PORT_ENV: &str = "Q_ORACLE_CHAIN_RPC_PORT";
pub const DEFAULT_CHAIN_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_CHAIN_RPC_PORT: u16 = 8080;

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

pub fn burn_source_from_env(config: &ExitConfig) -> Option<RpcBurnSource> {
    if !config.enabled {
        return None;
    }
    let host =
        std::env::var(CHAIN_RPC_HOST_ENV).unwrap_or_else(|_| DEFAULT_CHAIN_RPC_HOST.to_string());
    let port = std::env::var(CHAIN_RPC_PORT_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_CHAIN_RPC_PORT);
    Some(RpcBurnSource::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_burn_source_is_absent_unless_exits_are_enabled() {
        assert!(burn_source_from_env(&ExitConfig::default()).is_none());
        assert!(burn_source_from_env(&ExitConfig { enabled: true }).is_some());
    }
}
