#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod boot;
pub mod exits;
pub mod http;
pub mod json;
pub mod persist;
pub mod watch;
pub mod wire;

pub use boot::{
    boot, boot_with, declare_operator_source, run, run_with, shared, start_exits, ExitHandle,
    ExitService, DEFAULT_EPOCH_CAP, DEST_CHAIN,
};
pub use exits::{
    exit_config_from_env, exits_started, load_exit_config, parse_enabled, parse_exit_config,
    BitcoinCheckpointConfig, EnvSource, ExitConfigError, ExitTrustConfig, VaultSeed,
    EXITS_ENABLED_ENV,
};
pub use http::{serve, SharedState, MAX_BODY, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, MAX_HEAD};
pub use json::Json;
pub use persist::GuardStore;
pub use watch::{
    bitcoin_proof, cosmos_proof, ethereum_proof, federated_proof, ingest_once, ChainWatcher,
    Ingested, WatchError, WatcherPool,
};
pub use wire::{
    decode_request, decode_response, encode_request, encode_response, method_of, WireError,
};
