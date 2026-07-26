// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8645".to_string());
    let snapshot = std::env::var_os("Q_ORACLE_GUARD_SNAPSHOT").map(std::path::PathBuf::from);
    q_runtime::run(addr, snapshot)
}
