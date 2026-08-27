#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod prover;
pub mod statement;

pub use prover::{
    prove_statement, verify_statement, CommitmentProof, BRIDGE_BLOWUP, BRIDGE_QUERIES,
};
pub use statement::{CorridorStatement, BRIDGE_STATEMENT_DOMAIN, STATEMENT_DIGEST_LEN};

#[cfg(test)]
mod exports {
    use crate::{prove_statement, verify_statement, CorridorStatement};
    use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION};

    #[test]
    fn the_crate_root_surface_is_reachable() {
        let fact = BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            direction: Direction::Deposit,
            nonce: 42,
            source_ref: SourceRef([9u8; 32]),
            asset_id: AssetId([3u8; 16]),
            amount: 1_000_000,
            recipient: Recipient([5u8; 32]),
            finality_depth: 12,
            observed_height: 880_000,
            expiry_height: 900_000,
        };
        let statement = CorridorStatement::new(0, fact);
        let commitment = prove_statement(&statement);
        assert!(verify_statement(&statement, &commitment));
    }
}
