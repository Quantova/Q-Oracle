#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod admission;
pub mod corridors;
pub mod pools;
pub mod sources;
pub mod trustless;
pub mod watch;

pub use admission::{admit, install, FederatedError};
pub use pools::{
    corridor_for, derive_asset_id, depth_for, grade_for, install_all, install_pool, tier_for,
    PoolError, PoolRegistry, PoolRequest, PoolSpec,
};
pub use trustless::{
    admit_bitcoin_trustless, admit_cosmos_trustless, admit_ethereum_trustless, match_bitcoin_deposit,
    match_cosmos_deposit, match_ethereum_deposit, TrustlessError, TrustlessMint,
};
pub use corridors::{
    corridors, find, origin_tag, Corridor, Tier, TrustGrade, ALGORAND, APTOS, AVALANCHE, BNB_CHAIN,
    CARDANO, CCTP_USDC, DOGECOIN, HEDERA, LITECOIN, MONERO, NEAR, POLYGON, SOLANA, STELLAR, SUI,
    TON, TRON, XRPL, ZCASH,
};
pub use sources::{IndependenceReport, SourceEndpoint, SourceRegistry};
pub use watch::{watch_and_admit, OperatorFeed, WatchError};

#[cfg(test)]
mod exports {
    use crate::{corridors, find, SourceRegistry, Tier, SOLANA};

    #[test]
    fn the_crate_root_surface_is_reachable() {
        assert_eq!(corridors().len(), 19);
        assert_eq!(find(SOLANA).unwrap().tier, Tier::Federated);
        assert!(SourceRegistry::new().endpoint(SOLANA, 0).is_none());
    }
}
