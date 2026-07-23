#![forbid(unsafe_code)]

pub mod admission;
pub mod corridors;
pub mod sources;

pub use admission::{admit, install, FederatedError};
pub use corridors::{
    corridors, find, origin_tag, Corridor, Tier, TrustGrade, ALGORAND, APTOS, AVALANCHE, BNB_CHAIN,
    CARDANO, CCTP_USDC, DOGECOIN, HEDERA, LITECOIN, MONERO, NEAR, POLYGON, SOLANA, STELLAR, SUI,
    TON, TRON, XRPL, ZCASH,
};
pub use sources::{IndependenceReport, SourceEndpoint, SourceRegistry};

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
