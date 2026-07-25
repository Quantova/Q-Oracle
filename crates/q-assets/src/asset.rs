// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::network::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetId {
    Native,
    Foreign(Network, &'static str),
}

impl AssetId {
    pub fn origin(&self) -> Option<Network> {
        match self {
            AssetId::Native => None,
            AssetId::Foreign(network, _) => Some(*network),
        }
    }

    pub fn is_foreign(&self) -> bool {
        matches!(self, AssetId::Foreign(_, _))
    }

    pub fn identifier(&self) -> Option<&'static str> {
        match self {
            AssetId::Native => None,
            AssetId::Foreign(_, identifier) => Some(identifier),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_asset_resolves_to_its_origin_network() {
        let btc = AssetId::Foreign(Network::Bitcoin, "BTC");
        assert_eq!(btc.origin(), Some(Network::Bitcoin));
        assert_eq!(btc.identifier(), Some("BTC"));
        assert!(btc.is_foreign());
    }

    #[test]
    fn the_native_asset_has_no_foreign_origin() {
        assert_eq!(AssetId::Native.origin(), None);
        assert_eq!(AssetId::Native.identifier(), None);
        assert!(!AssetId::Native.is_foreign());
    }

    #[test]
    fn the_same_symbol_on_two_networks_is_two_distinct_assets() {
        let usdc_eth = AssetId::Foreign(Network::Ethereum, "USDC");
        let usdc_sol = AssetId::Foreign(Network::Solana, "USDC");
        assert_ne!(usdc_eth, usdc_sol);
        assert_eq!(usdc_eth.origin(), Some(Network::Ethereum));
        assert_eq!(usdc_sol.origin(), Some(Network::Solana));
    }
}
