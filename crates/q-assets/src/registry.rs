use crate::asset::AssetId;
use crate::network::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetRecord {
    pub id: AssetId,
    pub decimals: u8,
}

const fn foreign(network: Network, identifier: &'static str, decimals: u8) -> AssetRecord {
    AssetRecord {
        id: AssetId::Foreign(network, identifier),
        decimals,
    }
}

pub const ASSETS: &[AssetRecord] = &[
    AssetRecord {
        id: AssetId::Native,
        decimals: 18,
    },
    foreign(Network::Bitcoin, "BTC", 8),
    foreign(Network::BitcoinCash, "BCH", 8),
    foreign(Network::Ethereum, "ETH", 18),
    foreign(Network::Ethereum, "USDC", 6),
    foreign(Network::Ethereum, "USDT", 6),
    foreign(Network::Ethereum, "DAI", 18),
    foreign(Network::Ethereum, "WBTC", 8),
    foreign(Network::Ethereum, "WETH", 18),
    foreign(Network::BnbChain, "BNB", 18),
    foreign(Network::BnbChain, "USDC", 6),
    foreign(Network::BnbChain, "USDT", 6),
    foreign(Network::BnbChain, "WETH", 18),
    foreign(Network::BnbChain, "WBNB", 18),
    foreign(Network::Polygon, "POL", 18),
    foreign(Network::Polygon, "USDC", 6),
    foreign(Network::Polygon, "USDT", 6),
    foreign(Network::Polygon, "DAI", 18),
    foreign(Network::Polygon, "WBTC", 8),
    foreign(Network::Polygon, "WETH", 18),
    foreign(Network::Polygon, "WPOL", 18),
    foreign(Network::Avalanche, "AVAX", 18),
    foreign(Network::Avalanche, "USDC", 6),
    foreign(Network::Avalanche, "USDT", 6),
    foreign(Network::Avalanche, "DAI", 18),
    foreign(Network::Avalanche, "WBTC", 8),
    foreign(Network::Avalanche, "WETH", 18),
    foreign(Network::Avalanche, "WAVAX", 18),
    foreign(Network::Arbitrum, "ARB", 18),
    foreign(Network::Arbitrum, "USDC", 6),
    foreign(Network::Arbitrum, "USDT", 6),
    foreign(Network::Arbitrum, "DAI", 18),
    foreign(Network::Arbitrum, "WBTC", 8),
    foreign(Network::Arbitrum, "WETH", 18),
    foreign(Network::Optimism, "OP", 18),
    foreign(Network::Optimism, "USDC", 6),
    foreign(Network::Optimism, "DAI", 18),
    foreign(Network::Optimism, "WBTC", 8),
    foreign(Network::Optimism, "WETH", 18),
    foreign(Network::Fantom, "FTM", 18),
    foreign(Network::Fantom, "WFTM", 18),
    foreign(Network::Cosmos, "ATOM", 6),
    foreign(Network::Osmosis, "OSMO", 6),
    foreign(Network::Celestia, "TIA", 6),
    foreign(Network::Injective, "INJ", 18),
    foreign(Network::Polkadot, "DOT", 10),
    foreign(Network::Kusama, "KSM", 12),
    foreign(Network::Bittensor, "TAO", 9),
    foreign(Network::Solana, "SOL", 9),
    foreign(Network::Solana, "USDC", 6),
    foreign(Network::Solana, "USDT", 6),
    foreign(Network::Solana, "WSOL", 9),
    foreign(Network::Tron, "TRX", 6),
    foreign(Network::Tron, "USDT", 6),
    foreign(Network::Ripple, "XRP", 6),
    foreign(Network::Cardano, "ADA", 6),
    foreign(Network::Near, "NEAR", 24),
    foreign(Network::Near, "USDC", 6),
    foreign(Network::Near, "USDT", 6),
    foreign(Network::Sui, "SUI", 9),
    foreign(Network::Sui, "USDC", 6),
    foreign(Network::Aptos, "APT", 8),
    foreign(Network::Aptos, "USDC", 6),
    foreign(Network::Hedera, "HBAR", 8),
    foreign(Network::Algorand, "ALGO", 6),
    foreign(Network::Ton, "TON", 9),
    foreign(Network::Ton, "USDT", 6),
    foreign(Network::Stellar, "XLM", 7),
    foreign(Network::Monero, "XMR", 12),
    foreign(Network::Litecoin, "LTC", 8),
    foreign(Network::Dogecoin, "DOGE", 8),
    foreign(Network::Zcash, "ZEC", 8),
    foreign(Network::Sei, "SEI", 6),
    foreign(Network::Kava, "KAVA", 6),
    foreign(Network::Filecoin, "FIL", 18),
    foreign(Network::Celo, "CELO", 18),
    foreign(Network::Cronos, "CRO", 8),
    foreign(Network::RobinhoodChain, "RHC", 18),
    foreign(Network::RobinhoodChain, "ETH", 18),
    foreign(Network::RobinhoodChain, "USDC", 6),
    foreign(Network::RobinhoodChain, "RWA", 18),
];

pub fn find(id: AssetId) -> Option<&'static AssetRecord> {
    ASSETS.iter().find(|a| a.id == id)
}

pub fn by_network(network: Network) -> impl Iterator<Item = &'static AssetRecord> {
    ASSETS
        .iter()
        .filter(move |a| a.id.origin() == Some(network))
}

pub fn count() -> usize {
    ASSETS.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_registry_holds_more_than_seventy_assets() {
        assert!(count() > 70, "the registry has {} assets", count());
    }

    #[test]
    fn every_registered_asset_id_is_distinct() {
        let ids: BTreeSet<AssetId> = ASSETS.iter().map(|a| a.id).collect();
        assert_eq!(ids.len(), ASSETS.len());
    }

    #[test]
    fn a_registered_asset_resolves_to_its_origin_network() {
        let btc = find(AssetId::Foreign(Network::Bitcoin, "BTC")).expect("bitcoin is registered");
        assert_eq!(btc.id.origin(), Some(Network::Bitcoin));
        assert_eq!(btc.decimals, 8);
    }

    #[test]
    fn the_native_asset_is_registered_with_no_foreign_origin() {
        let native = find(AssetId::Native).expect("the native asset is registered");
        assert_eq!(native.id.origin(), None);
    }

    #[test]
    fn an_unregistered_asset_does_not_resolve() {
        assert_eq!(find(AssetId::Foreign(Network::Bitcoin, "NOTREAL")), None);
    }

    #[test]
    fn a_network_can_host_more_than_one_asset() {
        let on_ethereum: Vec<_> = by_network(Network::Ethereum).collect();
        assert!(on_ethereum.len() > 1);
        assert!(on_ethereum
            .iter()
            .all(|a| a.id.origin() == Some(Network::Ethereum)));
    }

    #[test]
    fn every_one_of_the_thirty_seven_networks_has_a_native_coin_registered() {
        for network in Network::ALL {
            assert!(
                by_network(network).count() >= 1,
                "no registered asset for {:?}",
                network
            );
        }
    }

    #[test]
    fn robinhood_chain_assets_resolve_to_their_origin_network() {
        let entries: Vec<_> = by_network(Network::RobinhoodChain).collect();
        assert_eq!(entries.len(), 4);
        assert!(entries
            .iter()
            .all(|a| a.id.origin() == Some(Network::RobinhoodChain)));
        assert!(find(AssetId::Foreign(Network::RobinhoodChain, "RHC")).is_some());
        assert!(find(AssetId::Foreign(Network::RobinhoodChain, "ETH")).is_some());
        assert!(find(AssetId::Foreign(Network::RobinhoodChain, "USDC")).is_some());
        assert!(find(AssetId::Foreign(Network::RobinhoodChain, "RWA")).is_some());
    }
}
