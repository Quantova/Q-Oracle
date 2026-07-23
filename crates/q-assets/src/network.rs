#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Network {
    Bitcoin,
    BitcoinCash,
    Ethereum,
    BnbChain,
    Polygon,
    Avalanche,
    Arbitrum,
    Optimism,
    Fantom,
    Cosmos,
    Osmosis,
    Celestia,
    Injective,
    Polkadot,
    Kusama,
    Bittensor,
    Solana,
    Tron,
    Ripple,
    Cardano,
    Near,
    Sui,
    Aptos,
    Hedera,
    Algorand,
    Ton,
    Stellar,
    Monero,
    Litecoin,
    Dogecoin,
    Zcash,
    Sei,
    Kava,
    Filecoin,
    Celo,
    Cronos,
    RobinhoodChain,
}

impl Network {
    pub const ALL: [Network; 37] = [
        Network::Bitcoin,
        Network::BitcoinCash,
        Network::Ethereum,
        Network::BnbChain,
        Network::Polygon,
        Network::Avalanche,
        Network::Arbitrum,
        Network::Optimism,
        Network::Fantom,
        Network::Cosmos,
        Network::Osmosis,
        Network::Celestia,
        Network::Injective,
        Network::Polkadot,
        Network::Kusama,
        Network::Bittensor,
        Network::Solana,
        Network::Tron,
        Network::Ripple,
        Network::Cardano,
        Network::Near,
        Network::Sui,
        Network::Aptos,
        Network::Hedera,
        Network::Algorand,
        Network::Ton,
        Network::Stellar,
        Network::Monero,
        Network::Litecoin,
        Network::Dogecoin,
        Network::Zcash,
        Network::Sei,
        Network::Kava,
        Network::Filecoin,
        Network::Celo,
        Network::Cronos,
        Network::RobinhoodChain,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn there_are_thirty_seven_origin_networks() {
        assert_eq!(Network::ALL.len(), 37);
    }

    #[test]
    fn every_origin_network_is_distinct() {
        let set: BTreeSet<Network> = Network::ALL.iter().copied().collect();
        assert_eq!(set.len(), Network::ALL.len());
    }
}
