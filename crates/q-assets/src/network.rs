// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Network {
    Bitcoin = 0,
    BitcoinCash = 1,
    Ethereum = 2,
    BnbChain = 3,
    Polygon = 4,
    Avalanche = 5,
    Arbitrum = 6,
    Optimism = 7,
    Fantom = 9,
    Celo = 15,
    Cosmos = 16,
    Osmosis = 17,
    Celestia = 18,
    Injective = 19,
    Sei = 20,
    Kava = 21,
    Solana = 22,
    Tron = 23,
    Ripple = 24,
    Cardano = 25,
    Near = 26,
    Sui = 27,
    Aptos = 28,
    Hedera = 29,
    Algorand = 30,
    Ton = 31,
    Stellar = 32,
    RobinhoodChain = 33,
    Monero = 34,
    Litecoin = 35,
    Dogecoin = 36,
    Zcash = 37,
    Filecoin = 39,
    Cronos = 40,
}

impl Network {
    pub const ALL: [Network; 34] = [
        Network::Bitcoin,
        Network::BitcoinCash,
        Network::Ethereum,
        Network::BnbChain,
        Network::Polygon,
        Network::Avalanche,
        Network::Arbitrum,
        Network::Optimism,
        Network::Fantom,
        Network::Celo,
        Network::Cosmos,
        Network::Osmosis,
        Network::Celestia,
        Network::Injective,
        Network::Sei,
        Network::Kava,
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
        Network::RobinhoodChain,
        Network::Monero,
        Network::Litecoin,
        Network::Dogecoin,
        Network::Zcash,
        Network::Filecoin,
        Network::Cronos,
    ];

    pub fn id(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn there_are_thirty_four_origin_networks() {
        assert_eq!(Network::ALL.len(), 34);
    }

    #[test]
    fn every_origin_network_is_distinct() {
        let set: BTreeSet<Network> = Network::ALL.iter().copied().collect();
        assert_eq!(set.len(), Network::ALL.len());
    }

    #[test]
    fn every_origin_network_id_is_distinct() {
        let ids: BTreeSet<u32> = Network::ALL.iter().map(|n| n.id()).collect();
        assert_eq!(ids.len(), Network::ALL.len());
    }

    #[test]
    fn the_shared_ids_match_the_light_client_registry() {
        assert_eq!(Network::Bitcoin.id(), 0);
        assert_eq!(Network::Ethereum.id(), 2);
        assert_eq!(Network::Solana.id(), 22);
        assert_eq!(Network::Tron.id(), 23);
        assert_eq!(Network::Ripple.id(), 24);
        assert_eq!(Network::RobinhoodChain.id(), 33);
    }
}
