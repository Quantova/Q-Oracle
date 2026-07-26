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

    pub fn from_id(id: u32) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.id() == id)
    }

    pub fn name(self) -> &'static str {
        match self {
            Network::Bitcoin => "Bitcoin",
            Network::BitcoinCash => "Bitcoin Cash",
            Network::Ethereum => "Ethereum",
            Network::BnbChain => "BNB Chain",
            Network::Polygon => "Polygon",
            Network::Avalanche => "Avalanche",
            Network::Arbitrum => "Arbitrum",
            Network::Optimism => "Optimism",
            Network::Fantom => "Fantom",
            Network::Celo => "Celo",
            Network::Cosmos => "Cosmos",
            Network::Osmosis => "Osmosis",
            Network::Celestia => "Celestia",
            Network::Injective => "Injective",
            Network::Sei => "Sei",
            Network::Kava => "Kava",
            Network::Solana => "Solana",
            Network::Tron => "Tron",
            Network::Ripple => "Ripple",
            Network::Cardano => "Cardano",
            Network::Near => "Near",
            Network::Sui => "Sui",
            Network::Aptos => "Aptos",
            Network::Hedera => "Hedera",
            Network::Algorand => "Algorand",
            Network::Ton => "Ton",
            Network::Stellar => "Stellar",
            Network::RobinhoodChain => "Robinhood Chain",
            Network::Monero => "Monero",
            Network::Litecoin => "Litecoin",
            Network::Dogecoin => "Dogecoin",
            Network::Zcash => "Zcash",
            Network::Filecoin => "Filecoin",
            Network::Cronos => "Cronos",
        }
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
    fn every_network_round_trips_through_its_id() {
        for network in Network::ALL {
            assert_eq!(Network::from_id(network.id()), Some(network));
        }
    }

    #[test]
    fn an_id_outside_the_registry_resolves_to_nothing() {
        assert_eq!(Network::from_id(8), None);
        assert_eq!(Network::from_id(999), None);
    }

    #[test]
    fn every_network_has_a_non_empty_distinct_name() {
        let names: BTreeSet<&'static str> = Network::ALL.iter().map(|n| n.name()).collect();
        assert_eq!(names.len(), Network::ALL.len());
        assert!(Network::ALL.iter().all(|n| !n.name().is_empty()));
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
