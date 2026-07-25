// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_codec::AssetId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Federated,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Federated => "Federated",
        }
    }

    pub fn is_federated(self) -> bool {
        matches!(self, Tier::Federated)
    }

    pub fn verifies_foreign_on_chain(self) -> bool {
        false
    }

    pub fn proof_backed(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustGrade {
    TrustedRelayer,
}

impl TrustGrade {
    pub fn label(self) -> &'static str {
        match self {
            TrustGrade::TrustedRelayer => "TrustedRelayer",
        }
    }
}

pub const BNB_CHAIN: u32 = 3;
pub const POLYGON: u32 = 4;
pub const AVALANCHE: u32 = 5;
pub const SOLANA: u32 = 22;
pub const TRON: u32 = 23;
pub const XRPL: u32 = 24;
pub const CARDANO: u32 = 25;
pub const NEAR: u32 = 26;
pub const SUI: u32 = 27;
pub const APTOS: u32 = 28;
pub const HEDERA: u32 = 29;
pub const ALGORAND: u32 = 30;
pub const TON: u32 = 31;
pub const STELLAR: u32 = 32;
pub const MONERO: u32 = 34;
pub const LITECOIN: u32 = 35;
pub const DOGECOIN: u32 = 36;
pub const ZCASH: u32 = 37;
pub const CCTP_USDC: u32 = 38;

pub const ORIGIN_MARKER: u8 = 0x0F;
pub const PROVISIONAL_CAP_BASE_UNITS: u128 = 1_000_000_000_000;

pub fn origin_tag(chain_id: u32) -> AssetId {
    let mut tag = [0u8; 16];
    let id = chain_id.to_le_bytes();
    tag[0..4].copy_from_slice(&id);
    tag[4] = b'Q';
    tag[5] = b'O';
    tag[6] = ORIGIN_MARKER;
    tag[7..11].copy_from_slice(&id);
    tag[11] = 0xF0;
    AssetId(tag)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corridor {
    pub chain_id: u32,
    pub name: &'static str,
    pub tier: Tier,
    pub grade: TrustGrade,
    pub confirmation_depth: u32,
    pub origin_asset: AssetId,
    pub cap_base_units: u128,
    pub active: bool,
}

impl Corridor {
    pub fn is_federated(&self) -> bool {
        self.tier.is_federated()
    }
}

fn corridor(chain_id: u32, name: &'static str, confirmation_depth: u32) -> Corridor {
    Corridor {
        chain_id,
        name,
        tier: Tier::Federated,
        grade: TrustGrade::TrustedRelayer,
        confirmation_depth,
        origin_asset: origin_tag(chain_id),
        cap_base_units: PROVISIONAL_CAP_BASE_UNITS,
        active: true,
    }
}

pub fn corridors() -> Vec<Corridor> {
    vec![
        corridor(BNB_CHAIN, "BNB Chain", 15),
        corridor(POLYGON, "Polygon", 128),
        corridor(AVALANCHE, "Avalanche", 1),
        corridor(SOLANA, "Solana", 32),
        corridor(TRON, "TRON", 19),
        corridor(XRPL, "XRP Ledger", 1),
        corridor(CARDANO, "Cardano", 12),
        corridor(NEAR, "Near", 2),
        corridor(SUI, "Sui", 1),
        corridor(APTOS, "Aptos", 1),
        corridor(HEDERA, "Hedera", 1),
        corridor(ALGORAND, "Algorand", 1),
        corridor(TON, "Ton", 1),
        corridor(STELLAR, "Stellar", 1),
        corridor(MONERO, "Monero", 10),
        corridor(LITECOIN, "Litecoin", 12),
        corridor(DOGECOIN, "Dogecoin", 30),
        corridor(ZCASH, "Zcash", 24),
        corridor(CCTP_USDC, "Circle CCTP USDC", 20),
    ]
}

pub fn find(chain_id: u32) -> Option<Corridor> {
    corridors().into_iter().find(|c| c.chain_id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_set_covers_nineteen_corridors() {
        assert_eq!(corridors().len(), 19);
    }

    #[test]
    fn bnb_chain_polygon_and_avalanche_keep_their_existing_canonical_ids() {
        assert_eq!(BNB_CHAIN, 3);
        assert_eq!(POLYGON, 4);
        assert_eq!(AVALANCHE, 5);
        assert_eq!(find(BNB_CHAIN).unwrap().name, "BNB Chain");
        assert_eq!(find(POLYGON).unwrap().name, "Polygon");
        assert_eq!(find(AVALANCHE).unwrap().name, "Avalanche");
    }

    #[test]
    fn every_corridor_is_labeled_federated_tier() {
        for c in corridors() {
            assert_eq!(c.tier, Tier::Federated);
            assert_eq!(c.tier.label(), "Federated");
            assert!(c.is_federated());
        }
    }

    #[test]
    fn every_corridor_is_the_trusted_relayer_grade() {
        for c in corridors() {
            assert_eq!(c.grade, TrustGrade::TrustedRelayer);
            assert_eq!(c.grade.label(), "TrustedRelayer");
        }
    }

    #[test]
    fn the_tier_verifies_nothing_foreign_and_carries_no_proof() {
        for c in corridors() {
            assert!(!c.tier.verifies_foreign_on_chain());
            assert!(!c.tier.proof_backed());
        }
    }

    #[test]
    fn named_corridors_resolve_to_their_chain_ids() {
        assert_eq!(find(SOLANA).unwrap().name, "Solana");
        assert_eq!(find(TRON).unwrap().name, "TRON");
        assert_eq!(find(CCTP_USDC).unwrap().name, "Circle CCTP USDC");
        assert_eq!(find(MONERO).unwrap().name, "Monero");
        assert!(find(9999).is_none());
    }

    #[test]
    fn chain_ids_do_not_collide() {
        let ids: BTreeSet<u32> = corridors().iter().map(|c| c.chain_id).collect();
        assert_eq!(ids.len(), corridors().len());
    }

    #[test]
    fn every_origin_tag_encodes_its_chain_id_and_is_non_zero() {
        for c in corridors() {
            assert_eq!(&c.origin_asset.0[0..4], &c.chain_id.to_le_bytes());
            assert_ne!(c.origin_asset.0, [0u8; 16]);
        }
    }

    #[test]
    fn origin_tags_are_distinct_across_corridors() {
        let tags: BTreeSet<[u8; 16]> = corridors().iter().map(|c| c.origin_asset.0).collect();
        assert_eq!(tags.len(), corridors().len());
    }

    #[test]
    fn confirmation_depths_are_set() {
        for c in corridors() {
            assert!(c.confirmation_depth >= 1);
        }
    }

    #[test]
    fn caps_are_base_units_and_non_zero() {
        for c in corridors() {
            let cap: u128 = c.cap_base_units;
            assert!(cap > 0);
        }
    }

    #[test]
    fn aligns_with_the_light_client_registry_ids_for_the_shared_names() {
        assert_eq!(BNB_CHAIN, 3);
        assert_eq!(POLYGON, 4);
        assert_eq!(AVALANCHE, 5);
        assert_eq!(SOLANA, 22);
        assert_eq!(TRON, 23);
        assert_eq!(XRPL, 24);
        assert_eq!(STELLAR, 32);
    }
}
