// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use q_assets::registry::ASSETS;
use q_assets::Network;
use q_codec::AssetId;
use q_gateway::Gateway;
use qtv_crypto::sha3::sha3_256;

use crate::corridors::{origin_tag, Corridor, Tier, TrustGrade, PROVISIONAL_CAP_BASE_UNITS};

pub const POOL_ASSET_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/POOL-ASSET/v1";
pub const MIN_IDENTIFIER_LEN: usize = 1;
pub const MAX_IDENTIFIER_LEN: usize = 64;
pub const MAX_DECIMALS: u8 = 36;
pub const MIN_CAP: u128 = 1;
pub const MAX_CAP: u128 = u128::MAX >> 1;
pub const DEFAULT_CONFIRMATION_DEPTH: u32 = 32;
pub const MAX_POOLS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    UnknownNetwork(u32),
    MalformedIdentifier,
    DecimalsTooLarge { decimals: u8, max: u8 },
    ZeroCap,
    CapTooLarge { cap: u128, max: u128 },
    EpochCapAboveAssetCap { epoch: u128, asset: u128 },
    DuplicatePool,
    AssetIdMismatch,
    TierMismatch,
    RegistryFull { max: usize },
}

pub fn derive_asset_id(network: Network, identifier: &str) -> AssetId {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(POOL_ASSET_DOMAIN);
    preimage.extend_from_slice(&network.id().to_le_bytes());
    preimage.extend_from_slice(&(identifier.len() as u32).to_le_bytes());
    preimage.extend_from_slice(identifier.as_bytes());
    let digest = sha3_256(&preimage);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&digest[..16]);
    AssetId(tag)
}

pub fn tier_for(network: Network) -> Tier {
    match network {
        Network::Bitcoin | Network::Ethereum | Network::Cosmos => Tier::ProofBacked,
        _ => Tier::Federated,
    }
}

pub fn native_asset(network: Network) -> Option<AssetId> {
    let identifier = match network {
        Network::Bitcoin => "BTC",
        Network::Ethereum => "ETH",
        Network::Cosmos => "ATOM",
        _ => return None,
    };
    Some(derive_asset_id(network, identifier))
}

pub fn grade_for(network: Network) -> TrustGrade {
    match tier_for(network) {
        Tier::ProofBacked => TrustGrade::Trustless,
        Tier::Federated => TrustGrade::TrustedRelayer,
    }
}

pub fn depth_for(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 6,
        Network::Ethereum => 64,
        Network::Cosmos => 2,
        other => crate::corridors::find(other.id())
            .map(|c| c.confirmation_depth)
            .unwrap_or(DEFAULT_CONFIRMATION_DEPTH),
    }
}

pub fn corridor_for(network: Network, cap_base_units: u128) -> Corridor {
    let tier = tier_for(network);
    Corridor {
        chain_id: network.id(),
        name: network.name(),
        tier,
        grade: grade_for(network),
        confirmation_depth: depth_for(network),
        origin_asset: native_asset(network).unwrap_or_else(|| origin_tag(network.id())),
        cap_base_units,
        active: true,
    }
}

pub fn identifier_is_wellformed(identifier: &str) -> bool {
    let len = identifier.len();
    if !(MIN_IDENTIFIER_LEN..=MAX_IDENTIFIER_LEN).contains(&len) {
        return false;
    }
    let bytes = identifier.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_alphanumeric();
    let is_separator = |b: u8| matches!(b, b'.' | b'_' | b'-' | b':');
    if !is_alnum(bytes[0]) || !is_alnum(bytes[len - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || is_separator(b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSpec {
    pub network: Network,
    pub identifier: String,
    pub decimals: u8,
    pub asset_id: AssetId,
    pub per_asset_cap: u128,
    pub per_epoch_cap: u128,
    pub tier: Tier,
}

impl PoolSpec {
    pub fn derive(
        network: Network,
        identifier: &str,
        decimals: u8,
        per_asset_cap: u128,
        per_epoch_cap: u128,
    ) -> PoolSpec {
        PoolSpec {
            network,
            identifier: identifier.to_string(),
            decimals,
            asset_id: derive_asset_id(network, identifier),
            per_asset_cap,
            per_epoch_cap,
            tier: tier_for(network),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRequest {
    pub network_id: u32,
    pub identifier: String,
    pub decimals: u8,
    pub per_asset_cap: u128,
    pub per_epoch_cap: u128,
}

pub struct PoolRegistry {
    by_asset: BTreeMap<[u8; 16], PoolSpec>,
    by_key: BTreeMap<(u32, String), [u8; 16]>,
}

impl PoolRegistry {
    pub fn new() -> PoolRegistry {
        PoolRegistry {
            by_asset: BTreeMap::new(),
            by_key: BTreeMap::new(),
        }
    }

    pub fn seeded() -> PoolRegistry {
        let mut registry = PoolRegistry::new();
        for record in ASSETS {
            let network = match record.id.origin() {
                Some(network) => network,
                None => continue,
            };
            let identifier = record
                .id
                .identifier()
                .expect("a foreign asset carries an identifier");
            let spec = PoolSpec::derive(
                network,
                identifier,
                record.decimals,
                PROVISIONAL_CAP_BASE_UNITS,
                PROVISIONAL_CAP_BASE_UNITS,
            );
            registry
                .register(spec)
                .expect("every enumerated asset is a well-formed pool");
        }
        registry
    }

    fn validate(&self, spec: &PoolSpec) -> Result<(), PoolError> {
        if !identifier_is_wellformed(&spec.identifier) {
            return Err(PoolError::MalformedIdentifier);
        }
        if spec.decimals > MAX_DECIMALS {
            return Err(PoolError::DecimalsTooLarge {
                decimals: spec.decimals,
                max: MAX_DECIMALS,
            });
        }
        if spec.per_asset_cap < MIN_CAP || spec.per_epoch_cap < MIN_CAP {
            return Err(PoolError::ZeroCap);
        }
        if spec.per_asset_cap > MAX_CAP {
            return Err(PoolError::CapTooLarge {
                cap: spec.per_asset_cap,
                max: MAX_CAP,
            });
        }
        if spec.per_epoch_cap > MAX_CAP {
            return Err(PoolError::CapTooLarge {
                cap: spec.per_epoch_cap,
                max: MAX_CAP,
            });
        }
        if spec.per_epoch_cap > spec.per_asset_cap {
            return Err(PoolError::EpochCapAboveAssetCap {
                epoch: spec.per_epoch_cap,
                asset: spec.per_asset_cap,
            });
        }
        if spec.asset_id != derive_asset_id(spec.network, &spec.identifier) {
            return Err(PoolError::AssetIdMismatch);
        }
        if spec.tier != tier_for(spec.network) {
            return Err(PoolError::TierMismatch);
        }
        let key = (spec.network.id(), spec.identifier.clone());
        if self.by_asset.contains_key(&spec.asset_id.0) || self.by_key.contains_key(&key) {
            return Err(PoolError::DuplicatePool);
        }
        Ok(())
    }

    pub fn register(&mut self, spec: PoolSpec) -> Result<(), PoolError> {
        if self.by_asset.len() >= MAX_POOLS {
            return Err(PoolError::RegistryFull { max: MAX_POOLS });
        }
        self.validate(&spec)?;
        let key = (spec.network.id(), spec.identifier.clone());
        self.by_key.insert(key, spec.asset_id.0);
        self.by_asset.insert(spec.asset_id.0, spec);
        Ok(())
    }

    pub fn create_pool(&mut self, request: &PoolRequest) -> Result<PoolSpec, PoolError> {
        let network =
            Network::from_id(request.network_id).ok_or(PoolError::UnknownNetwork(request.network_id))?;
        let spec = PoolSpec::derive(
            network,
            &request.identifier,
            request.decimals,
            request.per_asset_cap,
            request.per_epoch_cap,
        );
        self.register(spec.clone())?;
        Ok(spec)
    }

    pub fn get(&self, asset_id: &[u8; 16]) -> Option<&PoolSpec> {
        self.by_asset.get(asset_id)
    }

    pub fn get_by_identifier(&self, network: Network, identifier: &str) -> Option<&PoolSpec> {
        let asset = self.by_key.get(&(network.id(), identifier.to_string()))?;
        self.by_asset.get(asset)
    }

    pub fn contains(&self, asset_id: &[u8; 16]) -> bool {
        self.by_asset.contains_key(asset_id)
    }

    pub fn by_network(&self, network: Network) -> Vec<&PoolSpec> {
        self.by_asset
            .values()
            .filter(|spec| spec.network == network)
            .collect()
    }

    pub fn all(&self) -> impl Iterator<Item = &PoolSpec> {
        self.by_asset.values()
    }

    pub fn len(&self) -> usize {
        self.by_asset.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_asset.is_empty()
    }
}

impl Default for PoolRegistry {
    fn default() -> PoolRegistry {
        PoolRegistry::new()
    }
}

pub fn install_pool(gateway: &mut Gateway, spec: &PoolSpec) {
    gateway.register_corridor(spec.network.id(), depth_for(spec.network));
    gateway.register_asset_cap(spec.asset_id.0, spec.per_asset_cap);
    gateway.register_asset_epoch_cap(spec.asset_id.0, spec.per_epoch_cap);
}

pub fn install_all(gateway: &mut Gateway, registry: &PoolRegistry) {
    for spec in registry.all() {
        install_pool(gateway, spec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_ID: u64 = 0x0000_002a_0000_2328;

    fn request(network_id: u32, identifier: &str) -> PoolRequest {
        PoolRequest {
            network_id,
            identifier: identifier.to_string(),
            decimals: 18,
            per_asset_cap: 1_000_000,
            per_epoch_cap: 500_000,
        }
    }

    #[test]
    fn a_derived_asset_id_is_deterministic_and_binds_network_and_identifier() {
        let a = derive_asset_id(Network::Ethereum, "USDC");
        assert_eq!(a, derive_asset_id(Network::Ethereum, "USDC"));
        assert_ne!(a, derive_asset_id(Network::Solana, "USDC"));
        assert_ne!(a, derive_asset_id(Network::Ethereum, "USDT"));
        assert_ne!(a.0, [0u8; 16]);
    }

    #[test]
    fn the_identifier_length_prefix_removes_boundary_collisions() {
        assert_ne!(
            derive_asset_id(Network::Ethereum, "ABC"),
            derive_asset_id(Network::Ethereum, "AB"),
        );
    }

    #[test]
    fn the_three_verifier_networks_are_proof_backed_and_the_rest_federated() {
        assert_eq!(tier_for(Network::Bitcoin), Tier::ProofBacked);
        assert_eq!(tier_for(Network::Ethereum), Tier::ProofBacked);
        assert_eq!(tier_for(Network::Cosmos), Tier::ProofBacked);
        assert_eq!(tier_for(Network::Solana), Tier::Federated);
        assert_eq!(tier_for(Network::BitcoinCash), Tier::Federated);
        assert_eq!(tier_for(Network::Osmosis), Tier::Federated);
    }

    #[test]
    fn a_registered_pool_reads_back_by_asset_and_by_identifier() {
        let mut registry = PoolRegistry::new();
        let spec = registry
            .create_pool(&request(Network::Polygon.id(), "GHO"))
            .expect("a fresh token lists");
        assert_eq!(registry.get(&spec.asset_id.0), Some(&spec));
        assert_eq!(
            registry.get_by_identifier(Network::Polygon, "GHO"),
            Some(&spec)
        );
        assert_eq!(spec.tier, Tier::Federated);
        assert_eq!(spec.asset_id, derive_asset_id(Network::Polygon, "GHO"));
    }

    #[test]
    fn pool_creation_is_bounded_by_the_registry_cap() {
        let mut registry = PoolRegistry::new();
        for i in 0..MAX_POOLS {
            registry
                .create_pool(&request(Network::Polygon.id(), &format!("T{i}")))
                .unwrap_or_else(|e| panic!("pool {i} lists under the cap, got {e:?}"));
        }
        assert_eq!(registry.len(), MAX_POOLS);
        assert_eq!(
            registry.create_pool(&request(Network::Polygon.id(), "OVERFLOW")),
            Err(PoolError::RegistryFull { max: MAX_POOLS }),
            "creation past the cap is refused"
        );
        assert_eq!(registry.len(), MAX_POOLS);
    }

    #[test]
    fn a_birthday_collision_on_the_truncated_id_leaves_the_second_asset_unregisterable() {
        let mut registry = PoolRegistry::new();

        let gho = PoolSpec::derive(Network::Polygon, "GHO", 18, 1_000_000, 500_000);

        let other = PoolSpec::derive(Network::Ethereum, "WBTC", 8, 1_000_000, 500_000);
        registry.by_asset.insert(gho.asset_id.0, other.clone());
        registry
            .by_key
            .insert((other.network.id(), other.identifier.clone()), gho.asset_id.0);

        assert!(!registry
            .by_key
            .contains_key(&(Network::Polygon.id(), "GHO".to_string())));
        assert_eq!(
            registry.register(gho),
            Err(PoolError::DuplicatePool),
            "the id is already taken, so the colliding asset is refused, not aliased"
        );
    }

    #[test]
    fn a_duplicate_pool_is_rejected() {
        let mut registry = PoolRegistry::new();
        registry
            .create_pool(&request(Network::Polygon.id(), "GHO"))
            .expect("first listing succeeds");
        assert_eq!(
            registry.create_pool(&request(Network::Polygon.id(), "GHO")),
            Err(PoolError::DuplicatePool)
        );
    }

    #[test]
    fn an_unknown_network_is_rejected() {
        let mut registry = PoolRegistry::new();
        assert_eq!(
            registry.create_pool(&request(44, "GHO")),
            Err(PoolError::UnknownNetwork(44))
        );
        assert_eq!(
            registry.create_pool(&request(999, "GHO")),
            Err(PoolError::UnknownNetwork(999))
        );
    }

    #[test]
    fn a_malformed_identifier_is_rejected() {
        let mut registry = PoolRegistry::new();
        for bad in ["", " GHO", "GHO ", "-GHO", "GHO-", "gh o", "na\u{00e9}me"] {
            assert_eq!(
                registry.create_pool(&request(Network::Polygon.id(), bad)),
                Err(PoolError::MalformedIdentifier),
                "identifier {:?} should be rejected",
                bad
            );
        }
        let long = "A".repeat(MAX_IDENTIFIER_LEN + 1);
        assert_eq!(
            registry.create_pool(&request(Network::Polygon.id(), &long)),
            Err(PoolError::MalformedIdentifier)
        );
    }

    #[test]
    fn a_zero_cap_is_rejected() {
        let mut registry = PoolRegistry::new();
        let mut req = request(Network::Polygon.id(), "GHO");
        req.per_asset_cap = 0;
        assert_eq!(registry.create_pool(&req), Err(PoolError::ZeroCap));
        let mut req = request(Network::Polygon.id(), "GHO");
        req.per_epoch_cap = 0;
        assert_eq!(registry.create_pool(&req), Err(PoolError::ZeroCap));
    }

    #[test]
    fn an_oversized_cap_is_rejected() {
        let mut registry = PoolRegistry::new();
        let mut req = request(Network::Polygon.id(), "GHO");
        req.per_asset_cap = MAX_CAP + 1;
        req.per_epoch_cap = MAX_CAP + 1;
        assert_eq!(
            registry.create_pool(&req),
            Err(PoolError::CapTooLarge {
                cap: MAX_CAP + 1,
                max: MAX_CAP
            })
        );
    }

    #[test]
    fn an_epoch_cap_above_the_asset_cap_is_rejected() {
        let mut registry = PoolRegistry::new();
        let mut req = request(Network::Polygon.id(), "GHO");
        req.per_asset_cap = 1_000;
        req.per_epoch_cap = 1_001;
        assert_eq!(
            registry.create_pool(&req),
            Err(PoolError::EpochCapAboveAssetCap {
                epoch: 1_001,
                asset: 1_000
            })
        );
    }

    #[test]
    fn decimals_beyond_the_ceiling_are_rejected() {
        let mut registry = PoolRegistry::new();
        let mut req = request(Network::Polygon.id(), "GHO");
        req.decimals = MAX_DECIMALS + 1;
        assert_eq!(
            registry.create_pool(&req),
            Err(PoolError::DecimalsTooLarge {
                decimals: MAX_DECIMALS + 1,
                max: MAX_DECIMALS
            })
        );
    }

    #[test]
    fn a_spec_with_a_smuggled_asset_id_is_rejected() {
        let mut registry = PoolRegistry::new();
        let mut spec = PoolSpec::derive(Network::Polygon, "GHO", 18, 1_000, 1_000);
        spec.asset_id = AssetId([0x99; 16]);
        assert_eq!(registry.register(spec), Err(PoolError::AssetIdMismatch));
    }

    #[test]
    fn a_spec_with_a_smuggled_tier_is_rejected() {
        let mut registry = PoolRegistry::new();
        let mut spec = PoolSpec::derive(Network::Polygon, "GHO", 18, 1_000, 1_000);
        spec.tier = Tier::ProofBacked;
        assert_eq!(registry.register(spec), Err(PoolError::TierMismatch));
    }

    #[test]
    fn the_seed_set_lists_every_enumerated_foreign_asset() {
        let registry = PoolRegistry::seeded();
        let foreign = ASSETS.iter().filter(|a| a.id.is_foreign()).count();
        assert!(foreign >= 70, "there are {} foreign assets", foreign);
        assert_eq!(registry.len(), foreign);
        for record in ASSETS {
            if let Some(network) = record.id.origin() {
                let identifier = record.id.identifier().unwrap();
                let spec = registry
                    .get_by_identifier(network, identifier)
                    .unwrap_or_else(|| panic!("{:?} {} is a seeded pool", network, identifier));
                assert_eq!(spec.decimals, record.decimals);
                assert_eq!(spec.asset_id, derive_asset_id(network, identifier));
            }
        }
    }

    #[test]
    fn every_seed_network_has_a_pool_and_the_tier_matches_the_network() {
        let registry = PoolRegistry::seeded();
        for network in Network::ALL {
            assert!(
                !registry.by_network(network).is_empty(),
                "no seeded pool for {:?}",
                network
            );
        }
        for spec in registry.all() {
            assert_eq!(spec.tier, tier_for(spec.network));
        }
        assert_eq!(
            registry.get_by_identifier(Network::Bitcoin, "BTC").unwrap().tier,
            Tier::ProofBacked
        );
        assert_eq!(
            registry.get_by_identifier(Network::Ethereum, "ETH").unwrap().tier,
            Tier::ProofBacked
        );
        assert_eq!(
            registry.get_by_identifier(Network::Cosmos, "ATOM").unwrap().tier,
            Tier::ProofBacked
        );
        assert_eq!(
            registry.get_by_identifier(Network::Solana, "SOL").unwrap().tier,
            Tier::Federated
        );
    }

    #[test]
    fn listing_a_new_token_on_a_seeded_network_succeeds_but_a_seed_duplicate_fails() {
        let mut registry = PoolRegistry::seeded();
        assert_eq!(
            registry.create_pool(&request(Network::Bitcoin.id(), "BTC")),
            Err(PoolError::DuplicatePool)
        );
        let spec = registry
            .create_pool(&request(Network::Ethereum.id(), "GHO"))
            .expect("a brand new ethereum token lists");
        assert_eq!(spec.tier, Tier::ProofBacked);
        assert_eq!(spec.network, Network::Ethereum);
    }

    #[test]
    fn installing_a_pool_registers_its_corridor_and_asset_cap_on_the_gateway() {
        use q_gateway::OperatorSet;
        let mut registry = PoolRegistry::new();
        let spec = registry
            .create_pool(&request(Network::Bitcoin.id(), "BTC"))
            .expect("bitcoin pool lists");
        let mut gateway = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000_000);
        install_pool(&mut gateway, &spec);
        assert_eq!(gateway.asset_cap(&spec.asset_id.0), Some(spec.per_asset_cap));
        assert!(gateway.corridor_tier(Network::Bitcoin.id()).is_some());
    }

    #[test]
    fn a_corridor_built_for_a_network_carries_its_tier_and_depth() {
        let btc = corridor_for(Network::Bitcoin, 1_000);
        assert_eq!(btc.tier, Tier::ProofBacked);
        assert_eq!(btc.grade, TrustGrade::Trustless);
        assert_eq!(btc.confirmation_depth, 6);
        assert_eq!(btc.chain_id, Network::Bitcoin.id());

        let sol = corridor_for(Network::Solana, 1_000);
        assert_eq!(sol.tier, Tier::Federated);
        assert_eq!(sol.grade, TrustGrade::TrustedRelayer);
    }
}
