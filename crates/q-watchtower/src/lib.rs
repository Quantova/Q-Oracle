#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use q_gateway::Gateway;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breach {
    pub asset_id: [u8; 16],
    pub minted: u128,
    pub escrowed: u128,
}

pub trait ReserveView {
    fn escrow_of(&self, asset_id: &[u8; 16]) -> u128;
    fn assets(&self) -> Vec<[u8; 16]>;
}

pub struct StaticReserves {
    escrow: BTreeMap<[u8; 16], u128>,
}

impl StaticReserves {
    pub fn new() -> StaticReserves {
        StaticReserves {
            escrow: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, asset_id: [u8; 16], escrowed: u128) {
        self.escrow.insert(asset_id, escrowed);
    }
}

impl Default for StaticReserves {
    fn default() -> StaticReserves {
        StaticReserves::new()
    }
}

impl ReserveView for StaticReserves {
    fn escrow_of(&self, asset_id: &[u8; 16]) -> u128 {
        *self.escrow.get(asset_id).unwrap_or(&0)
    }

    fn assets(&self) -> Vec<[u8; 16]> {
        self.escrow.keys().copied().collect()
    }
}

pub struct Watchtower;

impl Watchtower {
    pub fn audit<R: ReserveView>(minted: &BTreeMap<[u8; 16], u128>, reserves: &R) -> Vec<Breach> {
        let mut breaches = Vec::new();
        for (asset_id, minted_amount) in minted {
            let escrowed = reserves.escrow_of(asset_id);
            if *minted_amount > escrowed {
                breaches.push(Breach {
                    asset_id: *asset_id,
                    minted: *minted_amount,
                    escrowed,
                });
            }
        }
        breaches
    }

    pub fn enforce<R: ReserveView>(gateway: &mut Gateway, reserves: &R) -> Vec<Breach> {
        let breaches = Watchtower::audit(gateway.minted_by_asset(), reserves);
        if !breaches.is_empty() {
            gateway.pause_all();
        }
        breaches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_reserves_do_not_pause() {
        let mut minted = BTreeMap::new();
        minted.insert([1u8; 16], 100u128);
        let mut reserves = StaticReserves::new();
        reserves.set([1u8; 16], 100);
        assert!(Watchtower::audit(&minted, &reserves).is_empty());
    }

    #[test]
    fn undercollateralized_asset_is_a_breach() {
        let mut minted = BTreeMap::new();
        minted.insert([1u8; 16], 150u128);
        let mut reserves = StaticReserves::new();
        reserves.set([1u8; 16], 100);
        let breaches = Watchtower::audit(&minted, &reserves);
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].minted, 150);
        assert_eq!(breaches[0].escrowed, 100);
    }
}
