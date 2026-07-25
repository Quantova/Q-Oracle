// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use crate::asset::AssetId;
use crate::errors::AssetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetCaps {
    pub mint_cap: u128,
    pub unlock_cap: u128,
}

pub struct AssetLedger {
    caps: BTreeMap<AssetId, AssetCaps>,
    minted: BTreeMap<AssetId, u128>,
    escrowed: BTreeMap<AssetId, u128>,
    epoch_cap: u128,
    epoch_minted: u128,
    epoch: u64,
}

impl AssetLedger {
    pub fn new(epoch_cap: u128) -> AssetLedger {
        AssetLedger {
            caps: BTreeMap::new(),
            minted: BTreeMap::new(),
            escrowed: BTreeMap::new(),
            epoch_cap,
            epoch_minted: 0,
            epoch: 0,
        }
    }

    pub fn set_caps(&mut self, asset_id: AssetId, caps: AssetCaps) {
        self.caps.insert(asset_id, caps);
    }

    pub fn caps_of(&self, asset_id: AssetId) -> Option<AssetCaps> {
        self.caps.get(&asset_id).copied()
    }

    pub fn credit_escrow(&mut self, asset_id: AssetId, amount: u128) {
        let entry = self.escrowed.entry(asset_id).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    pub fn minted_of(&self, asset_id: AssetId) -> u128 {
        *self.minted.get(&asset_id).unwrap_or(&0)
    }

    pub fn escrowed_of(&self, asset_id: AssetId) -> u128 {
        *self.escrowed.get(&asset_id).unwrap_or(&0)
    }

    pub fn epoch_minted(&self) -> u128 {
        self.epoch_minted
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn advance_epoch(&mut self) {
        self.epoch += 1;
        self.epoch_minted = 0;
    }

    pub fn invariant_holds(&self, asset_id: AssetId) -> bool {
        self.escrowed_of(asset_id) >= self.minted_of(asset_id)
    }

    pub fn mint(&mut self, asset_id: AssetId, amount: u128) -> Result<(), AssetError> {
        if amount == 0 {
            return Err(AssetError::ZeroAmount);
        }
        let caps = self
            .caps
            .get(&asset_id)
            .copied()
            .ok_or(AssetError::AssetNotRegistered)?;
        let minted = self.minted_of(asset_id);
        let minted_after = minted
            .checked_add(amount)
            .ok_or(AssetError::MintCapExceeded {
                minted,
                cap: caps.mint_cap,
                add: amount,
            })?;
        if minted_after > caps.mint_cap {
            return Err(AssetError::MintCapExceeded {
                minted,
                cap: caps.mint_cap,
                add: amount,
            });
        }
        let epoch_after =
            self.epoch_minted
                .checked_add(amount)
                .ok_or(AssetError::EpochCapExceeded {
                    minted: self.epoch_minted,
                    cap: self.epoch_cap,
                    add: amount,
                })?;
        if epoch_after > self.epoch_cap {
            return Err(AssetError::EpochCapExceeded {
                minted: self.epoch_minted,
                cap: self.epoch_cap,
                add: amount,
            });
        }
        let escrowed = self.escrowed_of(asset_id);
        if minted_after > escrowed {
            return Err(AssetError::EscrowInvariantBroken {
                escrowed,
                minted_after,
            });
        }
        self.minted.insert(asset_id, minted_after);
        self.epoch_minted = epoch_after;
        Ok(())
    }

    pub fn burn(&mut self, asset_id: AssetId, amount: u128) -> Result<(), AssetError> {
        if amount == 0 {
            return Err(AssetError::ZeroAmount);
        }
        let caps = self
            .caps
            .get(&asset_id)
            .copied()
            .ok_or(AssetError::AssetNotRegistered)?;
        if amount > caps.unlock_cap {
            return Err(AssetError::UnlockCapExceeded {
                amount,
                cap: caps.unlock_cap,
            });
        }
        let minted = self.minted_of(asset_id);
        if amount > minted {
            return Err(AssetError::InsufficientMinted { minted, amount });
        }
        let escrowed = self.escrowed_of(asset_id);
        self.minted.insert(asset_id, minted - amount);
        self.escrowed
            .insert(asset_id, escrowed.saturating_sub(amount));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;

    fn asset() -> AssetId {
        AssetId::Foreign(Network::Bitcoin, "BTC")
    }

    fn ledger() -> AssetLedger {
        let mut l = AssetLedger::new(10_000);
        l.set_caps(
            asset(),
            AssetCaps {
                mint_cap: 1_000,
                unlock_cap: 500,
            },
        );
        l.credit_escrow(asset(), 2_000);
        l
    }

    #[test]
    fn a_mint_beyond_the_per_asset_cap_is_rejected() {
        let mut l = ledger();
        assert_eq!(
            l.mint(asset(), 1_001),
            Err(AssetError::MintCapExceeded {
                minted: 0,
                cap: 1_000,
                add: 1_001
            })
        );
        assert_eq!(l.minted_of(asset()), 0);
    }

    #[test]
    fn a_mint_beyond_the_global_epoch_cap_is_rejected() {
        let mut l = AssetLedger::new(700);
        l.set_caps(
            asset(),
            AssetCaps {
                mint_cap: 1_000,
                unlock_cap: 500,
            },
        );
        l.credit_escrow(asset(), 1_000);
        assert_eq!(
            l.mint(asset(), 701),
            Err(AssetError::EpochCapExceeded {
                minted: 0,
                cap: 700,
                add: 701
            })
        );
        assert_eq!(l.epoch_minted(), 0);
    }

    #[test]
    fn a_burn_frees_mint_headroom() {
        let mut l = ledger();
        l.mint(asset(), 1_000)
            .expect("escrow and the cap allow the full mint");
        assert_eq!(
            l.mint(asset(), 1),
            Err(AssetError::MintCapExceeded {
                minted: 1_000,
                cap: 1_000,
                add: 1
            })
        );
        l.burn(asset(), 400)
            .expect("minted covers the burn and it is under the unlock cap");
        assert_eq!(l.minted_of(asset()), 600);
        l.mint(asset(), 300)
            .expect("the burn freed headroom under the mint cap");
        assert_eq!(l.minted_of(asset()), 900);
    }

    #[test]
    fn the_escrow_invariant_holds_across_a_sequence_and_rejects_a_mint_that_would_break_it() {
        let mut l = AssetLedger::new(10_000);
        l.set_caps(
            asset(),
            AssetCaps {
                mint_cap: 10_000,
                unlock_cap: 10_000,
            },
        );
        l.credit_escrow(asset(), 500);

        l.mint(asset(), 300).expect("escrow covers the mint");
        assert!(l.invariant_holds(asset()));

        l.burn(asset(), 100).expect("minted covers the burn");
        assert!(l.invariant_holds(asset()));
        assert_eq!(l.minted_of(asset()), 200);
        assert_eq!(l.escrowed_of(asset()), 400);

        l.mint(asset(), 200).expect("escrow still covers the mint");
        assert!(l.invariant_holds(asset()));
        assert_eq!(l.minted_of(asset()), 400);

        assert_eq!(
            l.mint(asset(), 1),
            Err(AssetError::EscrowInvariantBroken {
                escrowed: 400,
                minted_after: 401
            })
        );
        assert!(l.invariant_holds(asset()));
    }

    #[test]
    fn minting_an_unregistered_asset_is_rejected() {
        let mut l = AssetLedger::new(10_000);
        assert_eq!(l.mint(asset(), 1), Err(AssetError::AssetNotRegistered));
    }

    #[test]
    fn a_burn_beyond_the_unlock_cap_is_rejected() {
        let mut l = ledger();
        l.mint(asset(), 600)
            .expect("escrow and the cap allow this mint");
        assert_eq!(
            l.burn(asset(), 501),
            Err(AssetError::UnlockCapExceeded {
                amount: 501,
                cap: 500
            })
        );
    }

    #[test]
    fn a_burn_beyond_the_minted_balance_is_rejected() {
        let mut l = ledger();
        l.mint(asset(), 100)
            .expect("escrow and the cap allow this mint");
        assert_eq!(
            l.burn(asset(), 150),
            Err(AssetError::InsufficientMinted {
                minted: 100,
                amount: 150
            })
        );
    }

    #[test]
    fn advancing_the_epoch_resets_the_epoch_counter_but_not_minted_supply() {
        let mut l = ledger();
        l.mint(asset(), 500).expect("within the cap and the escrow");
        l.advance_epoch();
        assert_eq!(l.epoch_minted(), 0);
        assert_eq!(l.minted_of(asset()), 500);
        assert_eq!(l.epoch(), 1);
    }
}
