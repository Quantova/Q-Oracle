// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use crate::errors::ExitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vault {
    pub vault_id: u32,
    pub free: u128,
    pub locked: u128,
}

pub struct VaultBook {
    vaults: BTreeMap<u32, Vault>,
}

impl VaultBook {
    pub fn new() -> VaultBook {
        VaultBook {
            vaults: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, vault_id: u32, collateral: u128) {
        let entry = self.vaults.entry(vault_id).or_insert(Vault {
            vault_id,
            free: 0,
            locked: 0,
        });
        entry.free = entry.free.saturating_add(collateral);
    }

    pub fn contains(&self, vault_id: u32) -> bool {
        self.vaults.contains_key(&vault_id)
    }

    pub fn free_of(&self, vault_id: u32) -> u128 {
        self.vaults.get(&vault_id).map(|v| v.free).unwrap_or(0)
    }

    pub fn locked_of(&self, vault_id: u32) -> u128 {
        self.vaults.get(&vault_id).map(|v| v.locked).unwrap_or(0)
    }

    pub fn lock(&mut self, vault_id: u32, amount: u128) -> Result<(), ExitError> {
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or(ExitError::UnknownVault(vault_id))?;
        if vault.free < amount {
            return Err(ExitError::ThinVault {
                have: vault.free,
                need: amount,
            });
        }
        vault.free -= amount;
        vault.locked = vault.locked.checked_add(amount).ok_or(ExitError::Overflow)?;
        Ok(())
    }

    pub fn release(&mut self, vault_id: u32, amount: u128) -> Result<(), ExitError> {
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or(ExitError::UnknownVault(vault_id))?;
        vault.locked = vault.locked.checked_sub(amount).ok_or(ExitError::Overflow)?;
        vault.free = vault.free.checked_add(amount).ok_or(ExitError::Overflow)?;
        Ok(())
    }

    pub fn seize(&mut self, vault_id: u32, amount: u128) -> Result<(), ExitError> {
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or(ExitError::UnknownVault(vault_id))?;
        vault.locked = vault.locked.checked_sub(amount).ok_or(ExitError::Overflow)?;
        Ok(())
    }
}

impl Default for VaultBook {
    fn default() -> VaultBook {
        VaultBook::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_credits_free_collateral() {
        let mut book = VaultBook::new();
        book.register(1, 300);
        assert!(book.contains(1));
        assert_eq!(book.free_of(1), 300);
        assert_eq!(book.locked_of(1), 0);
    }

    #[test]
    fn register_tops_up_an_existing_vault() {
        let mut book = VaultBook::new();
        book.register(1, 300);
        book.register(1, 200);
        assert_eq!(book.free_of(1), 500);
    }

    #[test]
    fn lock_moves_free_into_locked() {
        let mut book = VaultBook::new();
        book.register(1, 300);
        book.lock(1, 200).unwrap();
        assert_eq!(book.free_of(1), 100);
        assert_eq!(book.locked_of(1), 200);
    }

    #[test]
    fn a_thin_vault_cannot_be_locked() {
        let mut book = VaultBook::new();
        book.register(1, 140);
        assert_eq!(
            book.lock(1, 150),
            Err(ExitError::ThinVault {
                have: 140,
                need: 150
            })
        );
        assert_eq!(book.locked_of(1), 0);
    }

    #[test]
    fn release_returns_locked_to_free() {
        let mut book = VaultBook::new();
        book.register(1, 300);
        book.lock(1, 200).unwrap();
        book.release(1, 200).unwrap();
        assert_eq!(book.free_of(1), 300);
        assert_eq!(book.locked_of(1), 0);
    }

    #[test]
    fn seize_removes_locked_collateral_for_good() {
        let mut book = VaultBook::new();
        book.register(1, 300);
        book.lock(1, 200).unwrap();
        book.seize(1, 200).unwrap();
        assert_eq!(book.free_of(1), 100);
        assert_eq!(book.locked_of(1), 0);
    }

    #[test]
    fn an_unknown_vault_cannot_be_locked() {
        let mut book = VaultBook::new();
        assert_eq!(book.lock(7, 1), Err(ExitError::UnknownVault(7)));
    }

    #[test]
    fn a_random_walk_of_locks_releases_and_seizes_conserves_free_plus_locked() {
        let mut st = 0xdead_beef_cafe_babeu64;
        let mut rng = || {
            st = st.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = st;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut book = VaultBook::new();
        let vaults = [1u32, 2, 3];
        let mut expected: BTreeMap<u32, u128> = BTreeMap::new();
        for v in &vaults {
            let col = (rng() % 10_000) as u128;
            book.register(*v, col);
            expected.insert(*v, col);
        }
        for _ in 0..8000 {
            let v = vaults[(rng() % 3) as usize];
            let amt = (rng() % 3000) as u128;
            match rng() % 3 {
                0 => {
                    let _ = book.lock(v, amt);
                }
                1 => {
                    let _ = book.release(v, amt);
                }
                _ => {
                    if book.seize(v, amt).is_ok() {
                        *expected.get_mut(&v).expect("registered vault") -= amt;
                    }
                }
            }
            for v in &vaults {
                assert_eq!(
                    book.free_of(*v).saturating_add(book.locked_of(*v)),
                    expected[v],
                    "vault {} broke conservation of free plus locked against collateral minus seized",
                    v
                );
            }
        }
    }
}
