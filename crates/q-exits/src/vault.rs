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
        vault.locked += amount;
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
}
