// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::merkle::merkle_root;
use crate::proto::put_varint;
use crate::sha256::sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub pubkey: [u8; 32],
    pub voting_power: u64,
}

impl ValidatorInfo {
    pub fn address(&self) -> [u8; 20] {
        let digest = sha256(&self.pubkey);
        let mut address = [0u8; 20];
        address.copy_from_slice(&digest[0..20]);
        address
    }

    pub fn encode_leaf(&self) -> Vec<u8> {
        let mut pubkey_msg = Vec::with_capacity(34);
        pubkey_msg.push(0x0a);
        pubkey_msg.push(0x20);
        pubkey_msg.extend_from_slice(&self.pubkey);

        let mut leaf = Vec::new();
        leaf.push(0x0a);
        put_varint(&mut leaf, pubkey_msg.len() as u64);
        leaf.extend_from_slice(&pubkey_msg);
        leaf.push(0x10);
        put_varint(&mut leaf, self.voting_power);
        leaf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<ValidatorInfo>) -> ValidatorSet {
        ValidatorSet { validators }
    }

    pub fn total_power(&self) -> u64 {
        let mut total: u128 = 0;
        for v in &self.validators {
            total += v.voting_power as u128;
        }
        total as u64
    }

    pub fn hash(&self) -> [u8; 32] {
        let leaves: Vec<Vec<u8>> = self.validators.iter().map(|v| v.encode_leaf()).collect();
        merkle_root(&leaves)
    }

    pub fn get_by_address(&self, address: &[u8; 20]) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.address() == address)
    }
}

pub fn has_two_thirds(signed_power: u64, total_power: u64) -> bool {
    (signed_power as u128) * 3 > (total_power as u128) * 2
}

pub fn overlap_power(old: &ValidatorSet, new: &ValidatorSet) -> u64 {
    let mut overlap: u128 = 0;
    for v in &old.validators {
        if new.get_by_address(&v.address()).is_some() {
            overlap += v.voting_power as u128;
        }
    }
    overlap as u64
}

pub fn overlap_meets(old: &ValidatorSet, new: &ValidatorSet, numerator: u64, denominator: u64) -> bool {
    let overlap = overlap_power(old, new) as u128;
    overlap * (denominator as u128) > (old.total_power() as u128) * (numerator as u128)
}

pub fn two_thirds_overlap(old: &ValidatorSet, new: &ValidatorSet) -> bool {
    overlap_meets(old, new, 2, 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(seed: u8, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            pubkey: [seed; 32],
            voting_power: power,
        }
    }

    #[test]
    fn address_is_the_leading_twenty_bytes_of_the_key_hash() {
        let v = validator(7, 100);
        let full = sha256(&v.pubkey);
        assert_eq!(&v.address()[..], &full[0..20]);
    }

    #[test]
    fn total_power_sums_the_set() {
        let set = ValidatorSet::new(vec![validator(1, 10), validator(2, 20), validator(3, 30)]);
        assert_eq!(set.total_power(), 60);
    }

    #[test]
    fn two_thirds_is_strict() {
        assert!(!has_two_thirds(66, 99));
        assert!(has_two_thirds(67, 99));
        assert!(!has_two_thirds(2, 3));
        assert!(has_two_thirds(3, 3));
    }

    #[test]
    fn the_set_hash_binds_each_power() {
        let a = ValidatorSet::new(vec![validator(1, 10), validator(2, 20)]);
        let mut b = a.clone();
        b.validators[1].voting_power = 21;
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn the_set_hash_binds_each_key() {
        let a = ValidatorSet::new(vec![validator(1, 10), validator(2, 20)]);
        let mut b = a.clone();
        b.validators[0].pubkey[0] ^= 0xff;
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn a_set_that_keeps_more_than_two_thirds_of_power_overlaps() {
        let old = ValidatorSet::new(vec![validator(1, 40), validator(2, 40), validator(3, 10)]);
        let new = ValidatorSet::new(vec![validator(1, 5), validator(2, 5), validator(9, 999)]);
        assert!(two_thirds_overlap(&old, &new));
    }

    #[test]
    fn a_set_that_keeps_two_thirds_or_less_does_not_overlap() {
        let old = ValidatorSet::new(vec![validator(1, 30), validator(2, 30), validator(3, 30)]);
        let new = ValidatorSet::new(vec![validator(1, 30), validator(2, 30)]);
        assert!(!two_thirds_overlap(&old, &new));

        let barely = ValidatorSet::new(vec![validator(1, 45), validator(9, 999)]);
        assert!(!two_thirds_overlap(&old, &barely));
    }

    #[test]
    fn the_overlap_threshold_is_configurable() {
        let old = ValidatorSet::new(vec![validator(1, 40), validator(2, 30), validator(3, 20)]);
        let new = ValidatorSet::new(vec![validator(1, 1), validator(9, 999)]);
        assert_eq!(overlap_power(&old, &new), 40);
        assert!(overlap_meets(&old, &new, 1, 3));
        assert!(!overlap_meets(&old, &new, 2, 3));
    }
}
