// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{BTreeMap, BTreeSet};

use q_airlock::SignerSig;
use qtv_crypto::ml_dsa::{self, PublicKey, SIGNATURE_BYTES};

use crate::errors::GatewayError;

pub struct OperatorSet {
    pubkeys: BTreeMap<u32, PublicKey>,
    threshold: usize,
}

impl OperatorSet {
    pub fn new(threshold: usize) -> OperatorSet {
        OperatorSet {
            pubkeys: BTreeMap::new(),
            threshold,
        }
    }

    pub fn register(&mut self, operator_id: u32, pubkey: PublicKey) -> bool {
        if self
            .pubkeys
            .iter()
            .any(|(id, existing)| *id != operator_id && *existing == pubkey)
        {
            return false;
        }
        self.pubkeys.insert(operator_id, pubkey);
        true
    }

    pub fn remove(&mut self, operator_id: u32) {
        self.pubkeys.remove(&operator_id);
    }

    pub fn pubkey(&self, operator_id: u32) -> Option<&PublicKey> {
        self.pubkeys.get(&operator_id)
    }

    pub fn size(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn set_threshold(&mut self, threshold: usize) {
        self.threshold = threshold;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        let mut seed = [0u8; 32];
        seed[0] = byte;
        let (pk, _sk) = ml_dsa::keygen(&seed);
        pk
    }

    #[test]
    fn a_pubkey_already_held_under_another_id_is_refused() {
        let mut set = OperatorSet::new(2);
        let shared = key(1);
        assert!(set.register(0, shared));
        assert!(!set.register(1, shared), "one key must not fill two slots");
        assert_eq!(set.size(), 1);
        assert!(set.pubkey(1).is_none());
    }

    #[test]
    fn distinct_keys_and_same_id_rotation_are_allowed() {
        let mut set = OperatorSet::new(2);
        assert!(set.register(0, key(1)));
        assert!(set.register(1, key(2)));
        assert_eq!(set.size(), 2);
        assert!(set.register(0, key(3)), "rotating a slot's own key is allowed");
        assert_eq!(set.size(), 2);
    }
}

pub fn verify_quorum(
    message: &[u8],
    context: &[u8],
    sigs: &[SignerSig],
    set: &OperatorSet,
) -> Result<BTreeSet<u32>, GatewayError> {
    let mut distinct: BTreeSet<u32> = BTreeSet::new();
    for s in sigs {
        if distinct.contains(&s.operator_id) {
            continue;
        }
        let pk = set
            .pubkey(s.operator_id)
            .ok_or(GatewayError::UnknownOperator(s.operator_id))?;
        if s.signature.len() != SIGNATURE_BYTES {
            return Err(GatewayError::BadSignature(s.operator_id));
        }
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&s.signature);
        let ok = ml_dsa::verify(pk, message, &sig, context);
        if !ok {
            return Err(GatewayError::BadSignature(s.operator_id));
        }
        distinct.insert(s.operator_id);
    }
    Ok(distinct)
}
