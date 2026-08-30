// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{BTreeMap, BTreeSet};

use q_airlock::SignerSig;
use qtv_crypto::ml_dsa::{self, PublicKey, SIGNATURE_BYTES};

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
        assert!(
            set.register(0, key(3)),
            "rotating a slot's own key is allowed"
        );
        assert_eq!(set.size(), 2);
    }

    #[test]
    fn a_junk_or_unknown_signature_is_skipped_not_fatal_to_the_quorum() {
        let mut set = OperatorSet::new(2);
        let mut sk = Vec::new();
        for i in 0..3u8 {
            let mut seed = [0u8; 32];
            seed[0] = i + 1;
            let (pk, secret) = ml_dsa::keygen(&seed);
            set.register(i as u32, pk);
            sk.push(secret);
        }
        let message = b"a bridge fact preimage";
        let context = &[0x11u8; 16];
        let mut sigs: Vec<SignerSig> = (0..2u32)
            .map(|id| SignerSig {
                operator_id: id,
                signature: ml_dsa::sign(&sk[id as usize], message, context, &[0u8; 32])
                    .unwrap()
                    .to_vec(),
            })
            .collect();
        sigs.push(SignerSig {
            operator_id: 2,
            signature: vec![0u8; SIGNATURE_BYTES],
        });
        sigs.push(SignerSig {
            operator_id: 99,
            signature: ml_dsa::sign(&sk[0], message, context, &[0u8; 32])
                .unwrap()
                .to_vec(),
        });
        let distinct = verify_quorum(message, context, &sigs, &set);
        assert_eq!(distinct.len(), 2);
        assert!(distinct.contains(&0) && distinct.contains(&1));
    }
}

pub fn verify_quorum(
    message: &[u8],
    context: &[u8],
    sigs: &[SignerSig],
    set: &OperatorSet,
) -> BTreeSet<u32> {
    let mut distinct: BTreeSet<u32> = BTreeSet::new();
    for s in sigs {
        if distinct.contains(&s.operator_id) {
            continue;
        }
        let pk = match set.pubkey(s.operator_id) {
            Some(pk) => pk,
            None => continue,
        };
        if s.signature.len() != SIGNATURE_BYTES {
            continue;
        }
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&s.signature);
        if !ml_dsa::verify(pk, message, &sig, context) {
            continue;
        }
        distinct.insert(s.operator_id);
    }
    distinct
}
