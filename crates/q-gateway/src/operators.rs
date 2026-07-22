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

    pub fn register(&mut self, operator_id: u32, pubkey: PublicKey) {
        self.pubkeys.insert(operator_id, pubkey);
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

pub fn verify_quorum(
    message: &[u8],
    context: &[u8],
    sigs: &[SignerSig],
    set: &OperatorSet,
) -> Result<BTreeSet<u32>, GatewayError> {
    let mut distinct: BTreeSet<u32> = BTreeSet::new();
    for s in sigs {
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
