// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::BridgeFact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregatorError {
    FactMismatch,
    Unverified,
}

pub struct Aggregator {
    threshold: usize,
    fact: Option<BridgeFact>,
    sigs: BTreeMap<u32, SignerSig>,
}

impl Aggregator {
    pub fn new(threshold: usize) -> Aggregator {
        Aggregator {
            threshold,
            fact: None,
            sigs: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, fact: &BridgeFact, sig: SignerSig) -> Result<(), AggregatorError> {
        match &self.fact {
            None => self.fact = Some(fact.clone()),
            Some(existing) => {
                if existing.encode() != fact.encode() {
                    return Err(AggregatorError::FactMismatch);
                }
            }
        }
        self.sigs.insert(sig.operator_id, sig);
        Ok(())
    }

    pub fn add_verified<F>(
        &mut self,
        fact: &BridgeFact,
        sig: SignerSig,
        verify: F,
    ) -> Result<(), AggregatorError>
    where
        F: FnOnce(&BridgeFact, &SignerSig) -> bool,
    {
        if let Some(existing) = &self.fact {
            if existing.encode() != fact.encode() {
                return Err(AggregatorError::FactMismatch);
            }
        }
        if !verify(fact, &sig) {
            return Err(AggregatorError::Unverified);
        }
        self.add(fact, sig)
    }

    pub fn distinct(&self) -> usize {
        self.sigs.len()
    }

    pub fn ready(&self) -> bool {
        self.sigs.len() >= self.threshold
    }

    pub fn try_finalize(&self) -> Option<AttestationEnvelope> {
        if !self.ready() {
            return None;
        }
        let fact = self.fact.clone()?;
        Some(AttestationEnvelope {
            fact,
            signatures: self.sigs.values().cloned().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_codec::{AssetId, Direction, Recipient, SourceRef, FACT_VERSION};

    fn fact() -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef([7; 32]),
            asset_id: AssetId([1; 16]),
            amount: 10,
            recipient: Recipient([2; 32]),
            finality_depth: 6,
            observed_height: 100,
            expiry_height: 200,
        }
    }

    fn sig(operator_id: u32, byte: u8) -> SignerSig {
        SignerSig {
            operator_id,
            signature: vec![byte; 8],
        }
    }

    #[test]
    fn a_junk_signature_never_displaces_a_verified_one() {
        let f = fact();
        let genuine = |_: &BridgeFact, s: &SignerSig| s.signature[0] == 0xAA;
        let mut agg = Aggregator::new(1);
        assert!(agg.add_verified(&f, sig(3, 0xAA), genuine).is_ok());
        assert_eq!(
            agg.add_verified(&f, sig(3, 0x00), genuine),
            Err(AggregatorError::Unverified)
        );
        let env = agg.try_finalize().expect("the verified signature stands");
        assert_eq!(env.signatures[0].signature[0], 0xAA);
    }

    #[test]
    fn unverified_signatures_never_count_toward_the_threshold() {
        let f = fact();
        let mut agg = Aggregator::new(2);
        let _ = agg.add_verified(&f, sig(1, 0xAA), |_, _| true);
        let _ = agg.add_verified(&f, sig(2, 0x00), |_, _| false);
        assert!(!agg.ready());
        assert_eq!(agg.distinct(), 1);
    }
}
