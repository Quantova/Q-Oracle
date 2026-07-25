// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::BridgeFact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregatorError {
    FactMismatch,
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
