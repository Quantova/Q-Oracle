// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceEndpoint(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependenceReport {
    pub signers: usize,
    pub independent_sources: usize,
    pub undeclared: usize,
}

impl IndependenceReport {
    pub fn fully_independent(&self) -> bool {
        self.undeclared == 0 && self.independent_sources == self.signers
    }

    pub fn correlated(&self) -> bool {
        self.independent_sources < self.signers.saturating_sub(self.undeclared)
    }
}

pub struct SourceRegistry {
    map: BTreeMap<u32, BTreeMap<u32, SourceEndpoint>>,
}

impl SourceRegistry {
    pub fn new() -> SourceRegistry {
        SourceRegistry {
            map: BTreeMap::new(),
        }
    }

    pub fn declare(&mut self, corridor: u32, operator_id: u32, endpoint: SourceEndpoint) {
        self.map
            .entry(corridor)
            .or_default()
            .insert(operator_id, endpoint);
    }

    pub fn endpoint(&self, corridor: u32, operator_id: u32) -> Option<SourceEndpoint> {
        self.map
            .get(&corridor)
            .and_then(|m| m.get(&operator_id))
            .copied()
    }

    pub fn analyze(&self, corridor: u32, operators: &BTreeSet<u32>) -> IndependenceReport {
        let mut endpoints: BTreeSet<SourceEndpoint> = BTreeSet::new();
        let mut undeclared = 0usize;
        for id in operators {
            match self.endpoint(corridor, *id) {
                Some(ep) => {
                    endpoints.insert(ep);
                }
                None => undeclared += 1,
            }
        }
        IndependenceReport {
            signers: operators.len(),
            independent_sources: endpoints.len(),
            undeclared,
        }
    }
}

impl Default for SourceRegistry {
    fn default() -> SourceRegistry {
        SourceRegistry::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(byte: u8) -> SourceEndpoint {
        SourceEndpoint([byte; 32])
    }

    fn ids(v: &[u32]) -> BTreeSet<u32> {
        v.iter().copied().collect()
    }

    #[test]
    fn distinct_endpoints_are_fully_independent() {
        let mut reg = SourceRegistry::new();
        reg.declare(3, 0, ep(0xa0));
        reg.declare(3, 1, ep(0xb1));
        reg.declare(3, 2, ep(0xc2));
        let report = reg.analyze(3, &ids(&[0, 1, 2]));
        assert_eq!(report.independent_sources, 3);
        assert_eq!(report.signers, 3);
        assert_eq!(report.undeclared, 0);
        assert!(report.fully_independent());
        assert!(!report.correlated());
    }

    #[test]
    fn a_shared_source_is_distinguishable_from_independent_sources() {
        let mut independent = SourceRegistry::new();
        independent.declare(3, 0, ep(0xa0));
        independent.declare(3, 1, ep(0xb1));
        independent.declare(3, 2, ep(0xc2));
        let clean = independent.analyze(3, &ids(&[0, 1, 2]));

        let mut shared = SourceRegistry::new();
        shared.declare(3, 0, ep(0xa0));
        shared.declare(3, 1, ep(0xa0));
        shared.declare(3, 2, ep(0xc2));
        let correlated = shared.analyze(3, &ids(&[0, 1, 2]));

        assert!(clean.fully_independent());
        assert!(!correlated.fully_independent());
        assert_eq!(correlated.independent_sources, 2);
        assert_eq!(correlated.signers, 3);
        assert!(correlated.correlated());
        assert_ne!(clean, correlated);
    }

    #[test]
    fn an_undeclared_source_is_not_counted_as_independent() {
        let mut reg = SourceRegistry::new();
        reg.declare(3, 0, ep(0xa0));
        reg.declare(3, 1, ep(0xb1));
        let report = reg.analyze(3, &ids(&[0, 1, 2]));
        assert_eq!(report.undeclared, 1);
        assert_eq!(report.independent_sources, 2);
        assert!(!report.fully_independent());
    }

    #[test]
    fn each_corridor_holds_its_own_source_map() {
        let mut reg = SourceRegistry::new();
        reg.declare(3, 0, ep(0xa0));
        reg.declare(4, 0, ep(0xd4));
        assert_eq!(reg.endpoint(3, 0), Some(ep(0xa0)));
        assert_eq!(reg.endpoint(4, 0), Some(ep(0xd4)));
        assert_eq!(reg.endpoint(9, 0), None);
    }
}
