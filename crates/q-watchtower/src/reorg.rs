use std::collections::BTreeMap;

use q_gateway::Gateway;

use crate::identity::WatchtowerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorgVerdict {
    NoPolicy,
    WithinDepth,
    Paused {
        watchtower: WatchtowerId,
        source_chain: u32,
        fork_depth: u32,
    },
}

pub struct CorridorReorgPolicy {
    max_depth: BTreeMap<u32, u32>,
}

impl CorridorReorgPolicy {
    pub fn new() -> CorridorReorgPolicy {
        CorridorReorgPolicy {
            max_depth: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, source_chain: u32, max_depth: u32) {
        self.max_depth.insert(source_chain, max_depth);
    }

    pub fn max_depth(&self, source_chain: u32) -> Option<u32> {
        self.max_depth.get(&source_chain).copied()
    }
}

impl Default for CorridorReorgPolicy {
    fn default() -> CorridorReorgPolicy {
        CorridorReorgPolicy::new()
    }
}

pub struct ReorgWatcher {
    id: WatchtowerId,
    policy: CorridorReorgPolicy,
}

impl ReorgWatcher {
    pub fn new(id: WatchtowerId, policy: CorridorReorgPolicy) -> ReorgWatcher {
        ReorgWatcher { id, policy }
    }

    pub fn id(&self) -> WatchtowerId {
        self.id
    }

    pub fn observe(&self, gateway: &mut Gateway, source_chain: u32, fork_depth: u32) -> ReorgVerdict {
        match self.policy.max_depth(source_chain) {
            None => ReorgVerdict::NoPolicy,
            Some(max_depth) => {
                if fork_depth > max_depth {
                    gateway.pause_source_direct(source_chain);
                    ReorgVerdict::Paused {
                        watchtower: self.id,
                        source_chain,
                        fork_depth,
                    }
                } else {
                    ReorgVerdict::WithinDepth
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_gateway::OperatorSet;

    fn gateway_with_corridor(source_chain: u32) -> Gateway {
        let set = OperatorSet::new(1);
        let mut gw = Gateway::new(9000, set, 1_000_000);
        gw.register_corridor(source_chain, 6);
        gw
    }

    fn watcher(source_chain: u32, max_depth: u32) -> ReorgWatcher {
        let mut policy = CorridorReorgPolicy::new();
        policy.set(source_chain, max_depth);
        ReorgWatcher::new(WatchtowerId(1), policy)
    }

    #[test]
    fn a_reorg_deeper_than_the_configured_depth_pauses_the_corridor() {
        let mut gw = gateway_with_corridor(1);
        let w = watcher(1, 6);
        let verdict = w.observe(&mut gw, 1, 7);
        assert_eq!(
            verdict,
            ReorgVerdict::Paused {
                watchtower: WatchtowerId(1),
                source_chain: 1,
                fork_depth: 7,
            }
        );
        assert!(gw.is_source_paused(1));
    }

    #[test]
    fn a_shallow_reorg_does_not_pause_the_corridor() {
        let mut gw = gateway_with_corridor(1);
        let w = watcher(1, 6);
        let verdict = w.observe(&mut gw, 1, 6);
        assert_eq!(verdict, ReorgVerdict::WithinDepth);
        assert!(!gw.is_source_paused(1));
    }

    #[test]
    fn a_source_with_no_configured_policy_is_left_alone() {
        let mut gw = gateway_with_corridor(2);
        let w = watcher(1, 6);
        let verdict = w.observe(&mut gw, 2, 100);
        assert_eq!(verdict, ReorgVerdict::NoPolicy);
        assert!(!gw.is_source_paused(2));
    }
}
