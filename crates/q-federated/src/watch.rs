// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_attestor::{Aggregator, AttestationSigner, Operator, WatcherSet};
use q_gateway::{Gateway, MintReceipt};

use crate::admission::{admit, FederatedError};
use crate::corridors::Corridor;
use crate::sources::SourceRegistry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchError {
    NoQuorumObserved { distinct: usize, threshold: usize },
    Admission(FederatedError),
}

impl From<FederatedError> for WatchError {
    fn from(e: FederatedError) -> WatchError {
        WatchError::Admission(e)
    }
}

pub struct OperatorFeed<S: AttestationSigner> {
    operator: Operator<S>,
    watchers: WatcherSet,
}

impl<S: AttestationSigner> OperatorFeed<S> {
    pub fn new(operator: Operator<S>, watchers: WatcherSet) -> OperatorFeed<S> {
        OperatorFeed { operator, watchers }
    }
}

pub fn watch_and_admit<S: AttestationSigner>(
    gateway: &mut Gateway,
    corridor: &Corridor,
    sources: &SourceRegistry,
    threshold: usize,
    feeds: &mut [OperatorFeed<S>],
) -> Result<MintReceipt, WatchError> {
    let mut agg = Aggregator::new(threshold);
    let dest_height = gateway.current_height();
    for feed in feeds.iter_mut() {
        let locks = feed.watchers.poll(corridor.chain_id).unwrap_or_default();
        for lock in locks {
            if let Ok(signed) = feed.operator.observe_and_sign(&lock, dest_height) {
                let _ = agg.add(&signed.fact, signed.sig);
            }
        }
    }
    match agg.try_finalize() {
        Some(envelope) => Ok(admit(gateway, corridor, sources, &envelope)?),
        None => Err(WatchError::NoQuorumObserved {
            distinct: agg.distinct(),
            threshold,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_ID: u64 = 0x0000_002a_0000_2328;
    use crate::corridors::{find, BNB_CHAIN};
    use crate::sources::SourceEndpoint;
    use q_attestor::{CorridorContext, ObservedLock, SoftSigner, Watcher, WatcherError};
    use q_gateway::OperatorSet;
    use qtv_crypto::ml_dsa;

    const CHAIN_ID: u32 = 9000;

    fn seed_for(id: u32) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed[0] = id as u8;
        seed[31] = 0x51;
        seed
    }

    fn public_key(id: u32) -> ml_dsa::PublicKey {
        let (pk, _sk) = ml_dsa::keygen(&seed_for(id));
        pk
    }

    struct NodeView {
        chain: u32,
        locks: Vec<ObservedLock>,
    }

    impl Watcher for NodeView {
        fn source_chain(&self) -> u32 {
            self.chain
        }

        fn poll_finalized(&self) -> Result<Vec<ObservedLock>, WatcherError> {
            Ok(self.locks.clone())
        }
    }

    fn own_node(chain: u32, lock: ObservedLock) -> WatcherSet {
        let mut set = WatcherSet::new();
        set.attach(Box::new(NodeView { chain, locks: vec![lock] }));
        set
    }

    fn lock_for(c: &Corridor, source_ref: [u8; 32], amount: u128) -> ObservedLock {
        ObservedLock {
            source_chain: c.chain_id,
            source_ref,
            asset_id: c.origin_asset.0,
            amount,
            recipient: [0x55; 32],
            observed_height: 900_000,
            confirmations: c.confirmation_depth,
        }
    }

    fn feed_for(id: u32, c: &Corridor, source_ref: [u8; 32], amount: u128) -> OperatorFeed<SoftSigner> {
        let signer = SoftSigner::from_seed(id, &seed_for(id));
        let mut operator = Operator::new(signer);
        operator.configure_corridor(CorridorContext {
            source_chain: c.chain_id,
            dest_chain: CHAIN_ID,
            dest_chain_id: DEST_ID,
            route_id: 1,
            required_confirmations: c.confirmation_depth,
            era: [0x11u8; 32],
        });
        OperatorFeed::new(operator, own_node(c.chain_id, lock_for(c, source_ref, amount)))
    }

    fn gateway(ids: &[u32], threshold: usize) -> Gateway {
        let mut set = OperatorSet::new(threshold);
        for id in ids {
            set.register(*id, public_key(*id));
        }
        let mut gw = Gateway::new(CHAIN_ID, DEST_ID, set, 1_000_000_000_000);
        gw.set_era([0x11u8; 32]);
        crate::admission::install(&mut gw);
        gw
    }

    fn independent_sources(chain_id: u32, ids: &[u32]) -> SourceRegistry {
        let mut reg = SourceRegistry::new();
        for id in ids {
            let mut fp = [0u8; 32];
            fp[0] = chain_id as u8;
            fp[1] = *id as u8;
            fp[2] = 0x9c;
            reg.declare(chain_id, *id, SourceEndpoint(fp));
        }
        reg
    }

    #[test]
    fn a_distinct_signer_quorum_watching_its_own_source_mints() {
        let c = find(BNB_CHAIN).unwrap();
        let ids = [0u32, 1, 2];
        let mut gw = gateway(&ids, 3);
        let sources = independent_sources(BNB_CHAIN, &ids);
        let mut feeds: Vec<_> = ids
            .iter()
            .map(|id| feed_for(*id, &c, [0x81; 32], 500))
            .collect();

        let receipt = watch_and_admit(&mut gw, &c, &sources, 3, &mut feeds)
            .expect("three independent watchers reach quorum and mint");
        assert_eq!(receipt.amount, 500);
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 500);
    }

    #[test]
    fn a_sub_quorum_of_watchers_does_not_mint() {
        let c = find(BNB_CHAIN).unwrap();
        let ids = [0u32, 1];
        let mut gw = gateway(&[0, 1, 2], 3);
        let sources = independent_sources(BNB_CHAIN, &ids);
        let mut feeds: Vec<_> = ids
            .iter()
            .map(|id| feed_for(*id, &c, [0x82; 32], 500))
            .collect();

        assert_eq!(
            watch_and_admit(&mut gw, &c, &sources, 3, &mut feeds),
            Err(WatchError::NoQuorumObserved { distinct: 2, threshold: 3 })
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }

    #[test]
    fn a_correlated_source_quorum_still_reaches_the_gate_and_is_refused() {
        let c = find(BNB_CHAIN).unwrap();
        let ids = [0u32, 1, 2];
        let mut gw = gateway(&ids, 3);
        let mut sources = SourceRegistry::new();
        sources.declare(BNB_CHAIN, 0, SourceEndpoint([0xaa; 32]));
        sources.declare(BNB_CHAIN, 1, SourceEndpoint([0xaa; 32]));
        sources.declare(BNB_CHAIN, 2, SourceEndpoint([0xcc; 32]));
        let mut feeds: Vec<_> = ids
            .iter()
            .map(|id| feed_for(*id, &c, [0x83; 32], 500))
            .collect();

        assert_eq!(
            watch_and_admit(&mut gw, &c, &sources, 3, &mut feeds),
            Err(WatchError::Admission(FederatedError::CorrelatedSources {
                independent: 2,
                signers: 3
            }))
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }
}
