use q_attestor::{CorridorContext, ObservedLock, Operator, SoftSigner, Watcher, WatcherError, WatcherSet};
use q_federated::{
    find, install, watch_and_admit, Corridor, FederatedError, OperatorFeed, SourceEndpoint,
    SourceRegistry, WatchError, AVALANCHE, BNB_CHAIN, POLYGON,
};
use q_gateway::{Gateway, OperatorSet};
use qtv_crypto::ml_dsa;

const CHAIN_ID: u32 = 9000;

fn seed_for(id: u32) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0x63;
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
        recipient: [0x66; 32],
        observed_height: 950_000,
        confirmations: c.confirmation_depth,
    }
}

fn feed_for(id: u32, c: &Corridor, source_ref: [u8; 32], amount: u128) -> OperatorFeed<SoftSigner> {
    let signer = SoftSigner::from_seed(id, &seed_for(id));
    let mut operator = Operator::new(signer);
    operator.configure_corridor(CorridorContext {
        source_chain: c.chain_id,
        dest_chain: CHAIN_ID,
        route_id: 1,
        required_confirmations: c.confirmation_depth,
    });
    OperatorFeed::new(operator, own_node(c.chain_id, lock_for(c, source_ref, amount)))
}

fn gateway(ids: &[u32], threshold: usize) -> Gateway {
    let mut set = OperatorSet::new(threshold);
    for id in ids {
        set.register(*id, public_key(*id));
    }
    let mut gw = Gateway::new(CHAIN_ID, set, 1_000_000_000_000);
    install(&mut gw);
    gw
}

fn independent_sources(chain_id: u32, ids: &[u32]) -> SourceRegistry {
    let mut reg = SourceRegistry::new();
    for id in ids {
        let mut fp = [0u8; 32];
        fp[0] = chain_id as u8;
        fp[1] = *id as u8;
        fp[2] = 0xe7;
        reg.declare(chain_id, *id, SourceEndpoint(fp));
    }
    reg
}

#[test]
fn bnb_chain_polygon_and_avalanche_keep_their_canonical_ids_on_the_live_path() {
    assert_eq!(BNB_CHAIN, 3);
    assert_eq!(POLYGON, 4);
    assert_eq!(AVALANCHE, 5);
}

#[test]
fn a_distinct_signer_quorum_watching_its_own_rpc_source_mints_for_each_new_corridor() {
    for id in [BNB_CHAIN, POLYGON, AVALANCHE] {
        let c = find(id).unwrap();
        let ids = [10u32, 11, 12];
        let mut gw = gateway(&ids, 3);
        let sources = independent_sources(id, &ids);
        let mut feeds: Vec<_> = ids
            .iter()
            .map(|op_id| feed_for(*op_id, &c, [0x90 + id as u8; 32], 500))
            .collect();

        let receipt = watch_and_admit(&mut gw, &c, &sources, 3, &mut feeds)
            .unwrap_or_else(|e| panic!("{} watchers reach quorum and mint, got {:?}", c.name, e));
        assert_eq!(receipt.amount, 500);
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 500);
    }
}

#[test]
fn a_sub_quorum_of_watchers_never_mints_for_each_new_corridor() {
    for id in [BNB_CHAIN, POLYGON, AVALANCHE] {
        let c = find(id).unwrap();
        let full = [20u32, 21, 22];
        let sub = [20u32, 21];
        let mut gw = gateway(&full, 3);
        let sources = independent_sources(id, &sub);
        let mut feeds: Vec<_> = sub
            .iter()
            .map(|op_id| feed_for(*op_id, &c, [0xa0 + id as u8; 32], 500))
            .collect();

        assert_eq!(
            watch_and_admit(&mut gw, &c, &sources, 3, &mut feeds),
            Err(WatchError::NoQuorumObserved { distinct: 2, threshold: 3 }),
            "{} must not mint on a sub quorum of watchers",
            c.name
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }
}

#[test]
fn a_correlated_rpc_source_quorum_is_refused_through_the_live_path_for_each_new_corridor() {
    for id in [BNB_CHAIN, POLYGON, AVALANCHE] {
        let c = find(id).unwrap();
        let ids = [30u32, 31, 32];
        let mut gw = gateway(&ids, 3);
        let mut sources = SourceRegistry::new();
        sources.declare(id, 30, SourceEndpoint([0xaa; 32]));
        sources.declare(id, 31, SourceEndpoint([0xaa; 32]));
        sources.declare(id, 32, SourceEndpoint([0xcc; 32]));
        let mut feeds: Vec<_> = ids
            .iter()
            .map(|op_id| feed_for(*op_id, &c, [0xb0 + id as u8; 32], 500))
            .collect();

        assert_eq!(
            watch_and_admit(&mut gw, &c, &sources, 3, &mut feeds),
            Err(WatchError::Admission(FederatedError::CorrelatedSources {
                independent: 2,
                signers: 3
            })),
            "{} must refuse a correlated source quorum before any mint",
            c.name
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }
}
