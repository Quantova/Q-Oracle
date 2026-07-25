use q_airlock::{parse, Artifact};
use q_attestor::{
    Aggregator, CorridorContext, HaltReason, ObservedLock, Operator, OperatorError, OperatorState,
    SignedObservation, SoftSigner, Watcher, WatcherError, WatcherSet,
};
use q_gateway::{Gateway, OperatorSet};

const CHAIN_ID: u32 = 9000;
const SOURCE: u32 = 1;
const ASSET: [u8; 16] = [0xa1; 16];

fn context() -> CorridorContext {
    CorridorContext {
        source_chain: SOURCE,
        dest_chain: CHAIN_ID,
        route_id: 1,
        required_confirmations: 6,
    }
}

fn lock(source_ref: [u8; 32], amount: u128, confirmations: u32) -> ObservedLock {
    ObservedLock {
        source_chain: SOURCE,
        source_ref,
        asset_id: ASSET,
        amount,
        recipient: [0x55; 32],
        observed_height: 800_000,
        confirmations,
    }
}

fn make_operator(id: u32) -> Operator<SoftSigner> {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0xBB;
    let signer = SoftSigner::from_seed(id, &seed);
    let mut op = Operator::new(signer);
    op.configure_corridor(context());
    op
}

fn signer_pubkey(id: u32) -> qtv_crypto::ml_dsa::PublicKey {
    let mut seed = [0u8; 32];
    seed[0] = id as u8;
    seed[31] = 0xBB;
    let (pk, _sk) = qtv_crypto::ml_dsa::keygen(&seed);
    pk
}

#[test]
fn full_pipeline_from_watcher_to_mint() {
    let mut set = OperatorSet::new(3);
    for id in 0..5u32 {
        set.register(id, signer_pubkey(id));
    }
    let mut gw = Gateway::new(CHAIN_ID, set, 1_000_000);
    gw.register_corridor(SOURCE, 6);
    gw.register_asset_cap(ASSET, 1_000);

    let mut operators: Vec<Operator<SoftSigner>> = (0..3).map(make_operator).collect();
    let observed = lock([0x11; 32], 500, 6);

    let mut agg = Aggregator::new(3);
    for op in operators.iter_mut() {
        let signed = op.observe_and_sign(&observed, 900_000).expect("operator signs a final lock");
        agg.add(&signed.fact, signed.sig).expect("bundle matching facts");
    }
    assert!(agg.ready());

    let envelope = agg.try_finalize().expect("threshold reached");
    let wire = envelope.encode();

    let artifact = parse(&wire).expect("airlock admits the attestation");
    let parsed = match artifact {
        Artifact::Attestation(a) => a,
        _ => panic!("wrong artifact"),
    };

    let receipt = gw.process_deposit(&parsed).expect("gateway mints");
    assert_eq!(receipt.amount, 500);
    assert_eq!(gw.minted_of_asset(&ASSET), 500);
}

#[test]
fn node_divergence_triggers_safe_halt_not_majority_override() {
    let mut op = make_operator(0);
    let source_ref = [0x22; 32];
    op.observe_and_sign(&lock(source_ref, 500, 6), 900_000).expect("first view signs");

    let conflicting = op.observe_and_sign(&lock(source_ref, 999, 6), 900_000);
    assert_eq!(conflicting, Err(OperatorError::Halted(HaltReason::Divergence)));
    assert!(op.is_halted());
    assert_eq!(op.state(), OperatorState::Halted(HaltReason::Divergence));

    let later = op.observe_and_sign(&lock([0x23; 32], 100, 6), 900_000);
    assert_eq!(later, Err(OperatorError::Halted(HaltReason::Divergence)));
}

#[test]
fn dos_overload_degrades_to_safe_halt() {
    let mut op = make_operator(0);
    op.note_load(10_000, 1_000);
    assert!(op.is_halted());
    let attempt = op.observe_and_sign(&lock([0x24; 32], 500, 6), 900_000);
    assert_eq!(attempt, Err(OperatorError::Halted(HaltReason::Overload)));
}

#[test]
fn below_finality_is_not_signed() {
    let mut op = make_operator(0);
    let attempt = op.observe_and_sign(&lock([0x25; 32], 500, 5), 900_000);
    assert_eq!(attempt, Err(OperatorError::BelowFinality { got: 5, need: 6 }));
    assert!(!op.is_halted());
}

#[test]
fn one_source_event_is_not_signed_twice_by_an_operator() {
    let mut op = make_operator(0);
    let source_ref = [0x26; 32];
    op.observe_and_sign(&lock(source_ref, 500, 6), 900_000).expect("first sign");
    let again = op.observe_and_sign(&lock(source_ref, 500, 6), 900_000);
    assert_eq!(again, Err(OperatorError::AlreadySigned));
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

fn own_node(locks: Vec<ObservedLock>) -> WatcherSet {
    let mut set = WatcherSet::new();
    set.attach(Box::new(NodeView {
        chain: SOURCE,
        locks,
    }));
    set
}

fn sign_own_view(id: u32, view: &WatcherSet) -> Vec<SignedObservation> {
    let mut op = make_operator(id);
    let mut out = Vec::new();
    for lk in view.poll(SOURCE).unwrap_or_default() {
        if let Ok(signed) = op.observe_and_sign(&lk, 900_000) {
            out.push(signed);
        }
    }
    out
}

#[test]
fn a_forged_lock_on_a_minority_of_nodes_never_reaches_quorum() {
    let forged = lock([0x77; 32], 500, 6);
    let mut agg = Aggregator::new(3);

    for id in [0u32, 1] {
        let compromised = own_node(vec![forged.clone()]);
        for signed in sign_own_view(id, &compromised) {
            agg.add(&signed.fact, signed.sig).expect("compromised node signs the forgery");
        }
    }

    for id in [2u32, 3, 4] {
        let honest = own_node(vec![]);
        for signed in sign_own_view(id, &honest) {
            agg.add(&signed.fact, signed.sig).expect("honest node sees nothing to sign");
        }
    }

    assert_eq!(agg.distinct(), 2);
    assert!(!agg.ready());
    assert!(agg.try_finalize().is_none());
}

#[test]
fn overload_halts_and_never_takes_a_relaxed_path() {
    let mut op = make_operator(0);
    op.note_load(5_000, 1_000);
    assert!(op.is_halted());

    let valid_final = lock([0x78; 32], 500, 6);
    assert_eq!(
        op.observe_and_sign(&valid_final, 900_000),
        Err(OperatorError::Halted(HaltReason::Overload))
    );

    op.note_load(0, 1_000);
    assert_eq!(
        op.observe_and_sign(&valid_final, 900_000),
        Err(OperatorError::Halted(HaltReason::Overload))
    );
    assert_eq!(op.state(), OperatorState::Halted(HaltReason::Overload));
}
