use q_codec::{
    AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_ENCODED_LEN, FACT_VERSION,
};
use q_prover_bridge::{
    prove_statement, verify_statement, CommitmentProof, CorridorStatement, BRIDGE_STATEMENT_DOMAIN,
    STATEMENT_DIGEST_LEN,
};

fn light_client_fact() -> BridgeFact {
    BridgeFact {
        version: FACT_VERSION,
        source_chain: 1,
        dest_chain: 9000,
        route_id: 7,
        direction: Direction::Deposit,
        nonce: 990_001,
        source_ref: SourceRef([0x11u8; 32]),
        asset_id: AssetId([0x22u8; 16]),
        amount: 500_000,
        recipient: Recipient([0x33u8; 32]),
        finality_depth: 6,
        observed_height: 880_101,
    }
}

fn statement() -> CorridorStatement {
    CorridorStatement::new(3, light_client_fact())
}

#[test]
fn a_verified_corridor_statement_proves_and_verifies() {
    let s = statement();
    let commitment = prove_statement(&s);
    assert!(verify_statement(&s, &commitment));
}

#[test]
fn a_tampered_statement_fails_verification() {
    let s = statement();
    let commitment = prove_statement(&s);

    let mut amount = statement();
    amount.fact.amount += 1;
    assert!(!verify_statement(&amount, &commitment));

    let mut recipient = statement();
    recipient.fact.recipient = Recipient([0x44u8; 32]);
    assert!(!verify_statement(&recipient, &commitment));

    let mut operator = statement();
    operator.operator = 4;
    assert!(!verify_statement(&operator, &commitment));

    let mut source = statement();
    source.fact.source_ref = SourceRef([0x12u8; 32]);
    assert!(!verify_statement(&source, &commitment));
}

#[test]
fn a_tampered_digest_fails_verification() {
    let s = statement();
    let mut commitment = prove_statement(&s);
    commitment.digest[STATEMENT_DIGEST_LEN - 1] ^= 1;
    assert!(!verify_statement(&s, &commitment));
}

#[test]
fn the_prover_consumes_only_the_native_statement() {
    let s = statement();
    let preimage = s.preimage();
    assert!(preimage.starts_with(BRIDGE_STATEMENT_DOMAIN));
    assert_eq!(
        preimage.len(),
        BRIDGE_STATEMENT_DOMAIN.len() + 4 + FACT_ENCODED_LEN
    );
}

#[test]
fn the_proof_is_a_native_stark_and_foreign_artifacts_are_rejected() {
    let s = statement();
    let commitment = prove_statement(&s);
    assert!(qtv_stark::codec::decode_proof(&commitment.proof).is_some());

    let mut bls_g1 = vec![0xa0u8];
    bls_g1.extend_from_slice(&[0x33u8; 47]);
    let foreign = CommitmentProof {
        digest: s.digest(),
        proof: bls_g1,
    };
    assert!(!verify_statement(&s, &foreign));
}

#[test]
fn the_proof_binds_the_committed_statement_not_the_foreign_signature() {
    let first = statement();
    let second = statement();
    assert_eq!(first.digest(), second.digest());
    let commitment = prove_statement(&first);
    assert!(verify_statement(&second, &commitment));
}
