use q_airlock::Artifact;
use q_attestor::{
    corridor_statement, package, translate, AttestationSigner, CorridorContext, ObservedLock,
    SoftSigner,
};
use q_bls::Bls12381AggregateVerifier;
use q_isolation::{admit, PqArtifact, Refused};
use q_prover_bridge::{prove_statement, verify_statement};
use qlc_ethereum::bls::{BlsAggregateVerifier, BlsPubkey, BlsSignature};
use qlc_stark::shake256_256;
use qtv_crypto::sha3::shake256;
use qtv_stark::sponge::{absorb_output, SHAKE256_RATE};

const PK_A: &str = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
const PK_B: &str = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81";
const PK_C: &str = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f";
const MESSAGE_ABAB: &str = "abababababababababababababababababababababababababababababababab";
const AGGREGATE_ABAB_VALID: &str = "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930";
const AGGREGATE_ABAB_TAMPERED: &str = "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff";

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn pubkey(text: &str) -> BlsPubkey {
    BlsPubkey::from_bytes(&from_hex(text)).unwrap()
}

fn signature(text: &str) -> BlsSignature {
    BlsSignature::from_bytes(&from_hex(text)).unwrap()
}

fn message(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&from_hex(text));
    out
}

fn ctx() -> CorridorContext {
    CorridorContext {
        source_chain: 2,
        dest_chain: 9000,
        route_id: 7,
        required_confirmations: 6,
    }
}

fn lock() -> ObservedLock {
    ObservedLock {
        source_chain: 2,
        source_ref: [0x71u8; 32],
        asset_id: [0x22u8; 16],
        amount: 4_200_000,
        recipient: [0x33u8; 32],
        observed_height: 20_000_000,
        confirmations: 6,
    }
}

#[test]
fn a_verified_foreign_fact_becomes_two_pq_artifacts_and_nothing_foreign_crosses() {
    let verifier = Bls12381AggregateVerifier::new();
    let committee = vec![pubkey(PK_A), pubkey(PK_B), pubkey(PK_C)];
    let signed = message(MESSAGE_ABAB);
    let aggregate = signature(AGGREGATE_ABAB_VALID);
    assert!(verifier.fast_aggregate_verify(&committee, &signed, &aggregate));
    assert!(!verifier.fast_aggregate_verify(&committee, &signed, &signature(AGGREGATE_ABAB_TAMPERED)));

    let signer = SoftSigner::from_seed(0, &[0x09u8; 32]);
    let fact = translate(&lock(), &ctx(), 900_000);
    let env = package(&fact, &signer);

    let statement = corridor_statement(signer.operator_id(), &fact);
    let commitment = prove_statement(&statement);
    assert!(verify_statement(&statement, &commitment));
    assert_eq!(env.stark.statement_digest, commitment.digest);
    assert_eq!(env.stark.statement_digest, statement.digest());

    let preimage = statement.preimage();
    let mut sponge = [0u8; 32];
    shake256(&preimage, &mut sponge);
    assert_eq!(shake256_256(&preimage), sponge);
    assert_eq!(&shake256_256(&preimage)[..], &absorb_output(SHAKE256_RATE, &preimage)[..32]);
    assert_eq!(commitment.digest, sponge);

    let crossings = env.cross().expect("the two pq artifacts admit through the door");
    assert_eq!(crossings[0].kind, PqArtifact::MlDsaAttestation);
    assert_eq!(crossings[1].kind, PqArtifact::HashStark);
    assert!(matches!(crossings[0].artifact, Artifact::Attestation(_)));
    assert!(matches!(crossings[1].artifact, Artifact::Stark(_)));

    let der = vec![0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd, 0xef, 0x02, 0x20, 0x11, 0x22, 0x33];
    assert_eq!(admit(&der), Err(Refused::Foreign));
    let mut g1 = vec![0xa0u8];
    g1.extend_from_slice(&[0x33u8; 47]);
    assert_eq!(admit(&g1), Err(Refused::Foreign));
    assert!(admit(&aggregate.0).is_err());
    assert!(admit(&committee[0].0).is_err());

    let mut poisoned = env.attestation.encode();
    poisoned.extend_from_slice(&committee[0].0);
    assert!(admit(&poisoned).is_err());
}
