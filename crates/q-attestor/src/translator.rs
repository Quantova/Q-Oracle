use q_airlock::{Artifact, AttestationEnvelope, SignerSig, StarkEnvelope};
use q_codec::{
    AssetId, BridgeFact, Direction, Recipient, SourceRef, Writer, ATTEST_DOMAIN, FACT_VERSION,
};
use qtv_crypto::sha3::sha3_256;

use crate::signer::AttestationSigner;
use crate::watcher::{CorridorContext, ObservedLock};

pub const CORRIDOR_STARK_STATEMENT_DOMAIN: &[u8] =
    b"QUANTOVA/Q-ORACLE/CORRIDOR-STARK-STATEMENT/v1";
pub const CORRIDOR_STARK_PROOF_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/CORRIDOR-STARK-PROOF/v1";

pub fn translate(lock: &ObservedLock, ctx: &CorridorContext) -> BridgeFact {
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&lock.source_ref[0..8]);
    BridgeFact {
        version: FACT_VERSION,
        source_chain: lock.source_chain,
        dest_chain: ctx.dest_chain,
        route_id: ctx.route_id,
        direction: Direction::Deposit,
        nonce: u64::from_le_bytes(nonce_bytes),
        source_ref: SourceRef(lock.source_ref),
        asset_id: AssetId(lock.asset_id),
        amount: lock.amount,
        recipient: Recipient(lock.recipient),
        finality_depth: lock.confirmations,
        observed_height: lock.observed_height,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundEnvelope {
    pub attestation: AttestationEnvelope,
    pub stark: StarkEnvelope,
}

impl OutboundEnvelope {
    pub fn artifacts(&self) -> [Artifact; 2] {
        [
            Artifact::Attestation(self.attestation.clone()),
            Artifact::Stark(self.stark.clone()),
        ]
    }
}

pub fn attest<S: AttestationSigner>(fact: &BridgeFact, signer: &S) -> AttestationEnvelope {
    let preimage = fact.attest_preimage();
    let signature = signer.sign(&preimage, ATTEST_DOMAIN);
    AttestationEnvelope {
        fact: fact.clone(),
        signatures: vec![SignerSig {
            operator_id: signer.operator_id(),
            signature: signature.to_vec(),
        }],
    }
}

pub fn corridor_stark_statement_digest(fact: &BridgeFact) -> [u8; 32] {
    let mut w = Writer::new();
    w.fixed(CORRIDOR_STARK_STATEMENT_DOMAIN);
    w.fixed(&fact.attest_preimage());
    sha3_256(&w.finish())
}

pub fn corridor_stark(fact: &BridgeFact) -> StarkEnvelope {
    let statement_digest = corridor_stark_statement_digest(fact);
    let mut w = Writer::new();
    w.fixed(CORRIDOR_STARK_PROOF_DOMAIN);
    w.fixed(&statement_digest);
    StarkEnvelope {
        statement_digest,
        proof: sha3_256(&w.finish()).to_vec(),
    }
}

pub fn verify_corridor_stark(fact: &BridgeFact, envelope: &StarkEnvelope) -> bool {
    if envelope.statement_digest != corridor_stark_statement_digest(fact) {
        return false;
    }
    let mut w = Writer::new();
    w.fixed(CORRIDOR_STARK_PROOF_DOMAIN);
    w.fixed(&envelope.statement_digest);
    envelope.proof == sha3_256(&w.finish()).to_vec()
}

pub fn package<S: AttestationSigner>(fact: &BridgeFact, signer: &S) -> OutboundEnvelope {
    OutboundEnvelope {
        attestation: attest(fact, signer),
        stark: corridor_stark(fact),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftSigner;
    use qtv_crypto::ml_dsa::{self, SIGNATURE_BYTES};

    fn ctx() -> CorridorContext {
        CorridorContext {
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            required_confirmations: 6,
        }
    }

    fn lock() -> ObservedLock {
        ObservedLock {
            source_chain: 1,
            source_ref: [0x11u8; 32],
            asset_id: [0x22u8; 16],
            amount: 500,
            recipient: [0x33u8; 32],
            observed_height: 800_001,
            confirmations: 6,
        }
    }

    fn fact() -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            direction: Direction::Deposit,
            nonce: 42,
            source_ref: SourceRef([9u8; 32]),
            asset_id: AssetId([3u8; 16]),
            amount: 1_000_000,
            recipient: Recipient([5u8; 32]),
            finality_depth: 12,
            observed_height: 880_000,
        }
    }

    fn signer() -> SoftSigner {
        SoftSigner::from_seed(0, &[0x09u8; 32])
    }

    fn reshapes() -> Vec<BridgeFact> {
        let mut out = Vec::new();

        let mut a = fact();
        a.source_chain = 2;
        out.push(a);

        let mut b = fact();
        b.dest_chain = 9001;
        out.push(b);

        let mut c = fact();
        c.route_id = 8;
        out.push(c);

        let mut d = fact();
        d.direction = Direction::ExitAck;
        out.push(d);

        let mut e = fact();
        e.nonce = 43;
        out.push(e);

        let mut g = fact();
        g.source_ref = SourceRef([8u8; 32]);
        out.push(g);

        let mut h = fact();
        h.asset_id = AssetId([4u8; 16]);
        out.push(h);

        let mut i = fact();
        i.amount = 1_000_001;
        out.push(i);

        let mut j = fact();
        j.recipient = Recipient([6u8; 32]);
        out.push(j);

        let mut k = fact();
        k.finality_depth = 13;
        out.push(k);

        let mut l = fact();
        l.observed_height = 880_001;
        out.push(l);

        out
    }

    #[test]
    fn translation_is_byte_deterministic_across_operators() {
        let a = translate(&lock(), &ctx());
        let b = translate(&lock(), &ctx());
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn translated_fact_validates() {
        assert!(translate(&lock(), &ctx()).validate().is_ok());
    }

    #[test]
    fn package_carries_exactly_the_two_pq_artifacts() {
        let env = package(&fact(), &signer());
        let artifacts = env.artifacts();
        assert_eq!(artifacts.len(), 2);
        assert!(matches!(artifacts[0], Artifact::Attestation(_)));
        assert!(matches!(artifacts[1], Artifact::Stark(_)));
    }

    #[test]
    fn the_attestation_binds_the_fact_over_the_attest_preimage() {
        let s = signer();
        let pk = s.public_key();
        let f = fact();
        let env = package(&f, &s);
        assert_eq!(env.attestation.fact, f);
        assert_eq!(env.attestation.signatures.len(), 1);
        assert_eq!(env.attestation.signatures[0].operator_id, s.operator_id());
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&env.attestation.signatures[0].signature);
        assert!(ml_dsa::verify(&pk, &f.attest_preimage(), &sig, ATTEST_DOMAIN));
    }

    #[test]
    fn the_attestation_is_bound_to_the_attest_domain() {
        let s = signer();
        let pk = s.public_key();
        let f = fact();
        let env = package(&f, &s);
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&env.attestation.signatures[0].signature);
        assert!(!ml_dsa::verify(&pk, &f.attest_preimage(), &sig, b"QUANTOVA/Q-ORACLE/REORG/v1"));
    }

    #[test]
    fn no_field_can_be_reshaped_under_the_attestation() {
        let s = signer();
        let pk = s.public_key();
        let base = fact();
        let env = package(&base, &s);
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&env.attestation.signatures[0].signature);
        assert!(ml_dsa::verify(&pk, &base.attest_preimage(), &sig, ATTEST_DOMAIN));
        for reshaped in reshapes() {
            assert_ne!(reshaped, base);
            assert!(!ml_dsa::verify(&pk, &reshaped.attest_preimage(), &sig, ATTEST_DOMAIN));
        }
    }

    #[test]
    fn no_field_can_be_reshaped_under_the_stark() {
        let base = fact();
        let env = package(&base, &signer());
        assert!(verify_corridor_stark(&base, &env.stark));
        for reshaped in reshapes() {
            assert_ne!(reshaped, base);
            assert_ne!(
                corridor_stark_statement_digest(&reshaped),
                env.stark.statement_digest
            );
            assert!(!verify_corridor_stark(&reshaped, &env.stark));
        }
    }

    #[test]
    fn the_stark_proof_is_bound_to_its_statement() {
        let f = fact();
        let env = package(&f, &signer());
        assert!(verify_corridor_stark(&f, &env.stark));

        let mut moved_digest = env.stark.clone();
        moved_digest.statement_digest[0] ^= 0x01;
        assert!(!verify_corridor_stark(&f, &moved_digest));

        let mut moved_proof = env.stark.clone();
        moved_proof.proof[0] ^= 0x01;
        assert!(!verify_corridor_stark(&f, &moved_proof));
    }

    #[test]
    fn both_artifacts_cross_the_airlock_as_exactly_their_q_form() {
        let f = fact();
        let env = package(&f, &signer());

        let attestation_bytes = env.attestation.encode();
        match q_airlock::parse(&attestation_bytes).unwrap() {
            Artifact::Attestation(got) => {
                assert_eq!(got.fact, f);
                assert_eq!(got, env.attestation);
            }
            _ => panic!("the attestation must read back as an attestation"),
        }

        let stark_bytes = env.stark.encode();
        match q_airlock::parse(&stark_bytes).unwrap() {
            Artifact::Stark(got) => assert_eq!(got, env.stark),
            _ => panic!("the stark must read back as a stark"),
        }
    }

    #[test]
    fn no_foreign_bytes_can_ride_beside_either_artifact() {
        let env = package(&fact(), &signer());

        let mut attestation = env.attestation.encode();
        attestation.extend_from_slice(&[0xf9, 0x02, 0x1a]);
        assert!(q_airlock::parse(&attestation).is_err());

        let mut stark = env.stark.encode();
        stark.extend_from_slice(&[0x30, 0x45, 0x02, 0x21]);
        assert!(q_airlock::parse(&stark).is_err());
    }

    #[test]
    fn the_choke_point_turns_a_foreign_observation_into_the_two_pq_artifacts() {
        let translated = translate(&lock(), &ctx());
        let env = package(&translated, &signer());

        assert!(verify_corridor_stark(&translated, &env.stark));
        assert!(matches!(
            q_airlock::parse(&env.attestation.encode()).unwrap(),
            Artifact::Attestation(_)
        ));
        assert!(matches!(
            q_airlock::parse(&env.stark.encode()).unwrap(),
            Artifact::Stark(_)
        ));
    }

    #[test]
    fn packaging_is_deterministic_across_operators() {
        let a = package(&fact(), &signer());
        let b = package(&fact(), &signer());
        assert_eq!(a, b);
    }
}
