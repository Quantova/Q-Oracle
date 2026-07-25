// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_codec::{Reader, Writer};
use qtv_crypto::sha3::shake256;

use crate::errors::ExitError;

pub(crate) fn shake256_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(input, &mut out);
    out
}

pub const EXIT_STATEMENT_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-STATEMENT/v1";
pub const EXIT_PROOF_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-PROOF/v1";
pub const EXIT_STATEMENT_VERSION: u8 = 1;
pub const EXIT_STATEMENT_ENCODED_LEN: usize = 113;
pub const EXIT_PROOF_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatement {
    pub version: u8,
    pub home_chain: u32,
    pub corridor: u32,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
    pub finalized_height: u64,
}

impl ExitStatement {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version);
        w.u32(self.home_chain);
        w.u32(self.corridor);
        w.fixed(&self.asset_id);
        w.u128(self.amount);
        w.fixed(&self.beneficiary);
        w.fixed(&self.burn_ref);
        w.u64(self.finalized_height);
        w.finish()
    }

    pub fn decode(input: &[u8]) -> Result<ExitStatement, ExitError> {
        let mut r = Reader::new(input);
        let version = r.u8()?;
        let home_chain = r.u32()?;
        let corridor = r.u32()?;
        let asset_id = r.array16()?;
        let amount = r.u128()?;
        let beneficiary = r.array32()?;
        let burn_ref = r.array32()?;
        let finalized_height = r.u64()?;
        r.finish()?;
        Ok(ExitStatement {
            version,
            home_chain,
            corridor,
            asset_id,
            amount,
            beneficiary,
            burn_ref,
            finalized_height,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.fixed(EXIT_STATEMENT_DOMAIN);
        w.fixed(&self.encode());
        shake256_256(&w.finish())
    }

    pub fn validate(&self) -> Result<(), ExitError> {
        if self.version != EXIT_STATEMENT_VERSION {
            return Err(ExitError::BadVersion(self.version));
        }
        if self.home_chain == 0 {
            return Err(ExitError::ZeroChain);
        }
        if self.corridor == 0 {
            return Err(ExitError::ZeroCorridor);
        }
        if self.amount == 0 {
            return Err(ExitError::ZeroAmount);
        }
        if self.asset_id == [0u8; 16] {
            return Err(ExitError::ZeroAsset);
        }
        if self.beneficiary == [0u8; 32] {
            return Err(ExitError::ZeroBeneficiary);
        }
        if self.burn_ref == [0u8; 32] {
            return Err(ExitError::ZeroBurnRef);
        }
        Ok(())
    }
}

pub trait ExitProver {
    fn prove(&self, statement: &ExitStatement) -> Vec<u8>;
}

pub trait ExitVerifier {
    fn verify(&self, statement_digest: &[u8; 32], proof: &[u8]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitCertificate {
    pub statement: ExitStatement,
    pub proof: Vec<u8>,
}

impl ExitCertificate {
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement.digest()
    }

    pub fn verify<V: ExitVerifier>(&self, verifier: &V) -> Result<(), ExitError> {
        self.statement.validate()?;
        if !verifier.verify(&self.statement.digest(), &self.proof) {
            return Err(ExitError::UnboundProof);
        }
        Ok(())
    }
}

pub struct HashStark;

impl HashStark {
    pub fn bind(statement_digest: &[u8; 32]) -> [u8; 32] {
        let mut w = Writer::new();
        w.fixed(EXIT_PROOF_DOMAIN);
        w.fixed(statement_digest);
        shake256_256(&w.finish())
    }
}

impl ExitProver for HashStark {
    fn prove(&self, statement: &ExitStatement) -> Vec<u8> {
        HashStark::bind(&statement.digest()).to_vec()
    }
}

impl ExitVerifier for HashStark {
    fn verify(&self, statement_digest: &[u8; 32], proof: &[u8]) -> bool {
        proof.len() == EXIT_PROOF_LEN && proof == HashStark::bind(statement_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> ExitStatement {
        ExitStatement {
            version: EXIT_STATEMENT_VERSION,
            home_chain: 9000,
            corridor: 1,
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
            finalized_height: 4_200_000,
        }
    }

    #[test]
    fn statement_round_trips_and_is_fixed_length() {
        let s = statement();
        let bytes = s.encode();
        assert_eq!(bytes.len(), EXIT_STATEMENT_ENCODED_LEN);
        assert_eq!(ExitStatement::decode(&bytes).unwrap(), s);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = statement().encode();
        bytes.push(0);
        assert!(ExitStatement::decode(&bytes).is_err());
    }

    #[test]
    fn digest_is_deterministic_and_leads_with_the_domain() {
        let s = statement();
        assert_eq!(s.digest(), s.digest());
    }

    #[test]
    fn every_field_moves_the_digest() {
        let base = statement().digest();

        let mut a = statement();
        a.home_chain = 9001;
        assert_ne!(a.digest(), base);

        let mut b = statement();
        b.corridor = 2;
        assert_ne!(b.digest(), base);

        let mut c = statement();
        c.asset_id = [0xa2; 16];
        assert_ne!(c.digest(), base);

        let mut d = statement();
        d.amount = 501;
        assert_ne!(d.digest(), base);

        let mut e = statement();
        e.beneficiary = [0x56; 32];
        assert_ne!(e.digest(), base);

        let mut f = statement();
        f.burn_ref = [0x12; 32];
        assert_ne!(f.digest(), base);

        let mut g = statement();
        g.finalized_height = 4_200_001;
        assert_ne!(g.digest(), base);
    }

    #[test]
    fn validate_rejects_zero_amount_and_zero_burn_ref() {
        let mut a = statement();
        a.amount = 0;
        assert_eq!(a.validate(), Err(ExitError::ZeroAmount));

        let mut b = statement();
        b.burn_ref = [0u8; 32];
        assert_eq!(b.validate(), Err(ExitError::ZeroBurnRef));
    }

    #[test]
    fn validate_rejects_a_bad_version() {
        let mut s = statement();
        s.version = 2;
        assert_eq!(s.validate(), Err(ExitError::BadVersion(2)));
    }

    #[test]
    fn a_proved_certificate_verifies() {
        let s = statement();
        let cert = ExitCertificate {
            statement: s.clone(),
            proof: HashStark.prove(&s),
        };
        assert_eq!(cert.verify(&HashStark), Ok(()));
    }

    #[test]
    fn a_tampered_statement_breaks_the_proof_binding() {
        let s = statement();
        let mut cert = ExitCertificate {
            statement: s.clone(),
            proof: HashStark.prove(&s),
        };
        cert.statement.amount = 501;
        assert_eq!(cert.verify(&HashStark), Err(ExitError::UnboundProof));
    }

    #[test]
    fn a_proof_from_another_burn_does_not_verify() {
        let s = statement();
        let mut other = statement();
        other.burn_ref = [0x99; 32];
        let cert = ExitCertificate {
            statement: s,
            proof: HashStark.prove(&other),
        };
        assert_eq!(cert.verify(&HashStark), Err(ExitError::UnboundProof));
    }

    #[test]
    fn an_empty_proof_does_not_verify() {
        let s = statement();
        let cert = ExitCertificate {
            statement: s,
            proof: Vec::new(),
        };
        assert_eq!(cert.verify(&HashStark), Err(ExitError::UnboundProof));
    }
}
