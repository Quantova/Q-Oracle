use q_codec::{Reader, Writer};
use qtv_crypto::sha3::sha3_256;

use crate::certificate::ExitStatement;
use crate::errors::ExitError;

pub const PAYOUT_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-PAYOUT/v1";
pub const PAYOUT_VERSION: u8 = 1;
pub const PAYOUT_ENCODED_LEN: usize = 141;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutAttestation {
    pub version: u8,
    pub corridor: u32,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: [u8; 32],
    pub foreign_ref: [u8; 32],
    pub proof_height: u64,
}

impl PayoutAttestation {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version);
        w.u32(self.corridor);
        w.fixed(&self.asset_id);
        w.u128(self.amount);
        w.fixed(&self.beneficiary);
        w.fixed(&self.burn_ref);
        w.fixed(&self.foreign_ref);
        w.u64(self.proof_height);
        w.finish()
    }

    pub fn decode(input: &[u8]) -> Result<PayoutAttestation, ExitError> {
        let mut r = Reader::new(input);
        let version = r.u8()?;
        let corridor = r.u32()?;
        let asset_id = r.array16()?;
        let amount = r.u128()?;
        let beneficiary = r.array32()?;
        let burn_ref = r.array32()?;
        let foreign_ref = r.array32()?;
        let proof_height = r.u64()?;
        r.finish()?;
        Ok(PayoutAttestation {
            version,
            corridor,
            asset_id,
            amount,
            beneficiary,
            burn_ref,
            foreign_ref,
            proof_height,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.fixed(PAYOUT_DOMAIN);
        w.fixed(&self.encode());
        sha3_256(&w.finish())
    }

    pub fn validate(&self) -> Result<(), ExitError> {
        if self.version != PAYOUT_VERSION {
            return Err(ExitError::BadVersion(self.version));
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

    pub fn covers(&self, statement: &ExitStatement) -> bool {
        self.corridor == statement.corridor
            && self.asset_id == statement.asset_id
            && self.amount == statement.amount
            && self.beneficiary == statement.beneficiary
            && self.burn_ref == statement.burn_ref
    }
}

pub trait PayoutWatcher {
    fn corridor(&self) -> u32;
    fn confirm(&self, statement: &ExitStatement) -> Option<PayoutAttestation>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::EXIT_STATEMENT_VERSION;

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

    fn attestation() -> PayoutAttestation {
        PayoutAttestation {
            version: PAYOUT_VERSION,
            corridor: 1,
            asset_id: [0xa1; 16],
            amount: 500,
            beneficiary: [0x55; 32],
            burn_ref: [0x11; 32],
            foreign_ref: [0x77; 32],
            proof_height: 880_100,
        }
    }

    #[test]
    fn attestation_round_trips_and_is_fixed_length() {
        let a = attestation();
        let bytes = a.encode();
        assert_eq!(bytes.len(), PAYOUT_ENCODED_LEN);
        assert_eq!(PayoutAttestation::decode(&bytes).unwrap(), a);
    }

    #[test]
    fn the_foreign_reference_moves_the_digest() {
        let base = attestation().digest();
        let mut other = attestation();
        other.foreign_ref = [0x78; 32];
        assert_ne!(other.digest(), base);
    }

    #[test]
    fn a_matching_attestation_covers_the_exit() {
        assert!(attestation().covers(&statement()));
    }

    #[test]
    fn a_wrong_beneficiary_does_not_cover_the_exit() {
        let mut a = attestation();
        a.beneficiary = [0x66; 32];
        assert!(!a.covers(&statement()));
    }

    #[test]
    fn a_short_payout_does_not_cover_the_exit() {
        let mut a = attestation();
        a.amount = 499;
        assert!(!a.covers(&statement()));
    }

    #[test]
    fn an_attestation_for_another_burn_does_not_cover_the_exit() {
        let mut a = attestation();
        a.burn_ref = [0x12; 32];
        assert!(!a.covers(&statement()));
    }

    #[test]
    fn validate_rejects_a_zero_beneficiary() {
        let mut a = attestation();
        a.beneficiary = [0u8; 32];
        assert_eq!(a.validate(), Err(ExitError::ZeroBeneficiary));
    }
}
