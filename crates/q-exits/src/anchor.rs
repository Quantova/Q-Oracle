// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::committee::MemberKey;
use qtv_attest::{Beacon, CommitteeCommitment};
use qtv_sampler::onetime::Root;

use crate::errors::ExitError;

pub const ATTEST_PK_BYTES: usize = qtv_crypto::ml_dsa::PUBLIC_KEY_BYTES;
pub const BEACON_SEED_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberConfig {
    pub id: u64,
    pub weight: u64,
    pub root_digest: [u8; 32],
    pub root_slots: u64,
    pub attest_pk: Vec<u8>,
}

pub struct QuantovaAnchor {
    chain_id: u64,
    tau: u64,
    commitment: CommitteeCommitment,
    beacon: Beacon,
}

impl QuantovaAnchor {
    pub fn from_config(
        chain_id: u64,
        tau: u64,
        slot: u64,
        budget: u64,
        beacon_seed: [u8; BEACON_SEED_BYTES],
        members: Vec<MemberConfig>,
    ) -> Result<QuantovaAnchor, ExitError> {
        if chain_id == 0 || tau == 0 {
            return Err(ExitError::UnsetAnchor);
        }
        if members.is_empty() {
            return Err(ExitError::UnsetAnchor);
        }
        let mut keys: Vec<MemberKey> = Vec::with_capacity(members.len());
        for member in members {
            if member.attest_pk.len() != ATTEST_PK_BYTES {
                return Err(ExitError::BadPublicKeyLen);
            }
            let mut attest_pk = [0u8; ATTEST_PK_BYTES];
            attest_pk.copy_from_slice(&member.attest_pk);
            keys.push(MemberKey {
                id: member.id,
                weight: member.weight,
                root: Root {
                    digest: member.root_digest,
                    slots: member.root_slots,
                },
                attest_pk,
            });
        }
        if tau as usize > keys.len() {
            return Err(ExitError::TauAboveCommittee);
        }
        let need = qtv_sampler::params::finality_threshold(keys.len() as u64);
        if tau < need {
            return Err(ExitError::TauBelowQuorum { tau, need });
        }
        let commitment = CommitteeCommitment::from_member_keys(slot, keys, budget);
        Ok(QuantovaAnchor {
            chain_id,
            tau,
            commitment,
            beacon: Beacon::from_seed(beacon_seed),
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn tau(&self) -> u64 {
        self.tau
    }

    pub fn commitment(&self) -> &CommitteeCommitment {
        &self.commitment
    }

    pub fn beacon(&self) -> &Beacon {
        &self.beacon
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> MemberConfig {
        MemberConfig {
            id: 1,
            weight: 100,
            root_digest: [0x11; 32],
            root_slots: 64,
            attest_pk: vec![0u8; ATTEST_PK_BYTES],
        }
    }

    #[test]
    fn a_zero_chain_id_is_refused() {
        assert_eq!(
            QuantovaAnchor::from_config(0, 1, 0, 100, [0u8; 32], vec![member()]).err(),
            Some(ExitError::UnsetAnchor)
        );
    }

    #[test]
    fn a_zero_tau_is_refused() {
        assert_eq!(
            QuantovaAnchor::from_config(1, 0, 0, 100, [0u8; 32], vec![member()]).err(),
            Some(ExitError::UnsetAnchor)
        );
    }

    #[test]
    fn an_empty_committee_is_refused() {
        assert_eq!(
            QuantovaAnchor::from_config(1, 1, 0, 100, [0u8; 32], Vec::new()).err(),
            Some(ExitError::UnsetAnchor)
        );
    }

    #[test]
    fn a_tau_above_the_committee_is_refused() {
        assert_eq!(
            QuantovaAnchor::from_config(1, 2, 0, 100, [0u8; 32], vec![member()]).err(),
            Some(ExitError::TauAboveCommittee)
        );
    }

    #[test]
    fn a_short_public_key_is_refused() {
        let mut m = member();
        m.attest_pk = vec![0u8; ATTEST_PK_BYTES - 1];
        assert_eq!(
            QuantovaAnchor::from_config(1, 1, 0, 100, [0u8; 32], vec![m]).err(),
            Some(ExitError::BadPublicKeyLen)
        );
    }

    #[test]
    fn a_tau_below_the_committee_supermajority_is_refused() {
        let committee: Vec<MemberConfig> = (1..=4)
            .map(|id| MemberConfig { id, ..member() })
            .collect();
        // Four members need a finality threshold of three; a tau of two would let a
        // sub-final certificate forge a burn.
        assert_eq!(
            QuantovaAnchor::from_config(1, 2, 0, 100, [0u8; 32], committee).err(),
            Some(ExitError::TauBelowQuorum { tau: 2, need: 3 })
        );
    }

    #[test]
    fn a_well_formed_anchor_holds_its_fields() {
        let anchor = QuantovaAnchor::from_config(9000, 1, 0, 100, [0x5a; 32], vec![member()]).unwrap();
        assert_eq!(anchor.chain_id(), 9000);
        assert_eq!(anchor.tau(), 1);
        assert_eq!(anchor.commitment().len(), 1);
    }
}
