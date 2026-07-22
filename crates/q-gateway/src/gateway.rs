use std::collections::{BTreeMap, BTreeSet};

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{BridgeFact, Direction, Writer, ATTEST_DOMAIN};

use crate::errors::GatewayError;
use crate::operators::{verify_quorum, OperatorSet};

pub const REORG_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/REORG/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorridorConfig {
    pub confirmation_depth: u32,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintReceipt {
    pub asset_id: [u8; 16],
    pub recipient: [u8; 32],
    pub amount: u128,
    pub source_ref: [u8; 32],
}

pub struct Gateway {
    chain_id: u32,
    operators: OperatorSet,
    used_refs: BTreeSet<[u8; 32]>,
    per_asset_minted: BTreeMap<[u8; 16], u128>,
    per_asset_cap: BTreeMap<[u8; 16], u128>,
    epoch_cap: u128,
    epoch_minted: u128,
    current_epoch: u64,
    corridors: BTreeMap<u32, CorridorConfig>,
    paused_sources: BTreeSet<u32>,
    global_pause: bool,
}

impl Gateway {
    pub fn new(chain_id: u32, operators: OperatorSet, epoch_cap: u128) -> Gateway {
        Gateway {
            chain_id,
            operators,
            used_refs: BTreeSet::new(),
            per_asset_minted: BTreeMap::new(),
            per_asset_cap: BTreeMap::new(),
            epoch_cap,
            epoch_minted: 0,
            current_epoch: 0,
            corridors: BTreeMap::new(),
            paused_sources: BTreeSet::new(),
            global_pause: false,
        }
    }

    pub fn register_corridor(&mut self, source_chain: u32, confirmation_depth: u32) {
        self.corridors.insert(
            source_chain,
            CorridorConfig {
                confirmation_depth,
                active: true,
            },
        );
    }

    pub fn set_corridor_active(&mut self, source_chain: u32, active: bool) {
        if let Some(c) = self.corridors.get_mut(&source_chain) {
            c.active = active;
        }
    }

    pub fn register_asset_cap(&mut self, asset_id: [u8; 16], cap: u128) {
        self.per_asset_cap.insert(asset_id, cap);
    }

    pub fn pause_all(&mut self) {
        self.global_pause = true;
    }

    pub fn unpause_all(&mut self) {
        self.global_pause = false;
    }

    pub fn pause_source_direct(&mut self, source_chain: u32) {
        self.paused_sources.insert(source_chain);
    }

    pub fn unpause_source(&mut self, source_chain: u32) {
        self.paused_sources.remove(&source_chain);
    }

    pub fn advance_epoch(&mut self) {
        self.current_epoch += 1;
        self.epoch_minted = 0;
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn epoch_minted(&self) -> u128 {
        self.epoch_minted
    }

    pub fn minted_of_asset(&self, asset_id: &[u8; 16]) -> u128 {
        *self.per_asset_minted.get(asset_id).unwrap_or(&0)
    }

    pub fn minted_by_asset(&self) -> &BTreeMap<[u8; 16], u128> {
        &self.per_asset_minted
    }

    pub fn is_source_paused(&self, source_chain: u32) -> bool {
        self.paused_sources.contains(&source_chain)
    }

    pub fn is_reference_used(&self, source_ref: &[u8; 32]) -> bool {
        self.used_refs.contains(source_ref)
    }

    pub fn report_reorg(
        &mut self,
        source_chain: u32,
        fork_depth: u32,
        sigs: &[SignerSig],
    ) -> Result<(), GatewayError> {
        let mut w = Writer::new();
        w.u32(source_chain);
        w.u32(fork_depth);
        let message = w.finish();
        let distinct = verify_quorum(&message, REORG_DOMAIN, sigs, &self.operators)?;
        if distinct.len() < self.operators.threshold() {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need: self.operators.threshold(),
            });
        }
        self.paused_sources.insert(source_chain);
        Ok(())
    }

    pub fn process_deposit(
        &mut self,
        env: &AttestationEnvelope,
    ) -> Result<MintReceipt, GatewayError> {
        if self.global_pause {
            return Err(GatewayError::GlobalPause);
        }
        let fact = &env.fact;
        if fact.is_zero() {
            return Err(GatewayError::ProveNothing);
        }
        fact.validate()?;
        if fact.direction != Direction::Deposit {
            return Err(GatewayError::WrongDirection);
        }
        if fact.dest_chain != self.chain_id {
            return Err(GatewayError::WrongDestination);
        }
        let corridor = self
            .corridors
            .get(&fact.source_chain)
            .copied()
            .ok_or(GatewayError::CorridorNotOpen(fact.source_chain))?;
        if !corridor.active {
            return Err(GatewayError::CorridorInactive(fact.source_chain));
        }
        if self.paused_sources.contains(&fact.source_chain) {
            return Err(GatewayError::SourcePaused(fact.source_chain));
        }
        if fact.finality_depth < corridor.confirmation_depth {
            return Err(GatewayError::InsufficientFinality {
                got: fact.finality_depth,
                need: corridor.confirmation_depth,
            });
        }

        let message = fact.encode();
        let distinct = verify_quorum(&message, ATTEST_DOMAIN, &env.signatures, &self.operators)?;
        let threshold = self.operators.threshold();
        if distinct.len() < threshold {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need: threshold,
            });
        }

        let cap = *self
            .per_asset_cap
            .get(&fact.asset_id.0)
            .ok_or(GatewayError::AssetNotRegistered)?;
        let minted = *self.per_asset_minted.get(&fact.asset_id.0).unwrap_or(&0);
        let asset_after = minted
            .checked_add(fact.amount)
            .ok_or(GatewayError::AssetCapExceeded {
                minted,
                cap,
                add: fact.amount,
            })?;
        if asset_after > cap {
            return Err(GatewayError::AssetCapExceeded {
                minted,
                cap,
                add: fact.amount,
            });
        }

        let epoch_after =
            self.epoch_minted
                .checked_add(fact.amount)
                .ok_or(GatewayError::EpochCapExceeded {
                    minted: self.epoch_minted,
                    cap: self.epoch_cap,
                    add: fact.amount,
                })?;
        if epoch_after > self.epoch_cap {
            return Err(GatewayError::EpochCapExceeded {
                minted: self.epoch_minted,
                cap: self.epoch_cap,
                add: fact.amount,
            });
        }

        if self.used_refs.contains(&fact.source_ref.0) {
            return Err(GatewayError::ReplayedReference);
        }

        self.used_refs.insert(fact.source_ref.0);
        self.per_asset_minted.insert(fact.asset_id.0, asset_after);
        self.epoch_minted = epoch_after;

        Ok(MintReceipt {
            asset_id: fact.asset_id.0,
            recipient: fact.recipient.0,
            amount: fact.amount,
            source_ref: fact.source_ref.0,
        })
    }
}

pub fn attestation_message(fact: &BridgeFact) -> Vec<u8> {
    fact.encode()
}
