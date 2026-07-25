use std::collections::{BTreeMap, BTreeSet};

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{BridgeFact, CodecError, Direction, Writer, ATTEST_DOMAIN};

use crate::errors::GatewayError;
use crate::operators::{verify_quorum, OperatorSet};

pub const REORG_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/REORG/v1";
pub const TIER_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/TIER/v1";
pub const FREEZE_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/FREEZE/v1";
pub const WATCHDOG_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/WATCHDOG/v1";
pub const BATCH_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/BATCH/v1";
pub const BASE_TIER: u8 = 1;
pub const WATCHDOG_MAX_WINDOW: u64 = 7_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorridorConfig {
    pub confirmation_depth: u32,
    pub quorum: usize,
    pub tier: u8,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitTicket {
    pub exit_id: u64,
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub destination: [u8; 32],
    pub unlock_height: u64,
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
    governance: OperatorSet,
    used_refs: BTreeSet<[u8; 32]>,
    highest_nonce: BTreeMap<(u32, u8), u64>,
    per_asset_minted: BTreeMap<[u8; 16], u128>,
    per_asset_cap: BTreeMap<[u8; 16], u128>,
    epoch_cap: u128,
    epoch_minted: u128,
    current_epoch: u64,
    corridors: BTreeMap<u32, CorridorConfig>,
    corridor_cursor: BTreeMap<u32, u64>,
    paused_sources: BTreeSet<u32>,
    global_pause: bool,
    current_height: u64,
    frozen_until: u64,
    exit_delay: u64,
    next_exit_id: u64,
    pending_exits: BTreeMap<u64, ExitTicket>,
}

impl Gateway {
    pub fn new(chain_id: u32, operators: OperatorSet, epoch_cap: u128) -> Gateway {
        Gateway {
            chain_id,
            operators,
            governance: OperatorSet::new(0),
            used_refs: BTreeSet::new(),
            highest_nonce: BTreeMap::new(),
            per_asset_minted: BTreeMap::new(),
            per_asset_cap: BTreeMap::new(),
            epoch_cap,
            epoch_minted: 0,
            current_epoch: 0,
            corridors: BTreeMap::new(),
            corridor_cursor: BTreeMap::new(),
            paused_sources: BTreeSet::new(),
            global_pause: false,
            current_height: 0,
            frozen_until: 0,
            exit_delay: 0,
            next_exit_id: 0,
            pending_exits: BTreeMap::new(),
        }
    }

    pub fn set_governance(&mut self, governance: OperatorSet) {
        self.governance = governance;
    }

    pub fn set_exit_delay(&mut self, exit_delay: u64) {
        self.exit_delay = exit_delay;
    }

    pub fn advance_to(&mut self, height: u64) {
        if height > self.current_height {
            self.current_height = height;
        }
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    pub fn frozen_until(&self) -> u64 {
        self.frozen_until
    }

    pub fn is_frozen(&self) -> bool {
        self.current_height < self.frozen_until
    }

    pub fn corridor_tier(&self, source_chain: u32) -> Option<u8> {
        self.corridors.get(&source_chain).map(|c| c.tier)
    }

    pub fn corridor_cursor(&self, source_chain: u32) -> u64 {
        *self.corridor_cursor.get(&source_chain).unwrap_or(&0)
    }

    pub fn register_corridor(&mut self, source_chain: u32, confirmation_depth: u32) {
        self.corridors.insert(
            source_chain,
            CorridorConfig {
                confirmation_depth,
                quorum: 0,
                tier: BASE_TIER,
                active: true,
            },
        );
    }

    pub fn set_corridor_active(&mut self, source_chain: u32, active: bool) {
        if let Some(c) = self.corridors.get_mut(&source_chain) {
            c.active = active;
        }
    }

    pub fn set_corridor_quorum(
        &mut self,
        source_chain: u32,
        quorum: usize,
    ) -> Result<(), GatewayError> {
        let size = self.operators.size();
        if quorum < 2 || quorum > size || quorum.saturating_mul(3) < size.saturating_mul(2) {
            return Err(GatewayError::ThinQuorum { quorum, size });
        }
        let corridor = self
            .corridors
            .get_mut(&source_chain)
            .ok_or(GatewayError::CorridorNotOpen(source_chain))?;
        corridor.quorum = quorum;
        Ok(())
    }

    pub fn corridor_quorum(&self, source_chain: u32) -> Option<usize> {
        self.corridors.get(&source_chain).map(|c| {
            if c.quorum > 0 {
                c.quorum
            } else {
                self.operators.threshold()
            }
        })
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

    pub fn set_corridor_tier(
        &mut self,
        source_chain: u32,
        proposed: u8,
        sigs: &[SignerSig],
    ) -> Result<(), GatewayError> {
        if self.governance.size() == 0 {
            return Err(GatewayError::NoGovernanceSet);
        }
        let mut w = Writer::new();
        w.u32(source_chain);
        w.u8(proposed);
        let message = w.finish();
        let distinct = verify_quorum(&message, TIER_DOMAIN, sigs, &self.governance)?;
        if distinct.len() < self.governance.threshold() {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need: self.governance.threshold(),
            });
        }
        let corridor = self
            .corridors
            .get_mut(&source_chain)
            .ok_or(GatewayError::CorridorNotOpen(source_chain))?;
        if proposed <= corridor.tier {
            return Err(GatewayError::TierDowngrade {
                from: corridor.tier,
                to: proposed,
            });
        }
        corridor.tier = proposed;
        Ok(())
    }

    pub fn emergency_freeze(
        &mut self,
        until_height: u64,
        sigs: &[SignerSig],
    ) -> Result<(), GatewayError> {
        let mut w = Writer::new();
        w.u64(until_height);
        let message = w.finish();
        let distinct = verify_quorum(&message, FREEZE_DOMAIN, sigs, &self.operators)?;
        if distinct.len() < self.operators.threshold() {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need: self.operators.threshold(),
            });
        }
        if until_height > self.frozen_until {
            self.frozen_until = until_height;
        }
        Ok(())
    }

    pub fn watchdog_freeze(
        &mut self,
        until_height: u64,
        sig: &SignerSig,
    ) -> Result<(), GatewayError> {
        let ceiling = self.current_height.saturating_add(WATCHDOG_MAX_WINDOW);
        if until_height > ceiling {
            return Err(GatewayError::WatchdogWindowTooWide {
                until: until_height,
                max: ceiling,
            });
        }
        let mut w = Writer::new();
        w.u64(until_height);
        let message = w.finish();
        verify_quorum(
            &message,
            WATCHDOG_DOMAIN,
            std::slice::from_ref(sig),
            &self.operators,
        )?;
        if until_height > self.frozen_until {
            self.frozen_until = until_height;
        }
        Ok(())
    }

    pub fn accept_batch(
        &mut self,
        source_chain: u32,
        batch_index: u64,
        sigs: &[SignerSig],
    ) -> Result<(), GatewayError> {
        let corridor = self
            .corridors
            .get(&source_chain)
            .copied()
            .ok_or(GatewayError::CorridorNotOpen(source_chain))?;
        if !corridor.active {
            return Err(GatewayError::CorridorInactive(source_chain));
        }
        let required = if corridor.quorum > 0 {
            corridor.quorum
        } else {
            self.operators.threshold()
        };
        let mut w = Writer::new();
        w.u32(source_chain);
        w.u64(batch_index);
        let message = w.finish();
        let distinct = verify_quorum(&message, BATCH_DOMAIN, sigs, &self.operators)?;
        if distinct.len() < required {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need: required,
            });
        }
        let cursor = *self.corridor_cursor.get(&source_chain).unwrap_or(&0);
        if batch_index != cursor {
            return Err(GatewayError::StaleBatch {
                got: batch_index,
                expected: cursor,
            });
        }
        self.corridor_cursor.insert(source_chain, cursor + 1);
        Ok(())
    }

    pub fn request_exit(
        &mut self,
        asset_id: [u8; 16],
        amount: u128,
        destination: [u8; 32],
    ) -> Result<ExitTicket, GatewayError> {
        if amount == 0 {
            return Err(GatewayError::InvalidFact(CodecError::ZeroAmount));
        }
        let minted = *self.per_asset_minted.get(&asset_id).unwrap_or(&0);
        if amount > minted {
            return Err(GatewayError::ExitExceedsMinted { minted, amount });
        }
        self.per_asset_minted.insert(asset_id, minted - amount);
        let exit_id = self.next_exit_id;
        self.next_exit_id += 1;
        let unlock_height = self.current_height.saturating_add(self.exit_delay);
        let ticket = ExitTicket {
            exit_id,
            asset_id,
            amount,
            destination,
            unlock_height,
        };
        self.pending_exits.insert(exit_id, ticket.clone());
        Ok(ticket)
    }

    pub fn finalize_exit(&mut self, exit_id: u64) -> Result<ExitTicket, GatewayError> {
        let ticket = self
            .pending_exits
            .get(&exit_id)
            .cloned()
            .ok_or(GatewayError::UnknownExit(exit_id))?;
        if self.current_height < ticket.unlock_height {
            return Err(GatewayError::ExitNotReady {
                now: self.current_height,
                unlock: ticket.unlock_height,
            });
        }
        self.pending_exits.remove(&exit_id);
        Ok(ticket)
    }

    pub fn process_deposit(
        &mut self,
        env: &AttestationEnvelope,
    ) -> Result<MintReceipt, GatewayError> {
        if self.global_pause {
            return Err(GatewayError::GlobalPause);
        }
        if self.current_height < self.frozen_until {
            return Err(GatewayError::Frozen {
                until: self.frozen_until,
            });
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
        if self.current_height > fact.expiry_height {
            return Err(GatewayError::MessageExpired {
                now: self.current_height,
                expiry: fact.expiry_height,
            });
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

        let size = self.operators.size();
        let required = if corridor.quorum > 0 {
            corridor.quorum
        } else {
            self.operators.threshold()
        };
        if required == 0 || required > size {
            return Err(GatewayError::ThinQuorum {
                quorum: required,
                size,
            });
        }

        let message = fact.attest_preimage();
        let distinct = verify_quorum(&message, ATTEST_DOMAIN, &env.signatures, &self.operators)?;
        if distinct.len() < required {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need: required,
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

        let direction_key = (fact.route_id, fact.direction.tag());
        if let Some(&high_water) = self.highest_nonce.get(&direction_key) {
            if fact.nonce <= high_water {
                return Err(GatewayError::StaleOrReplayedNonce {
                    got: fact.nonce,
                    high_water,
                });
            }
        }

        self.used_refs.insert(fact.source_ref.0);
        self.highest_nonce.insert(direction_key, fact.nonce);
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
    fact.attest_preimage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_codec::{AssetId, Recipient, SourceRef, FACT_VERSION};
    use qtv_crypto::ml_dsa;

    fn fact() -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef([0x11; 32]),
            asset_id: AssetId([0xa1; 16]),
            amount: 500,
            recipient: Recipient([0x55; 32]),
            finality_depth: 6,
            observed_height: 800_000,
            expiry_height: 900_000,
        }
    }

    fn signer(id: u32) -> (u32, ml_dsa::PublicKey, ml_dsa::SecretKey) {
        let mut seed = [0u8; 32];
        seed[0] = id as u8;
        seed[31] = 0x7c;
        let (pk, sk) = ml_dsa::keygen(&seed);
        (id, pk, sk)
    }

    fn sign(sk: &ml_dsa::SecretKey, id: u32, f: &BridgeFact) -> SignerSig {
        let sig = ml_dsa::sign(sk, &f.attest_preimage(), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
        SignerSig {
            operator_id: id,
            signature: sig.to_vec(),
        }
    }

    #[test]
    fn verify_reads_the_preimage_the_operator_signed() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);

        let f = fact();
        let env = AttestationEnvelope {
            fact: f.clone(),
            signatures: s.iter().map(|(id, _, sk)| sign(sk, *id, &f)).collect(),
        };
        let receipt = gw.process_deposit(&env).expect("quorum over the preimage mints");
        assert_eq!(receipt.amount, 500);
    }

    fn nine_op_gateway(global: usize) -> (Vec<(u32, ml_dsa::PublicKey, ml_dsa::SecretKey)>, Gateway) {
        let s: Vec<_> = (0..9).map(signer).collect();
        let mut set = OperatorSet::new(global);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);
        (s, gw)
    }

    fn envelope(
        s: &[(u32, ml_dsa::PublicKey, ml_dsa::SecretKey)],
        f: &BridgeFact,
    ) -> AttestationEnvelope {
        AttestationEnvelope {
            fact: f.clone(),
            signatures: s.iter().map(|(id, _, sk)| sign(sk, *id, f)).collect(),
        }
    }

    #[test]
    fn corridor_quorum_overrides_the_global_threshold() {
        let (s, mut gw) = nine_op_gateway(3);
        gw.set_corridor_quorum(1, 6).expect("two thirds is a wide margin");
        assert_eq!(gw.corridor_quorum(1), Some(6));

        let f = fact();
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..5], &f)),
            Err(GatewayError::BelowThreshold { got: 5, need: 6 })
        );
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..6], &f)).expect("wide margin mints").amount,
            500
        );
    }

    #[test]
    fn a_bare_majority_corridor_quorum_is_refused() {
        let (_s, mut gw) = nine_op_gateway(3);
        assert_eq!(
            gw.set_corridor_quorum(1, 5),
            Err(GatewayError::ThinQuorum { quorum: 5, size: 9 })
        );
    }

    #[test]
    fn a_zero_corridor_quorum_is_refused() {
        let (_s, mut gw) = nine_op_gateway(3);
        assert_eq!(
            gw.set_corridor_quorum(1, 0),
            Err(GatewayError::ThinQuorum { quorum: 0, size: 9 })
        );
    }
}
