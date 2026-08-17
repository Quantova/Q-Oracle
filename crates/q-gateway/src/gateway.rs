// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{BTreeMap, BTreeSet};

use q_airlock::{AttestationEnvelope, SignerSig};
use q_codec::{BridgeFact, CodecError, Direction, Reader, Writer, ATTEST_DOMAIN};

use crate::errors::GatewayError;
use crate::operators::{verify_quorum, OperatorSet};

pub const REORG_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/REORG/v1";
pub const TIER_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/TIER/v1";
pub const FREEZE_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/FREEZE/v1";
pub const WATCHDOG_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/WATCHDOG/v1";
pub const BATCH_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/BATCH/v1";
pub const BASE_TIER: u8 = 1;
pub const WATCHDOG_MAX_WINDOW: u64 = 7_200;
const GUARD_SNAPSHOT_VERSION: u8 = 5;

pub fn supermajority_floor(size: usize) -> usize {
    let two_thirds = (size.saturating_mul(2) + 2) / 3;
    two_thirds.max(2)
}

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
    pub source_chain: u32,
}

pub struct Gateway {
    chain_id: u32,
    dest_chain_id: u64,
    operators: OperatorSet,
    governance: OperatorSet,
    used_refs: BTreeSet<(u32, [u8; 32])>,
    per_asset_minted: BTreeMap<[u8; 16], u128>,
    per_asset_cap: BTreeMap<[u8; 16], u128>,
    per_asset_epoch_cap: BTreeMap<[u8; 16], u128>,
    per_asset_epoch_minted: BTreeMap<[u8; 16], u128>,
    epoch_cap: u128,
    epoch_minted: u128,
    current_epoch: u64,
    corridors: BTreeMap<u32, CorridorConfig>,
    corridor_cursor: BTreeMap<u32, u64>,
    paused_sources: BTreeSet<u32>,
    global_pause: bool,
    current_height: u64,
    frozen_until: u64,
    deposit_frozen_until: u64,
    exit_delay: u64,
    next_exit_id: u64,
    pending_exits: BTreeMap<u64, ExitTicket>,
    guard_revision: u64,
}

impl Gateway {
    pub fn new(chain_id: u32, dest_chain_id: u64, operators: OperatorSet, epoch_cap: u128) -> Gateway {
        Gateway {
            chain_id,
            dest_chain_id,
            operators,
            governance: OperatorSet::new(0),
            used_refs: BTreeSet::new(),
            per_asset_minted: BTreeMap::new(),
            per_asset_cap: BTreeMap::new(),
            per_asset_epoch_cap: BTreeMap::new(),
            per_asset_epoch_minted: BTreeMap::new(),
            epoch_cap,
            epoch_minted: 0,
            current_epoch: 0,
            corridors: BTreeMap::new(),
            corridor_cursor: BTreeMap::new(),
            paused_sources: BTreeSet::new(),
            global_pause: false,
            current_height: 0,
            frozen_until: 0,
            deposit_frozen_until: 0,
            exit_delay: 0,
            next_exit_id: 0,
            pending_exits: BTreeMap::new(),
            guard_revision: 0,
        }
    }

    pub fn set_governance(&mut self, governance: OperatorSet) {
        self.governance = governance;
    }

    pub fn governance_configured(&self) -> bool {
        self.governance.size() > 0
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn dest_chain_id(&self) -> u64 {
        self.dest_chain_id
    }

    pub fn guard_revision(&self) -> u64 {
        self.guard_revision
    }

    fn touch_guard(&mut self) {
        self.guard_revision = self.guard_revision.wrapping_add(1);
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

    fn mint_freeze_horizon(&self) -> u64 {
        self.frozen_until.max(self.deposit_frozen_until)
    }

    pub fn corridor_tier(&self, source_chain: u32) -> Option<u8> {
        self.corridors.get(&source_chain).map(|c| c.tier)
    }

    pub fn corridor_cursor(&self, source_chain: u32) -> u64 {
        *self.corridor_cursor.get(&source_chain).unwrap_or(&0)
    }

    pub fn register_corridor(&mut self, source_chain: u32, confirmation_depth: u32) {
        self.corridors.entry(source_chain).or_insert(CorridorConfig {
            confirmation_depth,
            quorum: 0,
            tier: BASE_TIER,
            active: true,
        });
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
            let floor = supermajority_floor(self.operators.size());
            if c.quorum > 0 {
                c.quorum.max(floor)
            } else {
                self.operators.threshold().max(floor)
            }
        })
    }

    pub fn register_asset_cap(&mut self, asset_id: [u8; 16], cap: u128) {
        self.per_asset_cap.insert(asset_id, cap);
    }

    pub fn register_asset_epoch_cap(&mut self, asset_id: [u8; 16], cap: u128) {
        self.per_asset_epoch_cap.insert(asset_id, cap);
    }

    fn charge_asset_epoch(&self, asset_id: &[u8; 16], amount: u128) -> Result<(), GatewayError> {
        if let Some(&cap) = self.per_asset_epoch_cap.get(asset_id) {
            let minted = *self.per_asset_epoch_minted.get(asset_id).unwrap_or(&0);
            let after = minted
                .checked_add(amount)
                .ok_or(GatewayError::EpochCapExceeded { minted, cap, add: amount })?;
            if after > cap {
                return Err(GatewayError::EpochCapExceeded { minted, cap, add: amount });
            }
        }
        Ok(())
    }

    fn record_asset_epoch(&mut self, asset_id: [u8; 16], amount: u128) {
        let entry = self.per_asset_epoch_minted.entry(asset_id).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    fn pending_exit_of(&self, asset_id: &[u8; 16]) -> u128 {
        self.pending_exits
            .values()
            .filter(|t| &t.asset_id == asset_id)
            .fold(0u128, |acc, t| acc.saturating_add(t.amount))
    }

    pub fn pause_all(&mut self) {
        self.global_pause = true;
        self.touch_guard();
    }

    pub fn unpause_all(&mut self) {
        self.global_pause = false;
        self.touch_guard();
    }

    pub fn pause_source_direct(&mut self, source_chain: u32) {
        self.paused_sources.insert(source_chain);
        self.touch_guard();
    }

    pub fn unpause_source(&mut self, source_chain: u32) {
        self.paused_sources.remove(&source_chain);
        self.touch_guard();
    }

    pub fn advance_epoch(&mut self) {
        self.current_epoch += 1;
        self.epoch_minted = 0;
        self.per_asset_epoch_minted.clear();
        self.touch_guard();
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

    pub fn asset_cap(&self, asset_id: &[u8; 16]) -> Option<u128> {
        self.per_asset_cap.get(asset_id).copied()
    }

    pub fn minted_by_asset(&self) -> &BTreeMap<[u8; 16], u128> {
        &self.per_asset_minted
    }

    pub fn is_source_paused(&self, source_chain: u32) -> bool {
        self.paused_sources.contains(&source_chain)
    }

    pub fn is_reference_used(&self, source_ref: &[u8; 32]) -> bool {
        self.used_refs.iter().any(|(_, reference)| reference == source_ref)
    }

    pub fn is_reference_used_on(&self, source_chain: u32, source_ref: &[u8; 32]) -> bool {
        self.used_refs.contains(&(source_chain, *source_ref))
    }

    pub fn report_reorg(
        &mut self,
        source_chain: u32,
        fork_depth: u32,
        sigs: &[SignerSig],
    ) -> Result<(), GatewayError> {
        let message = reorg_message(source_chain, fork_depth, self.dest_chain_id);
        let distinct = verify_quorum(&message, REORG_DOMAIN, sigs, &self.operators);
        let need = self
            .operators
            .threshold()
            .max(supermajority_floor(self.operators.size()));
        if distinct.len() < need {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need,
            });
        }
        self.paused_sources.insert(source_chain);
        self.touch_guard();
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
        let message = tier_message(source_chain, proposed, self.dest_chain_id);
        let distinct = verify_quorum(&message, TIER_DOMAIN, sigs, &self.governance);
        let need = self
            .governance
            .threshold()
            .max(supermajority_floor(self.governance.size()));
        if distinct.len() < need {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need,
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
        let message = freeze_message(until_height, self.dest_chain_id);
        let distinct = verify_quorum(&message, FREEZE_DOMAIN, sigs, &self.operators);
        let need = self
            .operators
            .threshold()
            .max(supermajority_floor(self.operators.size()));
        if distinct.len() < need {
            return Err(GatewayError::BelowThreshold {
                got: distinct.len(),
                need,
            });
        }
        if until_height > self.frozen_until {
            self.frozen_until = until_height;
            self.touch_guard();
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
        let message = freeze_message(until_height, self.dest_chain_id);
        let distinct = verify_quorum(
            &message,
            WATCHDOG_DOMAIN,
            std::slice::from_ref(sig),
            &self.operators,
        );
        if distinct.is_empty() {
            return Err(GatewayError::BelowThreshold { got: 0, need: 1 });
        }
        if until_height > self.deposit_frozen_until {
            self.deposit_frozen_until = until_height;
            self.touch_guard();
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
            corridor.quorum.max(supermajority_floor(self.operators.size()))
        } else {
            self.operators
                .threshold()
                .max(supermajority_floor(self.operators.size()))
        };
        let message = batch_message(source_chain, batch_index, self.dest_chain_id);
        let distinct = verify_quorum(&message, BATCH_DOMAIN, sigs, &self.operators);
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
        self.touch_guard();
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
        self.touch_guard();
        Ok(ticket)
    }

    pub fn finalize_exit(&mut self, exit_id: u64) -> Result<ExitTicket, GatewayError> {
        if self.global_pause {
            return Err(GatewayError::GlobalPause);
        }
        if self.current_height < self.frozen_until {
            return Err(GatewayError::Frozen {
                until: self.frozen_until,
            });
        }
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
        self.touch_guard();
        Ok(ticket)
    }

    pub fn cancel_exit(&mut self, exit_id: u64) -> Result<ExitTicket, GatewayError> {
        let ticket = self
            .pending_exits
            .remove(&exit_id)
            .ok_or(GatewayError::UnknownExit(exit_id))?;
        let minted = *self.per_asset_minted.get(&ticket.asset_id).unwrap_or(&0);
        self.per_asset_minted
            .insert(ticket.asset_id, minted.saturating_add(ticket.amount));
        self.touch_guard();
        Ok(ticket)
    }

    pub fn admit_trustless(
        &mut self,
        asset_id: [u8; 16],
        source_ref: [u8; 32],
        amount: u128,
        source_chain: u32,
    ) -> Result<(), GatewayError> {
        if self.global_pause {
            return Err(GatewayError::GlobalPause);
        }
        if self.current_height < self.mint_freeze_horizon() {
            return Err(GatewayError::Frozen {
                until: self.mint_freeze_horizon(),
            });
        }
        if self.paused_sources.contains(&source_chain) {
            return Err(GatewayError::SourcePaused(source_chain));
        }
        if let Some(corridor) = self.corridors.get(&source_chain) {
            if !corridor.active {
                return Err(GatewayError::CorridorInactive(source_chain));
            }
        }
        if self.used_refs.contains(&(source_chain, source_ref)) {
            return Err(GatewayError::ReplayedReference);
        }
        let cap = *self
            .per_asset_cap
            .get(&asset_id)
            .ok_or(GatewayError::AssetNotRegistered)?;
        let minted = *self.per_asset_minted.get(&asset_id).unwrap_or(&0);
        let outstanding = minted.saturating_add(self.pending_exit_of(&asset_id));
        let after_cap = outstanding
            .checked_add(amount)
            .ok_or(GatewayError::AssetCapExceeded { minted: outstanding, cap, add: amount })?;
        if after_cap > cap {
            return Err(GatewayError::AssetCapExceeded { minted: outstanding, cap, add: amount });
        }
        let asset_after = minted.saturating_add(amount);
        let epoch_after =
            self.epoch_minted
                .checked_add(amount)
                .ok_or(GatewayError::EpochCapExceeded {
                    minted: self.epoch_minted,
                    cap: self.epoch_cap,
                    add: amount,
                })?;
        if epoch_after > self.epoch_cap {
            return Err(GatewayError::EpochCapExceeded {
                minted: self.epoch_minted,
                cap: self.epoch_cap,
                add: amount,
            });
        }
        self.charge_asset_epoch(&asset_id, amount)?;
        self.used_refs.insert((source_chain, source_ref));
        self.per_asset_minted.insert(asset_id, asset_after);
        self.epoch_minted = epoch_after;
        self.record_asset_epoch(asset_id, amount);
        self.touch_guard();
        Ok(())
    }

    pub fn process_deposit(
        &mut self,
        env: &AttestationEnvelope,
    ) -> Result<MintReceipt, GatewayError> {
        if self.global_pause {
            return Err(GatewayError::GlobalPause);
        }
        if self.current_height < self.mint_freeze_horizon() {
            return Err(GatewayError::Frozen {
                until: self.mint_freeze_horizon(),
            });
        }
        if self.dest_chain_id == 0 {
            return Err(GatewayError::WrongDestination);
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
            corridor.quorum.max(supermajority_floor(size))
        } else {
            self.operators.threshold().max(supermajority_floor(size))
        };
        if required == 0 || required > size {
            return Err(GatewayError::ThinQuorum {
                quorum: required,
                size,
            });
        }

        let message = fact.attest_preimage(self.dest_chain_id);
        let distinct = verify_quorum(&message, ATTEST_DOMAIN, &env.signatures, &self.operators);
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
        let outstanding = minted.saturating_add(self.pending_exit_of(&fact.asset_id.0));
        let after_cap = outstanding
            .checked_add(fact.amount)
            .ok_or(GatewayError::AssetCapExceeded {
                minted: outstanding,
                cap,
                add: fact.amount,
            })?;
        if after_cap > cap {
            return Err(GatewayError::AssetCapExceeded {
                minted: outstanding,
                cap,
                add: fact.amount,
            });
        }
        let asset_after = minted.saturating_add(fact.amount);

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

        if self.used_refs.contains(&(fact.source_chain, fact.source_ref.0)) {
            return Err(GatewayError::ReplayedReference);
        }

        self.charge_asset_epoch(&fact.asset_id.0, fact.amount)?;
        self.used_refs.insert((fact.source_chain, fact.source_ref.0));
        self.per_asset_minted.insert(fact.asset_id.0, asset_after);
        self.epoch_minted = epoch_after;
        self.record_asset_epoch(fact.asset_id.0, fact.amount);
        self.touch_guard();

        Ok(MintReceipt {
            asset_id: fact.asset_id.0,
            recipient: fact.recipient.0,
            amount: fact.amount,
            source_ref: fact.source_ref.0,
            source_chain: fact.source_chain,
        })
    }

    pub fn encode_guard(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(GUARD_SNAPSHOT_VERSION);
        w.u8(self.global_pause as u8);
        w.u64(self.frozen_until);
        w.u64(self.deposit_frozen_until);
        w.u128(self.epoch_minted);
        w.u32(self.used_refs.len() as u32);
        for (source_chain, reference) in &self.used_refs {
            w.u32(*source_chain);
            w.fixed(reference);
        }
        w.u32(self.per_asset_minted.len() as u32);
        for (asset_id, minted) in &self.per_asset_minted {
            w.fixed(asset_id);
            w.u128(*minted);
        }
        w.u32(self.paused_sources.len() as u32);
        for source_chain in &self.paused_sources {
            w.u32(*source_chain);
        }
        w.u32(self.corridor_cursor.len() as u32);
        for (source_chain, cursor) in &self.corridor_cursor {
            w.u32(*source_chain);
            w.u64(*cursor);
        }
        w.u64(self.current_epoch);
        w.u32(self.per_asset_epoch_minted.len() as u32);
        for (asset_id, minted) in &self.per_asset_epoch_minted {
            w.fixed(asset_id);
            w.u128(*minted);
        }
        w.u64(self.next_exit_id);
        w.u32(self.pending_exits.len() as u32);
        for ticket in self.pending_exits.values() {
            w.u64(ticket.exit_id);
            w.fixed(&ticket.asset_id);
            w.u128(ticket.amount);
            w.fixed(&ticket.destination);
            w.u64(ticket.unlock_height);
        }
        w.u32(self.corridors.len() as u32);
        for (source_chain, corridor) in &self.corridors {
            w.u32(*source_chain);
            w.u32(corridor.confirmation_depth);
            w.u32(corridor.quorum as u32);
            w.u8(corridor.tier);
            w.u8(corridor.active as u8);
        }
        w.finish()
    }

    pub fn rehydrate_guard(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        let state = decode_guard(bytes)?;
        self.global_pause = state.global_pause;
        self.frozen_until = state.frozen_until;
        self.deposit_frozen_until = state.deposit_frozen_until;
        self.epoch_minted = state.epoch_minted;
        self.used_refs = state.used_refs;
        self.per_asset_minted = state.per_asset_minted;
        self.paused_sources = state.paused_sources;
        self.corridor_cursor = state.corridor_cursor;
        self.current_epoch = state.current_epoch;
        self.per_asset_epoch_minted = state.per_asset_epoch_minted;
        self.next_exit_id = state.next_exit_id;
        self.pending_exits = state.pending_exits;
        for (source_chain, corridor) in state.corridors {
            self.corridors.insert(source_chain, corridor);
        }
        Ok(())
    }
}

struct GuardState {
    global_pause: bool,
    frozen_until: u64,
    deposit_frozen_until: u64,
    epoch_minted: u128,
    used_refs: BTreeSet<(u32, [u8; 32])>,
    per_asset_minted: BTreeMap<[u8; 16], u128>,
    paused_sources: BTreeSet<u32>,
    corridor_cursor: BTreeMap<u32, u64>,
    current_epoch: u64,
    per_asset_epoch_minted: BTreeMap<[u8; 16], u128>,
    next_exit_id: u64,
    pending_exits: BTreeMap<u64, ExitTicket>,
    corridors: BTreeMap<u32, CorridorConfig>,
}

fn bounded_count(r: &mut Reader, item_size: usize) -> Result<usize, CodecError> {
    let count = r.u32()? as usize;
    if count > r.remaining() / item_size {
        return Err(CodecError::LengthMismatch);
    }
    Ok(count)
}

fn decode_guard(bytes: &[u8]) -> Result<GuardState, CodecError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != GUARD_SNAPSHOT_VERSION {
        return Err(CodecError::BadVersion(version));
    }
    let global_pause = match r.u8()? {
        0 => false,
        1 => true,
        other => return Err(CodecError::UnknownTag(other)),
    };
    let frozen_until = r.u64()?;
    let deposit_frozen_until = r.u64()?;
    let epoch_minted = r.u128()?;

    let count = bounded_count(&mut r, 36)?;
    let mut used_refs = BTreeSet::new();
    for _ in 0..count {
        let source_chain = r.u32()?;
        let reference = r.array32()?;
        used_refs.insert((source_chain, reference));
    }

    let count = bounded_count(&mut r, 32)?;
    let mut per_asset_minted = BTreeMap::new();
    for _ in 0..count {
        let asset_id = r.array16()?;
        let minted = r.u128()?;
        per_asset_minted.insert(asset_id, minted);
    }

    let count = bounded_count(&mut r, 4)?;
    let mut paused_sources = BTreeSet::new();
    for _ in 0..count {
        paused_sources.insert(r.u32()?);
    }

    let count = bounded_count(&mut r, 12)?;
    let mut corridor_cursor = BTreeMap::new();
    for _ in 0..count {
        let source_chain = r.u32()?;
        let cursor = r.u64()?;
        corridor_cursor.insert(source_chain, cursor);
    }

    let current_epoch = r.u64()?;

    let count = bounded_count(&mut r, 32)?;
    let mut per_asset_epoch_minted = BTreeMap::new();
    for _ in 0..count {
        let asset_id = r.array16()?;
        let minted = r.u128()?;
        per_asset_epoch_minted.insert(asset_id, minted);
    }

    let next_exit_id = r.u64()?;

    let count = bounded_count(&mut r, 80)?;
    let mut pending_exits = BTreeMap::new();
    for _ in 0..count {
        let exit_id = r.u64()?;
        let asset_id = r.array16()?;
        let amount = r.u128()?;
        let destination = r.array32()?;
        let unlock_height = r.u64()?;
        pending_exits.insert(
            exit_id,
            ExitTicket {
                exit_id,
                asset_id,
                amount,
                destination,
                unlock_height,
            },
        );
    }

    let count = bounded_count(&mut r, 14)?;
    let mut corridors = BTreeMap::new();
    for _ in 0..count {
        let source_chain = r.u32()?;
        let confirmation_depth = r.u32()?;
        let quorum = r.u32()? as usize;
        let tier = r.u8()?;
        let active = match r.u8()? {
            0 => false,
            1 => true,
            other => return Err(CodecError::UnknownTag(other)),
        };
        corridors.insert(
            source_chain,
            CorridorConfig {
                confirmation_depth,
                quorum,
                tier,
                active,
            },
        );
    }

    r.finish()?;
    Ok(GuardState {
        global_pause,
        frozen_until,
        deposit_frozen_until,
        epoch_minted,
        used_refs,
        per_asset_minted,
        paused_sources,
        corridor_cursor,
        current_epoch,
        per_asset_epoch_minted,
        next_exit_id,
        pending_exits,
        corridors,
    })
}

pub fn attestation_message(fact: &BridgeFact, dest_chain_id: u64) -> Vec<u8> {
    fact.attest_preimage(dest_chain_id)
}

pub fn reorg_message(source_chain: u32, fork_depth: u32, dest_chain_id: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(source_chain);
    w.u32(fork_depth);
    w.u64(dest_chain_id);
    w.finish()
}

pub fn tier_message(source_chain: u32, proposed: u8, dest_chain_id: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(source_chain);
    w.u8(proposed);
    w.u64(dest_chain_id);
    w.finish()
}

pub fn freeze_message(until_height: u64, dest_chain_id: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(until_height);
    w.u64(dest_chain_id);
    w.finish()
}

pub fn batch_message(source_chain: u32, batch_index: u64, dest_chain_id: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(source_chain);
    w.u64(batch_index);
    w.u64(dest_chain_id);
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_codec::{AssetId, Recipient, SourceRef, FACT_VERSION};
    use qtv_crypto::ml_dsa;

    const DEST_ID: u64 = 0x0000_002a_0000_2328;

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
        let sig = ml_dsa::sign(sk, &f.attest_preimage(DEST_ID), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
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
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
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

    #[test]
    fn a_gateway_left_at_the_zero_dest_chain_id_sentinel_fails_closed_instead_of_minting() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, 0, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);
        let f = fact();
        let signatures = s
            .iter()
            .map(|(id, _, sk)| {
                let sig = ml_dsa::sign(sk, &f.attest_preimage(0), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
                SignerSig {
                    operator_id: *id,
                    signature: sig.to_vec(),
                }
            })
            .collect();
        let env = AttestationEnvelope {
            fact: f.clone(),
            signatures,
        };
        assert_eq!(
            gw.process_deposit(&env),
            Err(GatewayError::WrongDestination),
            "a quorum bound to the zero dest chain id sentinel must not mint"
        );
    }

    fn nine_op_gateway(global: usize) -> (Vec<(u32, ml_dsa::PublicKey, ml_dsa::SecretKey)>, Gateway) {
        let s: Vec<_> = (0..9).map(signer).collect();
        let mut set = OperatorSet::new(global);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
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
    fn a_corridor_with_no_explicit_quorum_still_requires_a_two_thirds_supermajority() {
        let (s, mut gw) = nine_op_gateway(3);
        assert_eq!(gw.corridor_quorum(1), Some(6), "the fallback is raised to two thirds of nine");
        let f = fact();
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..5], &f)),
            Err(GatewayError::BelowThreshold { got: 5, need: 6 }),
            "five of nine is not a supermajority on the fallback path"
        );
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..6], &f)).expect("a real supermajority admits").amount,
            500
        );
    }

    #[test]
    fn a_single_operator_fallback_admit_is_refused() {
        let s: Vec<_> = (0..1).map(signer).collect();
        let mut set = OperatorSet::new(1);
        set.register(s[0].0, s[0].1);
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);
        let f = fact();
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..1], &f)),
            Err(GatewayError::ThinQuorum { quorum: 2, size: 1 }),
            "a lone operator can never form a two-thirds quorum of at least two"
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

    #[test]
    fn a_lower_nonce_with_a_fresh_reference_still_mints_after_a_higher_one() {
        let (s, mut gw) = nine_op_gateway(3);

        let mut high = fact();
        high.route_id = 7;
        high.nonce = 9_000;
        high.source_ref = SourceRef([0x21; 32]);
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..6], &high)).expect("the high-nonce deposit mints").amount,
            500
        );

        let mut low = fact();
        low.route_id = 7;
        low.nonce = 1;
        low.source_ref = SourceRef([0x22; 32]);
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..6], &low))
                .expect("a later lower-nonce deposit with a fresh reference is not wedged")
                .amount,
            500
        );
    }

    #[test]
    fn the_trustless_admit_honors_the_same_freeze_and_pause_guards_as_a_deposit() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);

        gw.pause_all();
        assert_eq!(
            gw.admit_trustless([0xa1; 16], [0x01; 32], 100, 1),
            Err(GatewayError::GlobalPause)
        );
        gw.unpause_all();

        gw.pause_source_direct(1);
        assert_eq!(
            gw.admit_trustless([0xa1; 16], [0x01; 32], 100, 1),
            Err(GatewayError::SourcePaused(1))
        );
        gw.unpause_source(1);

        gw.set_corridor_active(1, false);
        assert_eq!(
            gw.admit_trustless([0xa1; 16], [0x01; 32], 100, 1),
            Err(GatewayError::CorridorInactive(1))
        );
        gw.set_corridor_active(1, true);

        let until = 5_000u64;
        let message = freeze_message(until, DEST_ID);
        let sigs: Vec<SignerSig> = s
            .iter()
            .map(|(id, _, sk)| SignerSig {
                operator_id: *id,
                signature: ml_dsa::sign(sk, &message, FREEZE_DOMAIN, &[0u8; 32]).unwrap().to_vec(),
            })
            .collect();
        gw.emergency_freeze(until, &sigs).expect("a quorum freezes");
        assert_eq!(
            gw.admit_trustless([0xa1; 16], [0x01; 32], 100, 1),
            Err(GatewayError::Frozen { until })
        );

        gw.advance_to(until);
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x01; 32], 100, 1), Ok(()));
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 100);
    }

    #[test]
    fn re_registering_a_corridor_preserves_its_active_flag_and_quorum() {
        let s: Vec<_> = (0..5).map(signer).collect();
        let mut set = OperatorSet::new(5);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);
        gw.set_corridor_quorum(1, 4).expect("a two thirds quorum");
        gw.set_corridor_active(1, false);

        gw.register_corridor(1, 6);

        assert_eq!(gw.corridor_quorum(1), Some(4));
        assert_eq!(
            gw.admit_trustless([0xa1; 16], [0x01; 32], 100, 1),
            Err(GatewayError::CorridorInactive(1))
        );
    }

    #[test]
    fn the_per_asset_epoch_cap_bounds_minting_within_an_epoch_and_resets_on_advance() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 10_000);
        gw.register_asset_epoch_cap([0xa1; 16], 300);

        assert_eq!(gw.admit_trustless([0xa1; 16], [0x01; 32], 200, 1), Ok(()));
        assert!(matches!(
            gw.admit_trustless([0xa1; 16], [0x02; 32], 200, 1),
            Err(GatewayError::EpochCapExceeded { .. })
        ));
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x03; 32], 100, 1), Ok(()));
        assert!(matches!(
            gw.admit_trustless([0xa1; 16], [0x04; 32], 1, 1),
            Err(GatewayError::EpochCapExceeded { .. })
        ));

        gw.advance_epoch();
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x05; 32], 300, 1), Ok(()));
    }

    #[test]
    fn the_per_asset_total_cap_survives_epoch_advances_and_cannot_be_reset_by_cycling() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 500);

        assert_eq!(gw.admit_trustless([0xa1; 16], [0x01; 32], 300, 1), Ok(()));
        gw.advance_epoch();
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x02; 32], 200, 1), Ok(()));
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 500);
        gw.advance_epoch();
        assert!(
            matches!(
                gw.admit_trustless([0xa1; 16], [0x03; 32], 1, 1),
                Err(GatewayError::AssetCapExceeded { .. })
            ),
            "advancing the epoch must not reset the per-asset total cap"
        );
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 500);
    }

    #[test]
    fn a_pending_exit_still_counts_toward_the_cap_so_mint_exit_remint_cancel_cannot_exceed_it() {
        let mut gw = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 500);
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x01; 32], 500, 1), Ok(()));
        let ticket = gw.request_exit([0xa1; 16], 500, [0x99; 32]).expect("the exit request burns");
        assert!(
            matches!(
                gw.admit_trustless([0xa1; 16], [0x02; 32], 500, 1),
                Err(GatewayError::AssetCapExceeded { .. })
            ),
            "a pending exit must not free cap headroom for a re-mint"
        );
        gw.cancel_exit(ticket.exit_id).expect("cancel restores the burned units");
        assert_eq!(
            gw.minted_of_asset(&[0xa1; 16]),
            500,
            "cancel restores exactly to the cap, never above it"
        );
    }

    #[test]
    fn a_random_walk_of_mints_exits_cancels_and_finalizes_never_exceeds_the_per_asset_cap() {
        let mut st = 0x9e37_79b9_7f4a_7c15u64;
        let mut rng = || {
            st = st.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = st;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut gw = Gateway::new(9000, DEST_ID, OperatorSet::new(0), u128::MAX);
        gw.register_corridor(1, 6);
        let assets = [[0xa1u8; 16], [0xa2u8; 16], [0xa3u8; 16]];
        for a in &assets {
            gw.register_asset_cap(*a, 1000);
        }
        let mut ref_ctr = 0u64;
        let mut tickets: Vec<u64> = Vec::new();
        for _ in 0..8000 {
            let a = assets[(rng() % 3) as usize];
            match rng() % 6 {
                0 | 1 => {
                    let amt = (rng() % 500) as u128;
                    if amt > 0 {
                        let mut r = [0u8; 32];
                        r[..8].copy_from_slice(&ref_ctr.to_le_bytes());
                        ref_ctr += 1;
                        let _ = gw.admit_trustless(a, r, amt, 1);
                    }
                }
                2 => {
                    let minted = gw.minted_of_asset(&a);
                    if minted > 0 {
                        let amt = (rng() as u128 % minted) + 1;
                        if let Ok(t) = gw.request_exit(a, amt, [0x99; 32]) {
                            tickets.push(t.exit_id);
                        }
                    }
                }
                3 => {
                    if !tickets.is_empty() {
                        let id = tickets.swap_remove((rng() as usize) % tickets.len());
                        let _ = gw.cancel_exit(id);
                    }
                }
                4 => {
                    if !tickets.is_empty() {
                        let idx = (rng() as usize) % tickets.len();
                        let id = tickets[idx];
                        if gw.finalize_exit(id).is_ok() {
                            tickets.swap_remove(idx);
                        }
                    }
                }
                _ => gw.advance_epoch(),
            }
            for a in &assets {
                let minted = gw.minted_of_asset(a);
                assert!(
                    minted <= gw.asset_cap(a).unwrap(),
                    "cap invariant broken for {:?}: minted {} exceeds cap {:?}",
                    a,
                    minted,
                    gw.asset_cap(a)
                );
            }
        }
    }

    #[test]
    fn a_pending_exit_still_counts_toward_the_cap_after_a_snapshot_restart() {
        let mut gw = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 500);
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x01; 32], 500, 1), Ok(()));
        gw.request_exit([0xa1; 16], 500, [0xdd; 32]).expect("the exit request burns");
        let snapshot = gw.encode_guard();

        let mut restored = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000);
        restored.register_corridor(1, 6);
        restored.register_asset_cap([0xa1; 16], 500);
        restored.rehydrate_guard(&snapshot).expect("a clean snapshot rehydrates");
        assert!(
            matches!(
                restored.admit_trustless([0xa1; 16], [0x02; 32], 500, 1),
                Err(GatewayError::AssetCapExceeded { .. })
            ),
            "a persisted pending exit must still count toward the cap after a restart"
        );
    }

    #[test]
    fn a_closed_corridor_stays_closed_after_a_snapshot_restart() {
        let mut gw = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000);
        gw.register_corridor(1, 6);
        gw.set_corridor_active(1, false);
        let snapshot = gw.encode_guard();

        let mut restored = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000_000);
        restored.register_corridor(1, 6);
        restored.register_asset_cap([0xa1; 16], 500);
        restored.rehydrate_guard(&snapshot).expect("a clean snapshot rehydrates");
        assert_eq!(
            restored.admit_trustless([0xa1; 16], [0x01; 32], 500, 1),
            Err(GatewayError::CorridorInactive(1)),
            "a corridor closed before the snapshot must not re-open on restart"
        );
    }

    #[test]
    fn an_admin_freeze_signed_for_one_destination_does_not_replay_on_another() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set_here = OperatorSet::new(3);
        let mut set_there = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set_here.register(*id, *pk);
            set_there.register(*id, *pk);
        }
        const OTHER_DEST_ID: u64 = DEST_ID ^ 0xffff_ffff;
        let mut here = Gateway::new(9000, DEST_ID, set_here, 1_000_000);
        here.register_corridor(1, 6);
        let mut there = Gateway::new(9000, OTHER_DEST_ID, set_there, 1_000_000);
        there.register_corridor(1, 6);

        let until = 5_000u64;
        let message = freeze_message(until, DEST_ID);
        let sigs: Vec<SignerSig> = s
            .iter()
            .map(|(id, _, sk)| SignerSig {
                operator_id: *id,
                signature: ml_dsa::sign(sk, &message, FREEZE_DOMAIN, &[0u8; 32]).unwrap().to_vec(),
            })
            .collect();

        here.emergency_freeze(until, &sigs)
            .expect("the freeze verifies on the destination it was signed for");
        assert_eq!(
            there.emergency_freeze(until, &sigs),
            Err(GatewayError::BelowThreshold { got: 0, need: 3 }),
            "a freeze bound to one destination chain id must not verify on a second gateway"
        );
    }

    #[test]
    fn a_freeze_halts_finalize_and_a_cancel_restores_the_burned_balance() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);
        gw.admit_trustless([0xa1; 16], [0xab; 32], 400, 1)
            .expect("seed a minted balance to exit");
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 400);

        let ticket = gw
            .request_exit([0xa1; 16], 300, [0x22; 32])
            .expect("the exit burns the bridged units");
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 100);

        let until = 5_000u64;
        let message = freeze_message(until, DEST_ID);
        let sigs: Vec<SignerSig> = s
            .iter()
            .map(|(id, _, sk)| SignerSig {
                operator_id: *id,
                signature: ml_dsa::sign(sk, &message, FREEZE_DOMAIN, &[0u8; 32]).unwrap().to_vec(),
            })
            .collect();
        gw.emergency_freeze(until, &sigs).expect("a quorum freezes");
        assert_eq!(
            gw.finalize_exit(ticket.exit_id),
            Err(GatewayError::Frozen { until }),
            "a freeze halts a finalize even once the unlock height has passed"
        );

        let cancelled = gw.cancel_exit(ticket.exit_id).expect("the pending exit cancels");
        assert_eq!(cancelled.amount, 300);
        assert_eq!(
            gw.minted_of_asset(&[0xa1; 16]),
            400,
            "cancel restores the units the exit burned"
        );
        gw.advance_to(until);
        assert_eq!(
            gw.finalize_exit(ticket.exit_id),
            Err(GatewayError::UnknownExit(ticket.exit_id))
        );
    }

    #[test]
    fn the_guard_revision_advances_on_a_pause_and_a_mint_but_not_on_a_read() {
        let (s, mut gw) = nine_op_gateway(3);
        let start = gw.guard_revision();
        let _ = gw.asset_cap(&[0xa1; 16]);
        assert_eq!(
            gw.guard_revision(),
            start,
            "a read leaves the guard revision unchanged"
        );

        gw.pause_all();
        let after_pause = gw.guard_revision();
        assert!(after_pause > start, "a pause advances the guard revision");
        gw.unpause_all();

        let f = fact();
        gw.process_deposit(&envelope(&s[0..6], &f)).expect("a supermajority admits");
        assert!(
            gw.guard_revision() > after_pause,
            "an admission advances the guard revision so the runtime persists it"
        );
    }

    #[test]
    fn the_registered_asset_cap_reads_back() {
        let (_s, mut gw) = nine_op_gateway(3);
        assert_eq!(gw.asset_cap(&[0xb2; 16]), None);
        gw.register_asset_cap([0xb2; 16], 7_000);
        assert_eq!(gw.asset_cap(&[0xb2; 16]), Some(7_000));
    }

    #[test]
    fn a_restart_from_the_guard_snapshot_still_rejects_the_replay_and_keeps_the_caps() {
        let (s, mut gw) = nine_op_gateway(3);
        let f = fact();
        let receipt = gw.process_deposit(&envelope(&s[0..6], &f)).expect("a supermajority admits");
        assert_eq!(receipt.amount, 500);

        let snapshot = gw.encode_guard();
        drop(gw);

        let (_s2, mut restored) = nine_op_gateway(3);
        restored.rehydrate_guard(&snapshot).expect("a clean snapshot rehydrates");
        assert!(
            restored.is_reference_used(&f.source_ref.0),
            "the reserved reference survives the restart"
        );
        assert_eq!(restored.minted_of_asset(&f.asset_id.0), 500);
        assert_eq!(restored.epoch_minted(), 500);
        assert_eq!(
            restored.process_deposit(&envelope(&s[0..6], &f)),
            Err(GatewayError::ReplayedReference),
            "the same deposit is a replay once the guard is rehydrated"
        );
    }

    #[test]
    fn the_guard_snapshot_persists_the_epoch_counter_and_pending_exits() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 10_000);
        gw.register_asset_epoch_cap([0xa1; 16], 300);
        assert_eq!(gw.admit_trustless([0xa1; 16], [0x01; 32], 300, 1), Ok(()));
        let ticket = gw
            .request_exit([0xa1; 16], 100, [0xdd; 32])
            .expect("an exit is requested");
        let exit_id = ticket.exit_id;

        let snapshot = gw.encode_guard();
        drop(gw);

        let s2: Vec<_> = (0..3).map(signer).collect();
        let mut set2 = OperatorSet::new(3);
        for (id, pk, _) in &s2 {
            set2.register(*id, *pk);
        }
        let mut restored = Gateway::new(9000, DEST_ID, set2, 1_000_000);
        restored.register_corridor(1, 6);
        restored.register_asset_cap([0xa1; 16], 10_000);
        restored.register_asset_epoch_cap([0xa1; 16], 300);
        restored.rehydrate_guard(&snapshot).expect("a clean snapshot rehydrates");

        assert!(
            matches!(
                restored.admit_trustless([0xa1; 16], [0x02; 32], 1, 1),
                Err(GatewayError::EpochCapExceeded { .. })
            ),
            "the per asset epoch counter survives the restart so the cap still holds"
        );
        assert_eq!(
            restored.finalize_exit(exit_id).map(|t| t.amount),
            Ok(100),
            "the pending exit survives the restart and can be finalized"
        );
    }

    #[test]
    fn the_guard_snapshot_persists_a_watchdog_deposit_pause() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);
        gw.advance_to(1_000);

        let until = 1_500;
        let alarm = SignerSig {
            operator_id: s[0].0,
            signature: ml_dsa::sign(&s[0].2, &freeze_message(until, DEST_ID), WATCHDOG_DOMAIN, &[0u8; 32])
                .unwrap()
                .to_vec(),
        };
        gw.watchdog_freeze(until, &alarm).expect("a watchdog pauses new deposits");

        let snapshot = gw.encode_guard();
        drop(gw);

        let s2: Vec<_> = (0..3).map(signer).collect();
        let mut set2 = OperatorSet::new(3);
        for (id, pk, _) in &s2 {
            set2.register(*id, *pk);
        }
        let mut restored = Gateway::new(9000, DEST_ID, set2, 1_000_000);
        restored.register_corridor(1, 6);
        restored.register_asset_cap([0xa1; 16], 1_000);
        restored.advance_to(1_000);
        restored.rehydrate_guard(&snapshot).expect("a clean snapshot rehydrates");

        assert_eq!(
            restored.admit_trustless([0xa1; 16], [0x01; 32], 100, 1),
            Err(GatewayError::Frozen { until }),
            "the watchdog deposit pause survives the restart"
        );
    }

    #[test]
    fn a_shared_source_ref_on_two_corridors_both_mint_and_a_same_corridor_replay_is_refused() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(3);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        gw.register_corridor(2, 6);
        gw.register_asset_cap([0xa1; 16], 1_000);

        let shared_ref = [0x77; 32];
        gw.admit_trustless([0xa1; 16], shared_ref, 100, 1)
            .expect("the first corridor admits the reference");
        gw.admit_trustless([0xa1; 16], shared_ref, 100, 2)
            .expect("a distinct deposit sharing the reference on another corridor still mints");
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 200);

        assert_eq!(
            gw.admit_trustless([0xa1; 16], shared_ref, 100, 1),
            Err(GatewayError::ReplayedReference)
        );
        assert_eq!(
            gw.admit_trustless([0xa1; 16], shared_ref, 100, 2),
            Err(GatewayError::ReplayedReference)
        );
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 200);
    }

    #[test]
    fn process_deposit_scopes_the_reference_by_source_chain_and_the_receipt_carries_it() {
        let (s, mut gw) = nine_op_gateway(3);
        gw.register_corridor(2, 6);
        gw.register_asset_cap([0xa1; 16], 2_000);

        let first = fact();
        let r1 = gw
            .process_deposit(&envelope(&s[0..6], &first))
            .expect("the first corridor mints");
        assert_eq!(r1.source_chain, 1);
        assert_eq!(r1.source_ref, first.source_ref.0);

        let mut second = fact();
        second.source_chain = 2;
        let r2 = gw
            .process_deposit(&envelope(&s[0..6], &second))
            .expect("the same reference on another corridor still mints");
        assert_eq!(r2.source_chain, 2);
        assert_eq!(r2.source_ref, first.source_ref.0);
        assert_eq!(gw.minted_of_asset(&[0xa1; 16]), 1_000);

        assert!(gw.is_reference_used_on(1, &first.source_ref.0));
        assert!(gw.is_reference_used_on(2, &first.source_ref.0));
        assert!(!gw.is_reference_used_on(3, &first.source_ref.0));
        assert_eq!(
            gw.process_deposit(&envelope(&s[0..6], &first)),
            Err(GatewayError::ReplayedReference)
        );
    }

    #[test]
    fn a_zero_threshold_operator_set_never_freezes_or_pauses_on_no_signatures() {
        let s: Vec<_> = (0..3).map(signer).collect();
        let mut set = OperatorSet::new(0);
        for (id, pk, _) in &s {
            set.register(*id, *pk);
        }
        let mut gw = Gateway::new(9000, DEST_ID, set, 1_000_000);
        gw.register_corridor(1, 6);
        assert_eq!(
            gw.emergency_freeze(5_000, &[]),
            Err(GatewayError::BelowThreshold { got: 0, need: 2 }),
            "a zero threshold must not fail open into a no-signature freeze"
        );
        assert_eq!(gw.frozen_until(), 0, "the freeze did not take effect");
        assert_eq!(
            gw.report_reorg(1, 3, &[]),
            Err(GatewayError::BelowThreshold { got: 0, need: 2 }),
            "a zero threshold must not fail open into a no-signature pause"
        );
        assert!(!gw.is_source_paused(1), "the source was not paused");

        let empty = Gateway::new(9000, DEST_ID, OperatorSet::new(0), 1_000_000);
        let mut empty = empty;
        empty.register_corridor(1, 6);
        assert_eq!(
            empty.emergency_freeze(5_000, &[]),
            Err(GatewayError::BelowThreshold { got: 0, need: 2 }),
            "a trustless gateway with no operators must not be freezable by anyone"
        );
    }

    #[test]
    fn a_corrupt_guard_snapshot_is_refused_rather_than_rehydrating_an_empty_guard() {
        let (s, mut gw) = nine_op_gateway(3);
        let f = fact();
        gw.process_deposit(&envelope(&s[0..6], &f)).expect("seed a reserved reference");
        let mut snapshot = gw.encode_guard();
        snapshot.truncate(snapshot.len() - 1);

        let (_s2, mut restored) = nine_op_gateway(3);
        assert!(
            restored.rehydrate_guard(&snapshot).is_err(),
            "a truncated snapshot fails closed"
        );
        assert!(
            !restored.is_reference_used(&f.source_ref.0),
            "a failed rehydrate applies nothing"
        );
        assert!(
            restored.rehydrate_guard(&[0xff, 0xff, 0xff, 0xff]).is_err(),
            "garbage bytes are refused"
        );
    }
}
