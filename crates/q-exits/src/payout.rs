// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::cell::RefCell;
use std::collections::BTreeSet;

use q_codec::{Reader, Writer};
use qtv_crypto::sha3::shake256;

use qlc_bitcoin::{
    double_sha256, verify_chain, BlockHeader, Checkpoint, MerkleStep, NetworkParams, SpvError,
};
use qlc_ethereum::mpt::MptError;
use qlc_ethereum::receipt::ReceiptError;

use crate::errors::ExitError;
use crate::exits::ExitStatement;

pub const PAYOUT_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/EXIT-PAYOUT/v1";
pub const PAYOUT_VERSION: u8 = 1;
pub const PAYOUT_ENCODED_LEN: usize = 141;

pub(crate) fn shake256_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(input, &mut out);
    out
}

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
        shake256_256(&w.finish())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutProofError {
    WrongCorridor,
    WrongAsset,
    AmountMismatch,
    BeneficiaryMismatch,
    ReferenceMismatch,
    MalformedTransaction,
    UnboundPayout,
    TxidMismatch,
    MissingReceipt,
    ReusedPayout,
    EvmCorridorDisabled,
    Spv(SpvError),
    Mpt(MptError),
    Receipt(ReceiptError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayout {
    pub asset_id: Option<[u8; 16]>,
    pub amount: u128,
    pub beneficiary: [u8; 32],
    pub burn_ref: Option<[u8; 32]>,
    pub foreign_ref: [u8; 32],
    pub proof_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinReleaseProof {
    pub headers: Vec<BlockHeader>,
    pub start_height: u32,
    pub release_height: u32,
    pub branch: Vec<MerkleStep>,
    pub raw_tx: Vec<u8>,
}

impl BitcoinReleaseProof {
    pub fn verify(
        &self,
        params: &NetworkParams,
        checkpoint: &Checkpoint,
        confirmation_depth: u32,
    ) -> Result<VerifiedPayout, PayoutProofError> {
        let chain = verify_chain(&self.headers, self.start_height, params)
            .map_err(PayoutProofError::Spv)?;
        chain
            .anchored_to(checkpoint)
            .map_err(PayoutProofError::Spv)?;
        let txid = double_sha256(&self.raw_tx);
        let confirmed = chain
            .verify_deposit(self.release_height, txid, &self.branch, confirmation_depth)
            .map_err(PayoutProofError::Spv)?;
        let outputs =
            parse_bitcoin_outputs(&self.raw_tx).ok_or(PayoutProofError::MalformedTransaction)?;
        let (beneficiary, value, burn_ref) =
            scan_release_outputs(&outputs).ok_or(PayoutProofError::UnboundPayout)?;
        Ok(VerifiedPayout {
            asset_id: None,
            amount: value as u128,
            beneficiary,
            burn_ref: Some(burn_ref),
            foreign_ref: txid,
            proof_height: confirmed.deposit_height as u64,
        })
    }
}

struct BitcoinOutput {
    value: u64,
    script: Vec<u8>,
}

fn read_u16_le(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Some(u64::from_le_bytes(buf))
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *bytes.get(*pos)?;
    *pos += 1;
    match first {
        0xff => read_u64_le(bytes, pos),
        0xfe => read_u32_le(bytes, pos).map(|v| v as u64),
        0xfd => read_u16_le(bytes, pos).map(|v| v as u64),
        n => Some(n as u64),
    }
}

fn skip(bytes: &[u8], pos: &mut usize, len: usize) -> Option<()> {
    let end = pos.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    *pos = end;
    Some(())
}

fn parse_bitcoin_outputs(raw: &[u8]) -> Option<Vec<BitcoinOutput>> {
    let mut pos = 0usize;
    read_u32_le(raw, &mut pos)?;
    let vin = read_varint(raw, &mut pos)?;
    for _ in 0..vin {
        skip(raw, &mut pos, 36)?;
        let script_len = read_varint(raw, &mut pos)? as usize;
        skip(raw, &mut pos, script_len)?;
        skip(raw, &mut pos, 4)?;
    }
    let vout = read_varint(raw, &mut pos)?;
    let mut outputs = Vec::new();
    for _ in 0..vout {
        let value = read_u64_le(raw, &mut pos)?;
        let script_len = read_varint(raw, &mut pos)? as usize;
        let end = pos.checked_add(script_len)?;
        let script = raw.get(pos..end)?.to_vec();
        pos = end;
        outputs.push(BitcoinOutput { value, script });
    }
    read_u32_le(raw, &mut pos)?;
    Some(outputs)
}

fn scan_release_outputs(outputs: &[BitcoinOutput]) -> Option<([u8; 32], u64, [u8; 32])> {
    let mut payout: Option<([u8; 32], u64)> = None;
    let mut reference: Option<[u8; 32]> = None;
    for output in outputs {
        if output.script.len() != 34 || output.script[1] != 0x20 {
            continue;
        }
        let mut word = [0u8; 32];
        word.copy_from_slice(&output.script[2..34]);
        match output.script[0] {
            0x51 => {
                if payout.is_some() {
                    return None;
                }
                payout = Some((word, output.value));
            }
            0x6a => {
                if reference.is_some() {
                    return None;
                }
                reference = Some(word);
            }
            _ => {}
        }
    }
    match (payout, reference) {
        (Some((beneficiary, value)), Some(burn_ref)) => Some((beneficiary, value, burn_ref)),
        _ => None,
    }
}

pub struct BitcoinPayoutWatcher {
    corridor: u32,
    asset_id: [u8; 16],
    params: NetworkParams,
    checkpoint: Checkpoint,
    confirmation_depth: u32,
    releases: Vec<BitcoinReleaseProof>,
    consumed: RefCell<BTreeSet<[u8; 32]>>,
}

impl BitcoinPayoutWatcher {
    pub fn new(
        corridor: u32,
        asset_id: [u8; 16],
        params: NetworkParams,
        checkpoint: Checkpoint,
        confirmation_depth: u32,
        releases: Vec<BitcoinReleaseProof>,
    ) -> BitcoinPayoutWatcher {
        BitcoinPayoutWatcher {
            corridor,
            asset_id,
            params,
            checkpoint,
            confirmation_depth,
            releases,
            consumed: RefCell::new(BTreeSet::new()),
        }
    }

    pub fn attest(&self, statement: &ExitStatement) -> Result<PayoutAttestation, PayoutProofError> {
        if statement.corridor != self.corridor {
            return Err(PayoutProofError::WrongCorridor);
        }
        if statement.asset_id != self.asset_id {
            return Err(PayoutProofError::WrongAsset);
        }
        let mut last = PayoutProofError::MissingReceipt;
        for release in &self.releases {
            let payout =
                match release.verify(&self.params, &self.checkpoint, self.confirmation_depth) {
                    Ok(p) => p,
                    Err(e) => {
                        last = e;
                        continue;
                    }
                };
            if payout.amount != statement.amount {
                last = PayoutProofError::AmountMismatch;
                continue;
            }
            if payout.beneficiary != statement.beneficiary {
                last = PayoutProofError::BeneficiaryMismatch;
                continue;
            }
            if payout.burn_ref != Some(statement.burn_ref) {
                last = PayoutProofError::ReferenceMismatch;
                continue;
            }
            if self.consumed.borrow().contains(&payout.foreign_ref) {
                last = PayoutProofError::ReusedPayout;
                continue;
            }
            self.consumed.borrow_mut().insert(payout.foreign_ref);
            return Ok(PayoutAttestation {
                version: PAYOUT_VERSION,
                corridor: self.corridor,
                asset_id: self.asset_id,
                amount: payout.amount,
                beneficiary: payout.beneficiary,
                burn_ref: statement.burn_ref,
                foreign_ref: payout.foreign_ref,
                proof_height: payout.proof_height,
            });
        }
        Err(last)
    }
}

impl PayoutWatcher for BitcoinPayoutWatcher {
    fn corridor(&self) -> u32 {
        self.corridor
    }

    fn confirm(&self, statement: &ExitStatement) -> Option<PayoutAttestation> {
        self.attest(statement).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReleaseProof {
    pub receipts_root: [u8; 32],
    pub receipt_index: u64,
    pub receipt_proof: Vec<Vec<u8>>,
    pub block_number: u64,
    pub release_contract: [u8; 20],
}

impl EvmReleaseProof {
    pub fn verify(&self) -> Result<VerifiedPayout, PayoutProofError> {
        Err(PayoutProofError::EvmCorridorDisabled)
    }
}

pub struct EvmPayoutWatcher {
    corridor: u32,
    releases: Vec<EvmReleaseProof>,
    consumed: RefCell<BTreeSet<[u8; 32]>>,
}

impl EvmPayoutWatcher {
    pub fn new(corridor: u32, releases: Vec<EvmReleaseProof>) -> EvmPayoutWatcher {
        EvmPayoutWatcher {
            corridor,
            releases,
            consumed: RefCell::new(BTreeSet::new()),
        }
    }

    pub fn attest(&self, statement: &ExitStatement) -> Result<PayoutAttestation, PayoutProofError> {
        if statement.corridor != self.corridor {
            return Err(PayoutProofError::WrongCorridor);
        }
        let mut last = PayoutProofError::MissingReceipt;
        for release in &self.releases {
            let payout = match release.verify() {
                Ok(p) => p,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            if payout.asset_id != Some(statement.asset_id) {
                last = PayoutProofError::WrongAsset;
                continue;
            }
            if payout.amount != statement.amount {
                last = PayoutProofError::AmountMismatch;
                continue;
            }
            if payout.beneficiary != statement.beneficiary {
                last = PayoutProofError::BeneficiaryMismatch;
                continue;
            }
            if payout.burn_ref != Some(statement.burn_ref) {
                last = PayoutProofError::ReferenceMismatch;
                continue;
            }
            if self.consumed.borrow().contains(&payout.foreign_ref) {
                last = PayoutProofError::ReusedPayout;
                continue;
            }
            self.consumed.borrow_mut().insert(payout.foreign_ref);
            return Ok(PayoutAttestation {
                version: PAYOUT_VERSION,
                corridor: self.corridor,
                asset_id: statement.asset_id,
                amount: payout.amount,
                beneficiary: payout.beneficiary,
                burn_ref: statement.burn_ref,
                foreign_ref: payout.foreign_ref,
                proof_height: payout.proof_height,
            });
        }
        Err(last)
    }
}

impl PayoutWatcher for EvmPayoutWatcher {
    fn corridor(&self) -> u32 {
        self.corridor
    }

    fn confirm(&self, statement: &ExitStatement) -> Option<PayoutAttestation> {
        self.attest(statement).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exits::EXIT_STATEMENT_VERSION;
    use qlc_bitcoin::{BITCOIN, U256};

    const EASY: NetworkParams = NetworkParams {
        network: BITCOIN.network,
        name: BITCOIN.name,
        magic: BITCOIN.magic,
        pow_limit_bits: 0x207f_ffff,
        target_timespan: BITCOIN.target_timespan,
        target_spacing: BITCOIN.target_spacing,
        confirmation_depth: BITCOIN.confirmation_depth,
        requires_pinned_checkpoint: false,
    };

    fn statement() -> ExitStatement {
        ExitStatement {
            version: EXIT_STATEMENT_VERSION,
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

    fn put_varint(value: u64, out: &mut Vec<u8>) {
        if value < 0xfd {
            out.push(value as u8);
        } else if value <= 0xffff {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        } else if value <= 0xffff_ffff {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        } else {
            out.push(0xff);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    fn release_tx(beneficiary: &[u8; 32], amount: u64, burn_ref: &[u8; 32]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        put_varint(1, &mut tx);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        put_varint(0, &mut tx);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        put_varint(2, &mut tx);
        tx.extend_from_slice(&amount.to_le_bytes());
        let mut payout_script = vec![0x51u8, 0x20];
        payout_script.extend_from_slice(beneficiary);
        put_varint(payout_script.len() as u64, &mut tx);
        tx.extend_from_slice(&payout_script);
        tx.extend_from_slice(&0u64.to_le_bytes());
        let mut reference_script = vec![0x6au8, 0x20];
        reference_script.extend_from_slice(burn_ref);
        put_varint(reference_script.len() as u64, &mut tx);
        tx.extend_from_slice(&reference_script);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn mine(mut header: BlockHeader) -> BlockHeader {
        while !header.meets_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn bitcoin_release(
        beneficiary: &[u8; 32],
        amount: u64,
        burn_ref: &[u8; 32],
    ) -> BitcoinReleaseProof {
        release_around(release_tx(beneficiary, amount, burn_ref))
    }

    fn release_around(raw_tx: Vec<u8>) -> BitcoinReleaseProof {
        let coinbase = [0xcb; 32];
        let release_txid = double_sha256(&raw_tx);
        let mut leaves = Vec::new();
        leaves.extend_from_slice(&coinbase);
        leaves.extend_from_slice(&release_txid);
        let root = double_sha256(&leaves);
        let branch = vec![MerkleStep {
            hash: coinbase,
            sibling_on_left: true,
        }];

        let mut headers = Vec::new();
        let first = mine(BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: root,
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 0,
        });
        headers.push(first);
        for i in 1..BITCOIN.confirmation_depth {
            let prev = headers[headers.len() - 1].block_hash();
            let next = mine(BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root: [0x33; 32],
                timestamp: 1_700_000_000 + i,
                bits: 0x207f_ffff,
                nonce: 0,
            });
            headers.push(next);
        }

        BitcoinReleaseProof {
            headers,
            start_height: 100,
            release_height: 100,
            branch,
            raw_tx,
        }
    }

    fn checkpoint_for(release: &BitcoinReleaseProof) -> Checkpoint {
        Checkpoint {
            height: release.start_height,
            hash: release.headers[0].block_hash(),
            min_work: U256::ZERO,
        }
    }

    fn bitcoin_watcher(releases: Vec<BitcoinReleaseProof>) -> BitcoinPayoutWatcher {
        let checkpoint = checkpoint_for(&releases[0]);
        BitcoinPayoutWatcher::new(
            1,
            [0xa1; 16],
            EASY,
            checkpoint,
            EASY.confirmation_depth,
            releases,
        )
    }

    fn bitcoin_watcher_with(
        release: BitcoinReleaseProof,
        checkpoint: Checkpoint,
    ) -> BitcoinPayoutWatcher {
        BitcoinPayoutWatcher::new(
            1,
            [0xa1; 16],
            EASY,
            checkpoint,
            EASY.confirmation_depth,
            vec![release],
        )
    }

    fn evm_release_stub() -> EvmReleaseProof {
        EvmReleaseProof {
            receipts_root: [0x11; 32],
            receipt_index: 3,
            receipt_proof: vec![vec![0x22; 8]],
            block_number: 20_000_000,
            release_contract: [0xab; 20],
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

    #[test]
    fn a_real_bitcoin_inclusion_proof_that_covers_the_exit_is_confirmed() {
        let s = statement();
        let watcher = bitcoin_watcher(vec![bitcoin_release(&s.beneficiary, 500, &s.burn_ref)]);
        let attestation = watcher
            .confirm(&s)
            .expect("the verified payout covers the exit");
        assert!(attestation.covers(&s));
        assert_eq!(attestation.corridor, s.corridor);
    }

    #[test]
    fn the_evm_exit_corridor_is_disabled_until_it_is_anchored() {
        assert_eq!(
            evm_release_stub().verify(),
            Err(PayoutProofError::EvmCorridorDisabled)
        );
        let s = statement();
        let watcher = EvmPayoutWatcher::new(1, vec![evm_release_stub()]);
        assert_eq!(
            watcher.attest(&s),
            Err(PayoutProofError::EvmCorridorDisabled)
        );
        assert!(watcher.confirm(&s).is_none());
    }

    #[test]
    fn a_bitcoin_payout_that_pays_too_little_does_not_cover_the_exit() {
        let s = statement();
        let watcher = bitcoin_watcher(vec![bitcoin_release(&s.beneficiary, 499, &s.burn_ref)]);
        assert_eq!(watcher.attest(&s), Err(PayoutProofError::AmountMismatch));
        assert!(watcher.confirm(&s).is_none());
    }

    #[test]
    fn a_bitcoin_payout_bound_to_another_exit_does_not_cover_this_one() {
        let s = statement();
        let watcher = bitcoin_watcher(vec![bitcoin_release(&s.beneficiary, 500, &[0x99; 32])]);
        assert_eq!(watcher.attest(&s), Err(PayoutProofError::ReferenceMismatch));
        assert!(watcher.confirm(&s).is_none());
    }

    #[test]
    fn a_forged_bitcoin_header_fails_the_proof_of_work_check() {
        let s = statement();
        let mut release = bitcoin_release(&s.beneficiary, 500, &s.burn_ref);
        release.headers[0].nonce = release.headers[0].nonce.wrapping_add(1);
        assert_eq!(
            release.verify(&EASY, &checkpoint_for(&release), EASY.confirmation_depth),
            Err(PayoutProofError::Spv(SpvError::PowNotMet))
        );
        let watcher = bitcoin_watcher(vec![release]);
        assert!(watcher.confirm(&s).is_none());
    }

    #[test]
    fn a_forged_bitcoin_merkle_branch_fails_the_inclusion_check() {
        let s = statement();
        let mut release = bitcoin_release(&s.beneficiary, 500, &s.burn_ref);
        release.branch[0].hash = [0x00; 32];
        assert_eq!(
            release.verify(&EASY, &checkpoint_for(&release), EASY.confirmation_depth),
            Err(PayoutProofError::Spv(SpvError::MerkleMismatch))
        );
        assert!(bitcoin_watcher(vec![release]).confirm(&s).is_none());
    }

    #[test]
    fn a_forged_bitcoin_payload_breaks_the_txid_binding() {
        let s = statement();
        let mut release = bitcoin_release(&s.beneficiary, 500, &s.burn_ref);
        let last = release.raw_tx.len() - 6;
        release.raw_tx[last] ^= 0xff;
        assert_eq!(
            release.verify(&EASY, &checkpoint_for(&release), EASY.confirmation_depth),
            Err(PayoutProofError::Spv(SpvError::MerkleMismatch))
        );
    }

    #[test]
    fn a_trivial_difficulty_release_chain_is_rejected_without_the_pinned_work() {
        let s = statement();
        let release = bitcoin_release(&s.beneficiary, 500, &s.burn_ref);
        let heavy = Checkpoint {
            height: release.start_height,
            hash: release.headers[0].block_hash(),
            min_work: U256::from_u64(u64::MAX),
        };
        assert_eq!(
            release.verify(&EASY, &heavy, EASY.confirmation_depth),
            Err(PayoutProofError::Spv(SpvError::InsufficientWork)),
            "a floor-difficulty release chain cannot forge a payout below the pinned work"
        );
        assert!(bitcoin_watcher_with(release, heavy).confirm(&s).is_none());
    }

    #[test]
    fn a_release_chain_off_the_pinned_checkpoint_is_rejected() {
        let s = statement();
        let release = bitcoin_release(&s.beneficiary, 500, &s.burn_ref);
        let foreign = Checkpoint {
            height: release.start_height,
            hash: [0x99u8; 32],
            min_work: U256::ZERO,
        };
        assert_eq!(
            release.verify(&EASY, &foreign, EASY.confirmation_depth),
            Err(PayoutProofError::Spv(SpvError::CheckpointMismatch)),
            "a release proof on a chain off the pinned checkpoint cannot release the vault"
        );
        assert!(bitcoin_watcher_with(release, foreign).confirm(&s).is_none());
    }

    #[test]
    fn a_release_with_two_candidate_payout_outputs_is_rejected() {
        let s = statement();
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        put_varint(1, &mut tx);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        put_varint(0, &mut tx);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        put_varint(3, &mut tx);
        tx.extend_from_slice(&500u64.to_le_bytes());
        let mut first = vec![0x51u8, 0x20];
        first.extend_from_slice(&s.beneficiary);
        put_varint(first.len() as u64, &mut tx);
        tx.extend_from_slice(&first);
        tx.extend_from_slice(&999u64.to_le_bytes());
        let mut second = vec![0x51u8, 0x20];
        second.extend_from_slice(&[0x66u8; 32]);
        put_varint(second.len() as u64, &mut tx);
        tx.extend_from_slice(&second);
        tx.extend_from_slice(&0u64.to_le_bytes());
        let mut reference = vec![0x6au8, 0x20];
        reference.extend_from_slice(&s.burn_ref);
        put_varint(reference.len() as u64, &mut tx);
        tx.extend_from_slice(&reference);
        tx.extend_from_slice(&0u32.to_le_bytes());

        let release = release_around(tx);
        assert_eq!(
            release.verify(&EASY, &checkpoint_for(&release), EASY.confirmation_depth),
            Err(PayoutProofError::UnboundPayout),
            "two candidate payout outputs must be refused rather than bound to the last"
        );
    }

    #[test]
    fn a_confirmed_attestation_round_trips_on_the_wire() {
        let s = statement();
        let watcher = bitcoin_watcher(vec![bitcoin_release(&s.beneficiary, 500, &s.burn_ref)]);
        let attestation = watcher.confirm(&s).unwrap();

        let encoded = attestation.encode();
        assert_eq!(encoded.len(), PAYOUT_ENCODED_LEN);
        assert_eq!(PayoutAttestation::decode(&encoded).unwrap(), attestation);
    }

    #[test]
    fn one_verified_payout_cannot_be_replayed() {
        let s = statement();
        let watcher = bitcoin_watcher(vec![bitcoin_release(&s.beneficiary, 500, &s.burn_ref)]);
        assert!(watcher.confirm(&s).is_some());

        assert_eq!(watcher.attest(&s), Err(PayoutProofError::ReusedPayout));
        assert!(watcher.confirm(&s).is_none());
    }
}
