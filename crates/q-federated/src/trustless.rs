// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_codec::BridgeFact;
use q_gateway::{Gateway, GatewayError};
use qlc_bitcoin::TrustlessDeposit;
use qlc_cosmos::TrustlessDeposit as CosmosDeposit;
use qlc_ethereum::TrustlessDeposit as EthereumDeposit;

use crate::corridors::Corridor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustlessError {
    NotProofBacked,
    SourceMismatch { corridor: u32, fact: u32 },
    ReferenceMismatch,
    AmountMismatch { proven: u128, fact: u128 },
    RecipientMismatch,
    AssetMismatch,
    InsufficientConfirmations { have: u32, need: u32 },
    ReplayedReference,
    AssetNotRegistered,
    AssetCapExceeded { minted: u128, cap: u128, add: u128 },
    Gateway(GatewayError),
}

/// A trustless deposit that has passed the fact-match gate and is cleared to mint. Every field is
/// carried from the proof, never from the fact, so the fact only names an intent the proof met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessMint {
    pub asset_id: [u8; 16],
    pub recipient: [u8; 32],
    pub amount: u128,
    pub source_ref: [u8; 32],
    pub source_chain: u32,
    pub confirmations: u32,
}

/// The pure verification-plus-fact-match gate for a proof-backed corridor. A verified Bitcoin
/// deposit clears only when the fact names the same source chain, the same deposit by its
/// transaction id, the amount the transaction actually pays, and the recipient it actually names,
/// and only when the proven confirmations reach the corridor depth. The proven values, not the
/// fact's, are carried forward.
pub fn match_bitcoin_deposit(
    corridor: &Corridor,
    proven: &TrustlessDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    if !corridor.tier.is_proof_backed() {
        return Err(TrustlessError::NotProofBacked);
    }
    if fact.source_chain != corridor.chain_id {
        return Err(TrustlessError::SourceMismatch {
            corridor: corridor.chain_id,
            fact: fact.source_chain,
        });
    }
    if fact.source_ref.0 != proven.txid {
        return Err(TrustlessError::ReferenceMismatch);
    }
    if fact.amount != proven.amount {
        return Err(TrustlessError::AmountMismatch {
            proven: proven.amount,
            fact: fact.amount,
        });
    }
    if fact.recipient.0 != proven.recipient {
        return Err(TrustlessError::RecipientMismatch);
    }
    if fact.asset_id.0 != corridor.origin_asset.0 {
        return Err(TrustlessError::AssetMismatch);
    }
    if proven.confirmations < corridor.confirmation_depth {
        return Err(TrustlessError::InsufficientConfirmations {
            have: proven.confirmations,
            need: corridor.confirmation_depth,
        });
    }
    Ok(TrustlessMint {
        asset_id: corridor.origin_asset.0,
        recipient: proven.recipient,
        amount: proven.amount,
        source_ref: proven.txid,
        source_chain: corridor.chain_id,
        confirmations: proven.confirmations,
    })
}

pub fn admit_bitcoin_trustless(
    gateway: &mut Gateway,
    corridor: &Corridor,
    proven: &TrustlessDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    let mint = match_bitcoin_deposit(corridor, proven, fact)?;
    apply_replay_and_cap(gateway, &mint)?;
    Ok(mint)
}

fn apply_replay_and_cap(gateway: &mut Gateway, mint: &TrustlessMint) -> Result<(), TrustlessError> {
    gateway
        .admit_trustless(mint.asset_id, mint.source_ref, mint.amount)
        .map_err(|e| match e {
            GatewayError::ReplayedReference => TrustlessError::ReplayedReference,
            GatewayError::AssetNotRegistered => TrustlessError::AssetNotRegistered,
            GatewayError::AssetCapExceeded { minted, cap, add } => {
                TrustlessError::AssetCapExceeded { minted, cap, add }
            }
            other => TrustlessError::Gateway(other),
        })
}

/// The pure verification-plus-fact-match gate for a proof-backed Ethereum corridor. A verified
/// Ethereum deposit clears only when the fact names the same source chain, the same deposit by the
/// reference derived from its receipt, the amount, recipient and asset the bridge log actually
/// carries, and only when the proven finality depth reaches the corridor depth. The proven values,
/// not the fact's, are carried forward.
pub fn match_ethereum_deposit(
    corridor: &Corridor,
    proven: &EthereumDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    if !corridor.tier.is_proof_backed() {
        return Err(TrustlessError::NotProofBacked);
    }
    if fact.source_chain != corridor.chain_id {
        return Err(TrustlessError::SourceMismatch {
            corridor: corridor.chain_id,
            fact: fact.source_chain,
        });
    }
    if fact.source_ref.0 != proven.source_ref {
        return Err(TrustlessError::ReferenceMismatch);
    }
    if fact.amount != proven.amount {
        return Err(TrustlessError::AmountMismatch {
            proven: proven.amount,
            fact: fact.amount,
        });
    }
    if fact.recipient.0 != proven.recipient {
        return Err(TrustlessError::RecipientMismatch);
    }
    if fact.asset_id.0 != proven.asset_id {
        return Err(TrustlessError::AssetMismatch);
    }
    if proven.finality_depth < corridor.confirmation_depth {
        return Err(TrustlessError::InsufficientConfirmations {
            have: proven.finality_depth,
            need: corridor.confirmation_depth,
        });
    }
    Ok(TrustlessMint {
        asset_id: proven.asset_id,
        recipient: proven.recipient,
        amount: proven.amount,
        source_ref: proven.source_ref,
        source_chain: corridor.chain_id,
        confirmations: proven.finality_depth,
    })
}

pub fn admit_ethereum_trustless(
    gateway: &mut Gateway,
    corridor: &Corridor,
    proven: &EthereumDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    let mint = match_ethereum_deposit(corridor, proven, fact)?;
    apply_replay_and_cap(gateway, &mint)?;
    Ok(mint)
}

/// The pure verification-plus-fact-match gate for a proof-backed Cosmos corridor. A verified Cosmos
/// deposit clears only when the fact names the same source chain, the same deposit by the reference
/// derived from its proven key, the amount, recipient and asset the value under the app hash
/// actually carries, and only when the proven confirmations reach the corridor depth. The proven
/// values, not the fact's, are carried forward.
pub fn match_cosmos_deposit(
    corridor: &Corridor,
    proven: &CosmosDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    if !corridor.tier.is_proof_backed() {
        return Err(TrustlessError::NotProofBacked);
    }
    if fact.source_chain != corridor.chain_id {
        return Err(TrustlessError::SourceMismatch {
            corridor: corridor.chain_id,
            fact: fact.source_chain,
        });
    }
    if fact.source_ref.0 != proven.source_ref {
        return Err(TrustlessError::ReferenceMismatch);
    }
    if fact.amount != proven.amount {
        return Err(TrustlessError::AmountMismatch {
            proven: proven.amount,
            fact: fact.amount,
        });
    }
    if fact.recipient.0 != proven.recipient {
        return Err(TrustlessError::RecipientMismatch);
    }
    if fact.asset_id.0 != proven.asset_id {
        return Err(TrustlessError::AssetMismatch);
    }
    if proven.confirmations < corridor.confirmation_depth {
        return Err(TrustlessError::InsufficientConfirmations {
            have: proven.confirmations,
            need: corridor.confirmation_depth,
        });
    }
    Ok(TrustlessMint {
        asset_id: proven.asset_id,
        recipient: proven.recipient,
        amount: proven.amount,
        source_ref: proven.source_ref,
        source_chain: corridor.chain_id,
        confirmations: proven.confirmations,
    })
}

pub fn admit_cosmos_trustless(
    gateway: &mut Gateway,
    corridor: &Corridor,
    proven: &CosmosDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    let mint = match_cosmos_deposit(corridor, proven, fact)?;
    apply_replay_and_cap(gateway, &mint)?;
    Ok(mint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corridors::{origin_tag, Tier, TrustGrade};
    use q_codec::{AssetId, Direction, Recipient, SourceRef, FACT_VERSION};
    use q_gateway::{Gateway, OperatorSet};

    const BITCOIN_CHAIN: u32 = 1;
    const DEST: u32 = 9000;

    fn corridor(tier: Tier) -> Corridor {
        Corridor {
            chain_id: BITCOIN_CHAIN,
            name: "Bitcoin",
            tier,
            grade: TrustGrade::Trustless,
            confirmation_depth: 6,
            origin_asset: origin_tag(BITCOIN_CHAIN),
            cap_base_units: 1_000_000,
            active: true,
        }
    }

    fn proven(txid: [u8; 32], amount: u128, recipient: [u8; 32], confs: u32) -> TrustlessDeposit {
        TrustlessDeposit {
            txid,
            amount,
            recipient,
            confirmations: confs,
        }
    }

    fn fact_for(c: &Corridor, txid: [u8; 32], amount: u128, recipient: [u8; 32]) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: c.chain_id,
            dest_chain: DEST,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(txid),
            asset_id: AssetId(c.origin_asset.0),
            amount,
            recipient: Recipient(recipient),
            finality_depth: 6,
            observed_height: 800_000,
            expiry_height: 900_000,
        }
    }

    fn gateway_with_cap(asset: [u8; 16], cap: u128) -> Gateway {
        let mut gw = Gateway::new(DEST, OperatorSet::new(0), 1_000_000_000_000);
        gw.register_asset_cap(asset, cap);
        gw
    }

    #[test]
    fn a_proof_that_matches_the_fact_clears_the_gate() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);

        let mint = match_bitcoin_deposit(&c, &p, &f).expect("matching proof mints");
        assert_eq!(mint.amount, 250_000);
        assert_eq!(mint.recipient, recipient);
        assert_eq!(mint.source_ref, txid);
        assert_eq!(mint.source_chain, BITCOIN_CHAIN);
        assert_eq!(mint.asset_id, c.origin_asset.0);
        assert_eq!(mint.confirmations, 6);
    }

    #[test]
    fn a_federated_corridor_is_refused_from_the_trustless_path() {
        let c = corridor(Tier::Federated);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::NotProofBacked)
        );
    }

    #[test]
    fn a_bitcoin_deposit_naming_a_non_btc_asset_is_refused() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let mut f = fact_for(&c, txid, 250_000, recipient);
        f.asset_id = AssetId([0x99u8; 16]);
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::AssetMismatch),
            "a btc proof may not mint an attacker-listed bitcoin-network token"
        );
    }

    #[test]
    fn the_bitcoin_mint_asset_is_the_corridor_native_asset_not_the_fact() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        let mint = match_bitcoin_deposit(&c, &p, &f).expect("the canonical btc asset mints");
        assert_eq!(mint.asset_id, c.origin_asset.0);
    }

    #[test]
    fn a_fact_that_overstates_the_amount_is_refused() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_001, recipient);
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::AmountMismatch {
                proven: 250_000,
                fact: 250_001
            })
        );
    }

    #[test]
    fn a_fact_that_names_a_different_recipient_is_refused() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let p = proven(txid, 250_000, [0x42u8; 32], 6);
        let f = fact_for(&c, txid, 250_000, [0x43u8; 32]);
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::RecipientMismatch)
        );
    }

    #[test]
    fn a_fact_whose_reference_is_not_the_proven_txid_is_refused() {
        let c = corridor(Tier::ProofBacked);
        let recipient = [0x42u8; 32];
        let p = proven([0x11u8; 32], 250_000, recipient, 6);
        let f = fact_for(&c, [0x99u8; 32], 250_000, recipient);
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::ReferenceMismatch)
        );
    }

    #[test]
    fn a_fact_on_a_different_source_chain_is_refused() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let mut f = fact_for(&c, txid, 250_000, recipient);
        f.source_chain = 5;
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::SourceMismatch {
                corridor: BITCOIN_CHAIN,
                fact: 5
            })
        );
    }

    #[test]
    fn a_deposit_short_of_the_corridor_depth_is_refused() {
        let c = corridor(Tier::ProofBacked);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 5);
        let f = fact_for(&c, txid, 250_000, recipient);
        assert_eq!(
            match_bitcoin_deposit(&c, &p, &f),
            Err(TrustlessError::InsufficientConfirmations { have: 5, need: 6 })
        );
    }

    #[test]
    fn admission_clears_within_the_asset_cap() {
        let c = corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(c.origin_asset.0, 1_000_000);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        let mint = admit_bitcoin_trustless(&mut gw, &c, &p, &f).expect("within cap");
        assert_eq!(mint.amount, 250_000);
    }

    #[test]
    fn admission_refuses_an_unregistered_asset() {
        let c = corridor(Tier::ProofBacked);
        let mut gw = Gateway::new(DEST, OperatorSet::new(0), 1_000_000_000_000);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        assert_eq!(
            admit_bitcoin_trustless(&mut gw, &c, &p, &f),
            Err(TrustlessError::AssetNotRegistered)
        );
    }

    #[test]
    fn admission_refuses_a_deposit_over_the_asset_cap() {
        let c = corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(c.origin_asset.0, 249_999);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        assert_eq!(
            admit_bitcoin_trustless(&mut gw, &c, &p, &f),
            Err(TrustlessError::AssetCapExceeded {
                minted: 0,
                cap: 249_999,
                add: 250_000
            })
        );
    }

    #[test]
    fn a_second_admit_of_the_same_reference_is_rejected() {
        let c = corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(c.origin_asset.0, 1_000_000);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        admit_bitcoin_trustless(&mut gw, &c, &p, &f).expect("the first admit clears and records");
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 250_000);
        assert!(gw.is_reference_used(&txid));
        assert_eq!(
            admit_bitcoin_trustless(&mut gw, &c, &p, &f),
            Err(TrustlessError::ReplayedReference),
            "the same reference cannot be admitted twice"
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 250_000);
    }

    #[test]
    fn the_asset_cap_binds_across_two_admits() {
        let c = corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(c.origin_asset.0, 400_000);
        let recipient = [0x42u8; 32];
        let p1 = proven([0x11u8; 32], 250_000, recipient, 6);
        let f1 = fact_for(&c, [0x11u8; 32], 250_000, recipient);
        admit_bitcoin_trustless(&mut gw, &c, &p1, &f1).expect("the first admit reserves budget");
        let p2 = proven([0x22u8; 32], 250_000, recipient, 6);
        let f2 = fact_for(&c, [0x22u8; 32], 250_000, recipient);
        assert_eq!(
            admit_bitcoin_trustless(&mut gw, &c, &p2, &f2),
            Err(TrustlessError::AssetCapExceeded {
                minted: 250_000,
                cap: 400_000,
                add: 250_000
            }),
            "the second admit is refused because the first reserved the budget"
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 250_000);
    }

    const ETH_CHAIN: u32 = 1;
    const COSMOS_CHAIN: u32 = 8;
    const ETH_ASSET: [u8; 16] = [0x77; 16];
    const COSMOS_ASSET: [u8; 16] = [0x22; 16];

    fn eth_corridor(tier: Tier) -> Corridor {
        Corridor {
            chain_id: ETH_CHAIN,
            name: "Ethereum",
            tier,
            grade: TrustGrade::Trustless,
            confirmation_depth: 64,
            origin_asset: origin_tag(ETH_CHAIN),
            cap_base_units: 1_000_000,
            active: true,
        }
    }

    fn cosmos_corridor(tier: Tier) -> Corridor {
        Corridor {
            chain_id: COSMOS_CHAIN,
            name: "Cosmos Hub",
            tier,
            grade: TrustGrade::Trustless,
            confirmation_depth: 2,
            origin_asset: origin_tag(COSMOS_CHAIN),
            cap_base_units: 1_000_000,
            active: true,
        }
    }

    fn eth_proven(
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
        asset: [u8; 16],
        finality: u32,
    ) -> EthereumDeposit {
        EthereumDeposit {
            source_ref,
            amount,
            recipient,
            asset_id: asset,
            block_number: 20_000_000,
            finality_depth: finality,
        }
    }

    fn cosmos_proven(
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
        asset: [u8; 16],
        confs: u32,
    ) -> CosmosDeposit {
        CosmosDeposit {
            source_ref,
            amount,
            recipient,
            asset_id: asset,
            height: 18_500_000,
            confirmations: confs,
        }
    }

    fn fact_with_asset(
        c: &Corridor,
        source_ref: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
        asset: [u8; 16],
    ) -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: c.chain_id,
            dest_chain: DEST,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(source_ref),
            asset_id: AssetId(asset),
            amount,
            recipient: Recipient(recipient),
            finality_depth: c.confirmation_depth,
            observed_height: 800_000,
            expiry_height: 900_000,
        }
    }

    #[test]
    fn an_ethereum_proof_that_matches_the_fact_clears_the_gate() {
        let c = eth_corridor(Tier::ProofBacked);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, recipient, ETH_ASSET);
        let mint = match_ethereum_deposit(&c, &p, &f).expect("matching proof mints");
        assert_eq!(mint.amount, 250_000);
        assert_eq!(mint.recipient, recipient);
        assert_eq!(mint.source_ref, r);
        assert_eq!(mint.source_chain, ETH_CHAIN);
        assert_eq!(mint.asset_id, ETH_ASSET);
        assert_eq!(mint.confirmations, 64);
    }

    #[test]
    fn a_federated_ethereum_corridor_is_refused_from_the_trustless_path() {
        let c = eth_corridor(Tier::Federated);
        let r = [0x33u8; 32];
        let p = eth_proven(r, 250_000, [0x42u8; 32], ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, [0x42u8; 32], ETH_ASSET);
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::NotProofBacked)
        );
    }

    #[test]
    fn an_ethereum_fact_that_overstates_the_amount_is_refused() {
        let c = eth_corridor(Tier::ProofBacked);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_001, recipient, ETH_ASSET);
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::AmountMismatch {
                proven: 250_000,
                fact: 250_001
            })
        );
    }

    #[test]
    fn an_ethereum_fact_that_names_a_different_recipient_is_refused() {
        let c = eth_corridor(Tier::ProofBacked);
        let r = [0x33u8; 32];
        let p = eth_proven(r, 250_000, [0x42u8; 32], ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, [0x43u8; 32], ETH_ASSET);
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::RecipientMismatch)
        );
    }

    #[test]
    fn an_ethereum_fact_that_names_a_different_asset_is_refused() {
        let c = eth_corridor(Tier::ProofBacked);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, recipient, [0x88u8; 16]);
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::AssetMismatch)
        );
    }

    #[test]
    fn an_ethereum_fact_whose_reference_is_not_the_proven_one_is_refused() {
        let c = eth_corridor(Tier::ProofBacked);
        let recipient = [0x42u8; 32];
        let p = eth_proven([0x33u8; 32], 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, [0x99u8; 32], 250_000, recipient, ETH_ASSET);
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::ReferenceMismatch)
        );
    }

    #[test]
    fn an_ethereum_fact_on_a_different_source_chain_is_refused() {
        let c = eth_corridor(Tier::ProofBacked);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let mut f = fact_with_asset(&c, r, 250_000, recipient, ETH_ASSET);
        f.source_chain = 5;
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::SourceMismatch {
                corridor: ETH_CHAIN,
                fact: 5
            })
        );
    }

    #[test]
    fn an_ethereum_deposit_short_of_the_corridor_finality_is_refused() {
        let c = eth_corridor(Tier::ProofBacked);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 63);
        let f = fact_with_asset(&c, r, 250_000, recipient, ETH_ASSET);
        assert_eq!(
            match_ethereum_deposit(&c, &p, &f),
            Err(TrustlessError::InsufficientConfirmations { have: 63, need: 64 })
        );
    }

    #[test]
    fn ethereum_admission_clears_within_the_asset_cap() {
        let c = eth_corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(ETH_ASSET, 1_000_000);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, recipient, ETH_ASSET);
        let mint = admit_ethereum_trustless(&mut gw, &c, &p, &f).expect("within cap");
        assert_eq!(mint.amount, 250_000);
        assert_eq!(mint.asset_id, ETH_ASSET);
    }

    #[test]
    fn ethereum_admission_refuses_an_unregistered_asset() {
        let c = eth_corridor(Tier::ProofBacked);
        let mut gw = Gateway::new(DEST, OperatorSet::new(0), 1_000_000_000_000);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, recipient, ETH_ASSET);
        assert_eq!(
            admit_ethereum_trustless(&mut gw, &c, &p, &f),
            Err(TrustlessError::AssetNotRegistered)
        );
    }

    #[test]
    fn ethereum_admission_refuses_a_deposit_over_the_asset_cap() {
        let c = eth_corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(ETH_ASSET, 249_999);
        let r = [0x33u8; 32];
        let recipient = [0x42u8; 32];
        let p = eth_proven(r, 250_000, recipient, ETH_ASSET, 64);
        let f = fact_with_asset(&c, r, 250_000, recipient, ETH_ASSET);
        assert_eq!(
            admit_ethereum_trustless(&mut gw, &c, &p, &f),
            Err(TrustlessError::AssetCapExceeded {
                minted: 0,
                cap: 249_999,
                add: 250_000
            })
        );
    }

    #[test]
    fn a_cosmos_proof_that_matches_the_fact_clears_the_gate() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let r = [0x55u8; 32];
        let recipient = [0x51u8; 32];
        let p = cosmos_proven(r, 7_500_000, recipient, COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, r, 7_500_000, recipient, COSMOS_ASSET);
        let mint = match_cosmos_deposit(&c, &p, &f).expect("matching proof mints");
        assert_eq!(mint.amount, 7_500_000);
        assert_eq!(mint.recipient, recipient);
        assert_eq!(mint.source_ref, r);
        assert_eq!(mint.source_chain, COSMOS_CHAIN);
        assert_eq!(mint.asset_id, COSMOS_ASSET);
        assert_eq!(mint.confirmations, 2);
    }

    #[test]
    fn a_federated_cosmos_corridor_is_refused_from_the_trustless_path() {
        let c = cosmos_corridor(Tier::Federated);
        let r = [0x55u8; 32];
        let p = cosmos_proven(r, 7_500_000, [0x51u8; 32], COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, r, 7_500_000, [0x51u8; 32], COSMOS_ASSET);
        assert_eq!(
            match_cosmos_deposit(&c, &p, &f),
            Err(TrustlessError::NotProofBacked)
        );
    }

    #[test]
    fn a_cosmos_fact_that_overstates_the_amount_is_refused() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let r = [0x55u8; 32];
        let recipient = [0x51u8; 32];
        let p = cosmos_proven(r, 7_500_000, recipient, COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, r, 7_500_001, recipient, COSMOS_ASSET);
        assert_eq!(
            match_cosmos_deposit(&c, &p, &f),
            Err(TrustlessError::AmountMismatch {
                proven: 7_500_000,
                fact: 7_500_001
            })
        );
    }

    #[test]
    fn a_cosmos_fact_that_names_a_different_asset_is_refused() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let r = [0x55u8; 32];
        let recipient = [0x51u8; 32];
        let p = cosmos_proven(r, 7_500_000, recipient, COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, r, 7_500_000, recipient, [0x11u8; 16]);
        assert_eq!(
            match_cosmos_deposit(&c, &p, &f),
            Err(TrustlessError::AssetMismatch)
        );
    }

    #[test]
    fn a_cosmos_fact_whose_reference_is_not_the_proven_one_is_refused() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let recipient = [0x51u8; 32];
        let p = cosmos_proven([0x55u8; 32], 7_500_000, recipient, COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, [0x99u8; 32], 7_500_000, recipient, COSMOS_ASSET);
        assert_eq!(
            match_cosmos_deposit(&c, &p, &f),
            Err(TrustlessError::ReferenceMismatch)
        );
    }

    #[test]
    fn a_cosmos_deposit_short_of_the_corridor_depth_is_refused() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let r = [0x55u8; 32];
        let recipient = [0x51u8; 32];
        let p = cosmos_proven(r, 7_500_000, recipient, COSMOS_ASSET, 1);
        let f = fact_with_asset(&c, r, 7_500_000, recipient, COSMOS_ASSET);
        assert_eq!(
            match_cosmos_deposit(&c, &p, &f),
            Err(TrustlessError::InsufficientConfirmations { have: 1, need: 2 })
        );
    }

    #[test]
    fn cosmos_admission_clears_within_the_asset_cap() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(COSMOS_ASSET, 1_000_000_000);
        let r = [0x55u8; 32];
        let recipient = [0x51u8; 32];
        let p = cosmos_proven(r, 7_500_000, recipient, COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, r, 7_500_000, recipient, COSMOS_ASSET);
        let mint = admit_cosmos_trustless(&mut gw, &c, &p, &f).expect("within cap");
        assert_eq!(mint.amount, 7_500_000);
        assert_eq!(mint.asset_id, COSMOS_ASSET);
    }

    #[test]
    fn cosmos_admission_refuses_a_deposit_over_the_asset_cap() {
        let c = cosmos_corridor(Tier::ProofBacked);
        let mut gw = gateway_with_cap(COSMOS_ASSET, 7_499_999);
        let r = [0x55u8; 32];
        let recipient = [0x51u8; 32];
        let p = cosmos_proven(r, 7_500_000, recipient, COSMOS_ASSET, 2);
        let f = fact_with_asset(&c, r, 7_500_000, recipient, COSMOS_ASSET);
        assert_eq!(
            admit_cosmos_trustless(&mut gw, &c, &p, &f),
            Err(TrustlessError::AssetCapExceeded {
                minted: 0,
                cap: 7_499_999,
                add: 7_500_000
            })
        );
    }
}
