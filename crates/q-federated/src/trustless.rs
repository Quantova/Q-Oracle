// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_codec::BridgeFact;
use q_gateway::Gateway;
use qlc_bitcoin::TrustlessDeposit;

use crate::corridors::Corridor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustlessError {
    NotProofBacked,
    SourceMismatch { corridor: u32, fact: u32 },
    ReferenceMismatch,
    AmountMismatch { proven: u128, fact: u128 },
    RecipientMismatch,
    InsufficientConfirmations { have: u32, need: u32 },
    ReplayedReference,
    AssetNotRegistered,
    AssetCapExceeded { minted: u128, cap: u128, add: u128 },
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
    if proven.confirmations < corridor.confirmation_depth {
        return Err(TrustlessError::InsufficientConfirmations {
            have: proven.confirmations,
            need: corridor.confirmation_depth,
        });
    }
    Ok(TrustlessMint {
        asset_id: fact.asset_id.0,
        recipient: proven.recipient,
        amount: proven.amount,
        source_ref: proven.txid,
        source_chain: corridor.chain_id,
        confirmations: proven.confirmations,
    })
}

/// The trustless admission path, run alongside the federated `admit`. It clears the fact-match
/// gate, then applies the gateway's replay and per-asset cap checks against current state. The
/// gateway is read only here: the authoritative mint, which inserts the source reference and
/// advances the minted total under the same replay and cap invariants, is the seam this returns
/// to. That mint entry point is not opened on the gateway because a proof-backed deposit must not
/// mint without the corridor's STARK verified on chain, a founder-level gateway change.
pub fn admit_bitcoin_trustless(
    gateway: &Gateway,
    corridor: &Corridor,
    proven: &TrustlessDeposit,
    fact: &BridgeFact,
) -> Result<TrustlessMint, TrustlessError> {
    let mint = match_bitcoin_deposit(corridor, proven, fact)?;
    if gateway.is_reference_used(&mint.source_ref) {
        return Err(TrustlessError::ReplayedReference);
    }
    let cap = gateway
        .asset_cap(&mint.asset_id)
        .ok_or(TrustlessError::AssetNotRegistered)?;
    let minted = gateway.minted_of_asset(&mint.asset_id);
    let after = minted
        .checked_add(mint.amount)
        .ok_or(TrustlessError::AssetCapExceeded {
            minted,
            cap,
            add: mint.amount,
        })?;
    if after > cap {
        return Err(TrustlessError::AssetCapExceeded {
            minted,
            cap,
            add: mint.amount,
        });
    }
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
        let gw = gateway_with_cap(c.origin_asset.0, 1_000_000);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        let mint = admit_bitcoin_trustless(&gw, &c, &p, &f).expect("within cap");
        assert_eq!(mint.amount, 250_000);
    }

    #[test]
    fn admission_refuses_an_unregistered_asset() {
        let c = corridor(Tier::ProofBacked);
        let gw = Gateway::new(DEST, OperatorSet::new(0), 1_000_000_000_000);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        assert_eq!(
            admit_bitcoin_trustless(&gw, &c, &p, &f),
            Err(TrustlessError::AssetNotRegistered)
        );
    }

    #[test]
    fn admission_refuses_a_deposit_over_the_asset_cap() {
        let c = corridor(Tier::ProofBacked);
        let gw = gateway_with_cap(c.origin_asset.0, 249_999);
        let txid = [0x11u8; 32];
        let recipient = [0x42u8; 32];
        let p = proven(txid, 250_000, recipient, 6);
        let f = fact_for(&c, txid, 250_000, recipient);
        assert_eq!(
            admit_bitcoin_trustless(&gw, &c, &p, &f),
            Err(TrustlessError::AssetCapExceeded {
                minted: 0,
                cap: 249_999,
                add: 250_000
            })
        );
    }
}
