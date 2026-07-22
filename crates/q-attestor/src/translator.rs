use q_codec::{AssetId, BridgeFact, Direction, Recipient, SourceRef, FACT_VERSION};

use crate::watcher::{CorridorContext, ObservedLock};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
