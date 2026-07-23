use std::collections::BTreeSet;

use q_airlock::AttestationEnvelope;
use q_gateway::{Gateway, GatewayError, MintReceipt};

use crate::corridors::{corridors, Corridor};
use crate::sources::SourceRegistry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedError {
    NotFederated,
    UndeclaredSource(u32),
    CorrelatedSources { independent: usize, signers: usize },
    Gateway(GatewayError),
}

pub fn install(gateway: &mut Gateway) {
    for c in corridors() {
        gateway.register_corridor(c.chain_id, c.confirmation_depth);
        gateway.register_asset_cap(c.origin_asset.0, c.cap_base_units);
    }
}

pub fn admit(
    gateway: &mut Gateway,
    corridor: &Corridor,
    sources: &SourceRegistry,
    env: &AttestationEnvelope,
) -> Result<MintReceipt, FederatedError> {
    if !corridor.is_federated() {
        return Err(FederatedError::NotFederated);
    }

    let signers: BTreeSet<u32> = env.signatures.iter().map(|s| s.operator_id).collect();

    for id in &signers {
        if sources.endpoint(corridor.chain_id, *id).is_none() {
            return Err(FederatedError::UndeclaredSource(*id));
        }
    }

    let report = sources.analyze(corridor.chain_id, &signers);
    if report.correlated() {
        return Err(FederatedError::CorrelatedSources {
            independent: report.independent_sources,
            signers: report.signers,
        });
    }

    gateway
        .process_deposit(env)
        .map_err(FederatedError::Gateway)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corridors::{find, SOLANA};
    use crate::sources::SourceEndpoint;
    use q_airlock::SignerSig;
    use q_codec::{
        AssetId, BridgeFact, Direction, Recipient, SourceRef, ATTEST_DOMAIN, FACT_VERSION,
    };
    use q_gateway::OperatorSet;
    use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey};

    const CHAIN_ID: u32 = 9000;

    struct Op {
        id: u32,
        pk: PublicKey,
        sk: SecretKey,
    }

    fn mk(id: u32) -> Op {
        let mut seed = [0u8; 32];
        seed[0] = id as u8;
        seed[31] = 0x5e;
        let (pk, sk) = ml_dsa::keygen(&seed);
        Op { id, pk, sk }
    }

    fn fact(source_ref: [u8; 32]) -> BridgeFact {
        let c = find(SOLANA).unwrap();
        BridgeFact {
            version: FACT_VERSION,
            source_chain: SOLANA,
            dest_chain: CHAIN_ID,
            route_id: 1,
            direction: Direction::Deposit,
            nonce: 1,
            source_ref: SourceRef(source_ref),
            asset_id: AssetId(c.origin_asset.0),
            amount: 500,
            recipient: Recipient([0x55; 32]),
            finality_depth: 40,
            observed_height: 900_000,
        }
    }

    fn attest(op: &Op, f: &BridgeFact) -> SignerSig {
        let sig = ml_dsa::sign(&op.sk, &f.attest_preimage(), ATTEST_DOMAIN, &[0u8; 32]).unwrap();
        SignerSig {
            operator_id: op.id,
            signature: sig.to_vec(),
        }
    }

    fn ep(byte: u8) -> SourceEndpoint {
        SourceEndpoint([byte; 32])
    }

    fn build() -> (Vec<Op>, Gateway) {
        let ops: Vec<Op> = (0..5).map(mk).collect();
        let mut set = OperatorSet::new(3);
        for op in &ops {
            set.register(op.id, op.pk);
        }
        let mut gw = Gateway::new(CHAIN_ID, set, 1_000_000_000_000);
        install(&mut gw);
        (ops, gw)
    }

    #[test]
    fn an_independent_distinct_quorum_mints() {
        let (ops, mut gw) = build();
        let mut sources = SourceRegistry::new();
        for op in &ops {
            sources.declare(SOLANA, op.id, ep(0x10 + op.id as u8));
        }
        let f = fact([0x11; 32]);
        let env = AttestationEnvelope {
            fact: f.clone(),
            signatures: vec![attest(&ops[0], &f), attest(&ops[1], &f), attest(&ops[2], &f)],
        };
        let c = find(SOLANA).unwrap();
        let receipt = admit(&mut gw, &c, &sources, &env).expect("independent quorum mints");
        assert_eq!(receipt.amount, 500);
    }

    #[test]
    fn a_correlated_quorum_is_refused_before_any_mint() {
        let (ops, mut gw) = build();
        let mut sources = SourceRegistry::new();
        sources.declare(SOLANA, ops[0].id, ep(0xaa));
        sources.declare(SOLANA, ops[1].id, ep(0xaa));
        sources.declare(SOLANA, ops[2].id, ep(0xcc));
        let f = fact([0x12; 32]);
        let env = AttestationEnvelope {
            fact: f.clone(),
            signatures: vec![attest(&ops[0], &f), attest(&ops[1], &f), attest(&ops[2], &f)],
        };
        let c = find(SOLANA).unwrap();
        assert_eq!(
            admit(&mut gw, &c, &sources, &env),
            Err(FederatedError::CorrelatedSources {
                independent: 2,
                signers: 3
            })
        );
        assert_eq!(gw.minted_of_asset(&c.origin_asset.0), 0);
    }

    #[test]
    fn a_sub_quorum_reaches_the_gateway_and_is_below_threshold() {
        let (ops, mut gw) = build();
        let mut sources = SourceRegistry::new();
        for op in &ops {
            sources.declare(SOLANA, op.id, ep(0x20 + op.id as u8));
        }
        let f = fact([0x13; 32]);
        let env = AttestationEnvelope {
            fact: f.clone(),
            signatures: vec![attest(&ops[0], &f), attest(&ops[1], &f)],
        };
        let c = find(SOLANA).unwrap();
        assert_eq!(
            admit(&mut gw, &c, &sources, &env),
            Err(FederatedError::Gateway(GatewayError::BelowThreshold {
                got: 2,
                need: 3
            }))
        );
    }

    #[test]
    fn an_undeclared_source_is_refused() {
        let (ops, mut gw) = build();
        let mut sources = SourceRegistry::new();
        sources.declare(SOLANA, ops[0].id, ep(0x30));
        sources.declare(SOLANA, ops[1].id, ep(0x31));
        let f = fact([0x14; 32]);
        let env = AttestationEnvelope {
            fact: f.clone(),
            signatures: vec![attest(&ops[0], &f), attest(&ops[1], &f), attest(&ops[2], &f)],
        };
        let c = find(SOLANA).unwrap();
        assert_eq!(
            admit(&mut gw, &c, &sources, &env),
            Err(FederatedError::UndeclaredSource(2))
        );
    }
}
