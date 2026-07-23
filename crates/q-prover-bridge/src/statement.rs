use q_codec::{BridgeFact, Writer};
use qtv_stark::sponge::{absorb_output, SHAKE256_RATE};

pub const BRIDGE_STATEMENT_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/BRIDGE-PROVER/v1";
pub const STATEMENT_DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorridorStatement {
    pub operator: u32,
    pub fact: BridgeFact,
}

impl CorridorStatement {
    pub fn new(operator: u32, fact: BridgeFact) -> CorridorStatement {
        CorridorStatement { operator, fact }
    }

    pub fn preimage(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(BRIDGE_STATEMENT_DOMAIN);
        w.u32(self.operator);
        w.fixed(&self.fact.encode());
        w.finish()
    }

    pub fn digest(&self) -> [u8; STATEMENT_DIGEST_LEN] {
        let squeeze = absorb_output(SHAKE256_RATE, &self.preimage());
        let mut digest = [0u8; STATEMENT_DIGEST_LEN];
        digest.copy_from_slice(&squeeze[..STATEMENT_DIGEST_LEN]);
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use q_codec::{AssetId, Direction, Recipient, SourceRef, FACT_ENCODED_LEN, FACT_VERSION};
    use qtv_crypto::sha3::shake256;

    fn fact() -> BridgeFact {
        BridgeFact {
            version: FACT_VERSION,
            source_chain: 1,
            dest_chain: 9000,
            route_id: 7,
            direction: Direction::Deposit,
            nonce: 42,
            source_ref: SourceRef([9u8; 32]),
            asset_id: AssetId([3u8; 16]),
            amount: 1_000_000,
            recipient: Recipient([5u8; 32]),
            finality_depth: 12,
            observed_height: 880_000,
        }
    }

    fn statement() -> CorridorStatement {
        CorridorStatement::new(4, fact())
    }

    #[test]
    fn the_preimage_leads_with_the_domain_and_carries_the_operator_and_fact() {
        let s = statement();
        let pre = s.preimage();
        assert!(pre.starts_with(BRIDGE_STATEMENT_DOMAIN));
        assert!(pre.ends_with(&s.fact.encode()));
        assert_eq!(
            pre.len(),
            BRIDGE_STATEMENT_DOMAIN.len() + 4 + FACT_ENCODED_LEN
        );
    }

    #[test]
    fn the_digest_is_deterministic() {
        assert_eq!(statement().digest(), statement().digest());
    }

    #[test]
    fn the_digest_is_the_shake256_prefix_of_the_preimage() {
        let s = statement();
        let mut squeeze = [0u8; STATEMENT_DIGEST_LEN];
        shake256(&s.preimage(), &mut squeeze);
        assert_eq!(s.digest(), squeeze);
    }

    #[test]
    fn the_operator_moves_the_digest() {
        let base = statement().digest();
        let mut other = statement();
        other.operator = 5;
        assert_ne!(other.digest(), base);
    }

    #[test]
    fn every_fact_field_moves_the_digest() {
        let base = statement().digest();

        let mut a = statement();
        a.fact.source_chain = 2;
        assert_ne!(a.digest(), base);

        let mut b = statement();
        b.fact.dest_chain = 9001;
        assert_ne!(b.digest(), base);

        let mut c = statement();
        c.fact.route_id = 8;
        assert_ne!(c.digest(), base);

        let mut d = statement();
        d.fact.direction = Direction::ExitAck;
        assert_ne!(d.digest(), base);

        let mut e = statement();
        e.fact.nonce = 43;
        assert_ne!(e.digest(), base);

        let mut f = statement();
        f.fact.source_ref = SourceRef([8u8; 32]);
        assert_ne!(f.digest(), base);

        let mut g = statement();
        g.fact.asset_id = AssetId([4u8; 16]);
        assert_ne!(g.digest(), base);

        let mut h = statement();
        h.fact.amount = 1_000_001;
        assert_ne!(h.digest(), base);

        let mut i = statement();
        i.fact.recipient = Recipient([6u8; 32]);
        assert_ne!(i.digest(), base);

        let mut j = statement();
        j.fact.finality_depth = 13;
        assert_ne!(j.digest(), base);

        let mut k = statement();
        k.fact.observed_height = 880_001;
        assert_ne!(k.digest(), base);
    }
}
