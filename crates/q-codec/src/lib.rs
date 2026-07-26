#![forbid(unsafe_code)]
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


pub const ATTEST_DOMAIN: &[u8] = b"QUANTOVA/Q-ORACLE/ATTEST/v1";
pub const FACT_VERSION: u8 = 1;
pub const FACT_ENCODED_LEN: usize = 138;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    ExitAck,
}

impl Direction {
    pub fn tag(self) -> u8 {
        match self {
            Direction::Deposit => 0,
            Direction::ExitAck => 1,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Direction, CodecError> {
        match tag {
            0 => Ok(Direction::Deposit),
            1 => Ok(Direction::ExitAck),
            other => Err(CodecError::UnknownTag(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRef(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipient(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeFact {
    pub version: u8,
    pub source_chain: u32,
    pub dest_chain: u32,
    pub route_id: u32,
    pub direction: Direction,
    pub nonce: u64,
    pub source_ref: SourceRef,
    pub asset_id: AssetId,
    pub amount: u128,
    pub recipient: Recipient,
    pub finality_depth: u32,
    pub observed_height: u64,
    pub expiry_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    ShortInput,
    TrailingBytes,
    UnknownTag(u8),
    BadVersion(u8),
    ZeroAmount,
    ZeroAsset,
    ZeroRecipient,
    ZeroSourceRef,
    ZeroChain,
    LengthMismatch,
}

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn fixed(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub fn bytes_u16(&mut self, v: &[u8]) {
        let len = v.len() as u16;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(v);
    }

    pub fn bytes_u32(&mut self, v: &[u8]) {
        let len = v.len() as u32;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(v);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for Writer {
    fn default() -> Writer {
        Writer::new()
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    fn advance(&self, n: usize) -> Result<usize, CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::ShortInput)?;
        if end > self.buf.len() {
            return Err(CodecError::ShortInput);
        }
        Ok(end)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        let end = self.advance(1)?;
        let v = self.buf[self.pos];
        self.pos = end;
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let end = self.advance(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(u32::from_le_bytes(a))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let end = self.advance(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(u64::from_le_bytes(a))
    }

    pub fn u128(&mut self) -> Result<u128, CodecError> {
        let end = self.advance(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(u128::from_le_bytes(a))
    }

    pub fn fixed(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.advance(n)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn array32(&mut self) -> Result<[u8; 32], CodecError> {
        let s = self.fixed(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn array16(&mut self) -> Result<[u8; 16], CodecError> {
        let s = self.fixed(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn bytes_u16(&mut self) -> Result<&'a [u8], CodecError> {
        let end = self.advance(2)?;
        let mut a = [0u8; 2];
        a.copy_from_slice(&self.buf[self.pos..end]);
        let len = u16::from_le_bytes(a) as usize;
        self.pos = end;
        self.fixed(len)
    }

    pub fn bytes_u32(&mut self) -> Result<&'a [u8], CodecError> {
        let end = self.advance(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.buf[self.pos..end]);
        let len = u32::from_le_bytes(a) as usize;
        self.pos = end;
        self.fixed(len)
    }

    pub fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn finish_ref(&self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

impl BridgeFact {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version);
        w.u32(self.source_chain);
        w.u32(self.dest_chain);
        w.u32(self.route_id);
        w.u8(self.direction.tag());
        w.u64(self.nonce);
        w.fixed(&self.source_ref.0);
        w.fixed(&self.asset_id.0);
        w.u128(self.amount);
        w.fixed(&self.recipient.0);
        w.u32(self.finality_depth);
        w.u64(self.observed_height);
        w.u64(self.expiry_height);
        w.finish()
    }

    pub fn decode(input: &[u8]) -> Result<BridgeFact, CodecError> {
        let mut r = Reader::new(input);
        let version = r.u8()?;
        let source_chain = r.u32()?;
        let dest_chain = r.u32()?;
        let route_id = r.u32()?;
        let direction = Direction::from_tag(r.u8()?)?;
        let nonce = r.u64()?;
        let source_ref = SourceRef(r.array32()?);
        let asset_id = AssetId(r.array16()?);
        let amount = r.u128()?;
        let recipient = Recipient(r.array32()?);
        let finality_depth = r.u32()?;
        let observed_height = r.u64()?;
        let expiry_height = r.u64()?;
        r.finish()?;
        Ok(BridgeFact {
            version,
            source_chain,
            dest_chain,
            route_id,
            direction,
            nonce,
            source_ref,
            asset_id,
            amount,
            recipient,
            finality_depth,
            observed_height,
            expiry_height,
        })
    }

    pub fn is_zero(&self) -> bool {
        self.source_chain == 0
            && self.dest_chain == 0
            && self.route_id == 0
            && self.direction == Direction::Deposit
            && self.nonce == 0
            && self.source_ref.0 == [0u8; 32]
            && self.asset_id.0 == [0u8; 16]
            && self.amount == 0
            && self.recipient.0 == [0u8; 32]
            && self.finality_depth == 0
            && self.observed_height == 0
            && self.expiry_height == 0
    }

    pub fn attest_preimage(&self, dest_chain_id: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(ATTEST_DOMAIN);
        w.fixed(&self.encode());
        w.u64(dest_chain_id);
        w.finish()
    }

    pub fn validate(&self) -> Result<(), CodecError> {
        if self.version != FACT_VERSION {
            return Err(CodecError::BadVersion(self.version));
        }
        if self.source_chain == 0 || self.dest_chain == 0 {
            return Err(CodecError::ZeroChain);
        }
        if self.amount == 0 {
            return Err(CodecError::ZeroAmount);
        }
        if self.asset_id.0 == [0u8; 16] {
            return Err(CodecError::ZeroAsset);
        }
        if self.recipient.0 == [0u8; 32] {
            return Err(CodecError::ZeroRecipient);
        }
        if self.source_ref.0 == [0u8; 32] {
            return Err(CodecError::ZeroSourceRef);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_ID: u64 = 0x0123_4567_89AB_CDEF;

    fn sample() -> BridgeFact {
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
            expiry_height: 900_000,
        }
    }

    #[test]
    fn round_trips_and_is_fixed_length() {
        let f = sample();
        let bytes = f.encode();
        assert_eq!(bytes.len(), FACT_ENCODED_LEN);
        let back = BridgeFact::decode(&bytes).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let f = sample();
        assert_eq!(f.encode(), f.encode());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let f = sample();
        let mut bytes = f.encode();
        bytes.push(0);
        assert_eq!(BridgeFact::decode(&bytes), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn rejects_short_input() {
        let f = sample();
        let bytes = f.encode();
        assert_eq!(
            BridgeFact::decode(&bytes[..bytes.len() - 1]),
            Err(CodecError::ShortInput)
        );
    }

    #[test]
    fn an_oversized_length_prefix_errors_and_does_not_panic() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_le_bytes());
        framed.push(0x01);
        let mut r = Reader::new(&framed);
        assert_eq!(r.bytes_u32(), Err(CodecError::ShortInput));

        let mut framed16 = Vec::new();
        framed16.extend_from_slice(&u16::MAX.to_le_bytes());
        framed16.push(0x01);
        let mut r16 = Reader::new(&framed16);
        assert_eq!(r16.bytes_u16(), Err(CodecError::ShortInput));

        let mut past = Reader::new(&framed);
        let _ = past.fixed(framed.len());
        assert_eq!(past.u8(), Err(CodecError::ShortInput));
    }

    #[test]
    fn rejects_unknown_direction_tag() {
        let f = sample();
        let mut bytes = f.encode();
        bytes[13] = 9;
        assert!(matches!(
            BridgeFact::decode(&bytes),
            Err(CodecError::UnknownTag(9))
        ));
    }

    #[test]
    fn zero_fact_is_prove_nothing_and_fails_validation() {
        let z = BridgeFact {
            version: 0,
            source_chain: 0,
            dest_chain: 0,
            route_id: 0,
            direction: Direction::Deposit,
            nonce: 0,
            source_ref: SourceRef([0u8; 32]),
            asset_id: AssetId([0u8; 16]),
            amount: 0,
            recipient: Recipient([0u8; 32]),
            finality_depth: 0,
            observed_height: 0,
            expiry_height: 0,
        };
        assert!(z.is_zero());
        assert!(z.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_amount() {
        let mut f = sample();
        f.amount = 0;
        assert_eq!(f.validate(), Err(CodecError::ZeroAmount));
    }

    #[test]
    fn validate_rejects_zero_recipient() {
        let mut f = sample();
        f.recipient = Recipient([0u8; 32]);
        assert_eq!(f.validate(), Err(CodecError::ZeroRecipient));
    }

    #[test]
    fn attest_preimage_carries_the_encoded_fact() {
        let f = sample();
        let pre = f.attest_preimage(DEST_ID);
        assert_eq!(
            &pre[ATTEST_DOMAIN.len()..ATTEST_DOMAIN.len() + FACT_ENCODED_LEN],
            f.encode().as_slice()
        );
        assert!(pre.ends_with(&DEST_ID.to_le_bytes()));
    }

    #[test]
    fn attest_preimage_is_deterministic() {
        let f = sample();
        assert_eq!(f.attest_preimage(DEST_ID), f.attest_preimage(DEST_ID));
    }

    #[test]
    fn attest_preimage_leads_with_the_context_and_is_longer_than_the_fact() {
        let f = sample();
        let pre = f.attest_preimage(DEST_ID);
        assert!(pre.starts_with(ATTEST_DOMAIN));
        assert_eq!(pre.len(), ATTEST_DOMAIN.len() + FACT_ENCODED_LEN + 8);
    }

    #[test]
    fn every_semantic_field_moves_the_preimage() {
        let base = sample().attest_preimage(DEST_ID);

        let mut a = sample();
        a.source_chain = 2;
        assert_ne!(a.attest_preimage(DEST_ID), base);

        let mut b = sample();
        b.dest_chain = 9001;
        assert_ne!(b.attest_preimage(DEST_ID), base);

        let mut c = sample();
        c.route_id = 8;
        assert_ne!(c.attest_preimage(DEST_ID), base);

        let mut d = sample();
        d.direction = Direction::ExitAck;
        assert_ne!(d.attest_preimage(DEST_ID), base);

        let mut e = sample();
        e.nonce = 43;
        assert_ne!(e.attest_preimage(DEST_ID), base);

        let mut g = sample();
        g.source_ref = SourceRef([8u8; 32]);
        assert_ne!(g.attest_preimage(DEST_ID), base);

        let mut h = sample();
        h.asset_id = AssetId([4u8; 16]);
        assert_ne!(h.attest_preimage(DEST_ID), base);

        let mut i = sample();
        i.amount = 1_000_001;
        assert_ne!(i.attest_preimage(DEST_ID), base);

        let mut j = sample();
        j.recipient = Recipient([6u8; 32]);
        assert_ne!(j.attest_preimage(DEST_ID), base);

        let mut k = sample();
        k.finality_depth = 13;
        assert_ne!(k.attest_preimage(DEST_ID), base);

        let mut l = sample();
        l.observed_height = 880_001;
        assert_ne!(l.attest_preimage(DEST_ID), base);

        let mut m = sample();
        m.expiry_height = 900_001;
        assert_ne!(m.attest_preimage(DEST_ID), base);

        assert_ne!(
            sample().attest_preimage(DEST_ID ^ (1u64 << 40)),
            base,
            "the destination chain u64 moves the preimage while the fact stays fixed"
        );
    }

    fn pinned_vector_fact() -> BridgeFact {
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
            finality_depth: 6,
            observed_height: 111,
            expiry_height: 222,
        }
    }

    #[test]
    fn the_attest_preimage_matches_the_pinned_cross_chain_vector() {
        const PINNED: [u8; 173] = [
            81, 85, 65, 78, 84, 79, 86, 65, 47, 81, 45, 79, 82, 65, 67, 76, 69, 47, 65, 84, 84, 69,
            83, 84, 47, 118, 49, 1, 1, 0, 0, 0, 40, 35, 0, 0, 7, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0,
            0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
            9, 9, 9, 9, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 64, 66, 15, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 0, 0, 0, 111, 0, 0, 0, 0, 0, 0, 0, 222, 0, 0, 0, 0,
            0, 0, 0, 239, 205, 171, 137, 103, 69, 35, 1,
        ];
        let preimage = pinned_vector_fact().attest_preimage(0x0123_4567_89AB_CDEF);
        assert_eq!(preimage.len(), ATTEST_DOMAIN.len() + FACT_ENCODED_LEN + 8);
        assert_eq!(preimage.len(), 173);
        assert_eq!(preimage.as_slice(), PINNED.as_slice());
        assert!(preimage.starts_with(ATTEST_DOMAIN));
        assert_eq!(
            &preimage[ATTEST_DOMAIN.len()..ATTEST_DOMAIN.len() + FACT_ENCODED_LEN],
            pinned_vector_fact().encode().as_slice()
        );
        assert_eq!(
            &preimage[ATTEST_DOMAIN.len() + FACT_ENCODED_LEN..],
            0x0123_4567_89AB_CDEFu64.to_le_bytes()
        );
    }
}
