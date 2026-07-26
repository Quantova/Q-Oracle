// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rlp {
    Bytes(Vec<u8>),
    List(Vec<Rlp>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpError {
    Empty,
    Truncated,
    LeadingZeroLength,
    Trailing,
    OversizeLength,
}

impl Rlp {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Rlp::Bytes(b) => Some(b),
            Rlp::List(_) => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Rlp]> {
        match self {
            Rlp::List(items) => Some(items),
            Rlp::Bytes(_) => None,
        }
    }
}

fn encode_length(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let len_bytes = &be[start..];
        out.push(offset + 55 + len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
}

pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        encode_length(bytes.len(), 0x80, &mut out);
        out.extend_from_slice(bytes);
    }
    out
}

pub fn encode_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return encode_bytes(&[]);
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap();
    encode_bytes(&be[start..])
}

pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    let mut out = Vec::new();
    encode_length(body.len(), 0xc0, &mut out);
    out.extend_from_slice(&body);
    out
}

fn read_length(bytes: &[u8], of_len: usize) -> Result<usize, RlpError> {
    if of_len == 0 || of_len > 8 || of_len > bytes.len() {
        return Err(RlpError::Truncated);
    }
    if bytes[0] == 0 {
        return Err(RlpError::LeadingZeroLength);
    }
    let mut value = 0usize;
    for &b in &bytes[0..of_len] {
        value = value.checked_shl(8).ok_or(RlpError::OversizeLength)? | b as usize;
    }
    Ok(value)
}

fn decode_item(bytes: &[u8]) -> Result<(Rlp, usize), RlpError> {
    if bytes.is_empty() {
        return Err(RlpError::Empty);
    }
    let prefix = bytes[0];
    if prefix < 0x80 {
        Ok((Rlp::Bytes(vec![prefix]), 1))
    } else if prefix < 0xb8 {
        let len = (prefix - 0x80) as usize;
        let end = 1 + len;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        Ok((Rlp::Bytes(bytes[1..end].to_vec()), end))
    } else if prefix < 0xc0 {
        let of_len = (prefix - 0xb7) as usize;
        let len = read_length(&bytes[1..], of_len)?;
        let start = 1 + of_len;
        let end = start.checked_add(len).ok_or(RlpError::OversizeLength)?;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        Ok((Rlp::Bytes(bytes[start..end].to_vec()), end))
    } else if prefix < 0xf8 {
        let len = (prefix - 0xc0) as usize;
        let start = 1;
        let end = start + len;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        let items = decode_list_body(&bytes[start..end])?;
        Ok((Rlp::List(items), end))
    } else {
        let of_len = (prefix - 0xf7) as usize;
        let len = read_length(&bytes[1..], of_len)?;
        let start = 1 + of_len;
        let end = start.checked_add(len).ok_or(RlpError::OversizeLength)?;
        if end > bytes.len() {
            return Err(RlpError::Truncated);
        }
        let items = decode_list_body(&bytes[start..end])?;
        Ok((Rlp::List(items), end))
    }
}

fn decode_list_body(mut bytes: &[u8]) -> Result<Vec<Rlp>, RlpError> {
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let (item, used) = decode_item(bytes)?;
        items.push(item);
        bytes = &bytes[used..];
    }
    Ok(items)
}

pub fn decode(bytes: &[u8]) -> Result<Rlp, RlpError> {
    let (item, used) = decode_item(bytes)?;
    if used != bytes.len() {
        return Err(RlpError::Trailing);
    }
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn a_short_string_encodes_with_the_known_prefix() {
        assert_eq!(to_hex(&encode_bytes(b"dog")), "83646f67");
    }

    #[test]
    fn an_empty_string_is_a_single_byte() {
        assert_eq!(to_hex(&encode_bytes(b"")), "80");
    }

    #[test]
    fn a_single_low_byte_is_itself() {
        assert_eq!(to_hex(&encode_bytes(&[0x0f])), "0f");
    }

    #[test]
    fn a_two_element_list_matches_the_known_vector() {
        let cat = encode_bytes(b"cat");
        let dog = encode_bytes(b"dog");
        assert_eq!(to_hex(&encode_list(&[cat, dog])), "c88363617483646f67");
    }

    #[test]
    fn the_index_zero_key_encodes_to_the_empty_string_byte() {
        assert_eq!(to_hex(&encode_uint(0)), "80");
        assert_eq!(to_hex(&encode_uint(1)), "01");
        assert_eq!(to_hex(&encode_uint(127)), "7f");
        assert_eq!(to_hex(&encode_uint(128)), "8180");
        assert_eq!(to_hex(&encode_uint(1024)), "820400");
    }

    #[test]
    fn a_long_string_uses_a_length_prefix() {
        let data = vec![0x61u8; 60];
        let encoded = encode_bytes(&data);
        assert_eq!(encoded[0], 0xb8);
        assert_eq!(encoded[1], 60);
        assert_eq!(decode(&encoded).unwrap(), Rlp::Bytes(data));
    }

    #[test]
    fn decode_round_trips_a_nested_list() {
        let inner = encode_list(&[encode_bytes(b"a"), encode_bytes(b"bb")]);
        let outer = encode_list(&[inner, encode_bytes(&[0xff])]);
        let decoded = decode(&outer).unwrap();
        let items = decoded.as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_list().unwrap().len(), 2);
        assert_eq!(items[1].as_bytes().unwrap(), &[0xff]);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = encode_bytes(b"dog");
        encoded.push(0x00);
        assert_eq!(decode(&encoded), Err(RlpError::Trailing));
    }

    #[test]
    fn a_truncated_string_is_rejected() {
        assert_eq!(decode(&[0x83, 0x64, 0x6f]), Err(RlpError::Truncated));
    }
}
