// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::OnceLock;

use zeroize::Zeroizing;

pub const STATE_KEY_FILE_ENV: &str = "QORACLE_STATE_KEY_FILE";

const MIN_STATE_KEY_BYTES: usize = 32;

fn state_key() -> Option<&'static [u8]> {
    static KEY: OnceLock<Option<Zeroizing<Vec<u8>>>> = OnceLock::new();
    KEY.get_or_init(|| {
        let path = std::env::var(STATE_KEY_FILE_ENV).ok()?;
        let key = Zeroizing::new(std::fs::read(path).ok()?);
        (key.len() >= MIN_STATE_KEY_BYTES).then_some(key)
    })
    .as_ref()
    .map(|key| key.as_slice())
}

pub fn state_key_configured() -> bool {
    state_key().is_some()
}

pub fn state_tag(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let key = state_key().unwrap_or(&[]);
    let mut input = Zeroizing::new(Vec::with_capacity(
        24 + domain.len() + key.len() + body.len(),
    ));
    input.extend_from_slice(b"QORACLE/STATE-TAG/v1");
    input.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    input.extend_from_slice(domain);
    input.extend_from_slice(&(key.len() as u32).to_le_bytes());
    input.extend_from_slice(key);
    input.extend_from_slice(body);
    qtv_crypto::sha3::sha3_256(&input)
}
