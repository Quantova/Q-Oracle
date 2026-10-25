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

pub fn state_key_file_problem(state_file: &std::path::Path) -> Option<String> {
    let Ok(path) = std::env::var(STATE_KEY_FILE_ENV) else {
        return Some(format!(
            "{STATE_KEY_FILE_ENV} is not set, so the state tags would be an unkeyed hash anyone can recompute"
        ));
    };
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) => return Some(format!("the state key file {path} cannot be read: {e}")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            return Some(format!(
                "the state key file {path} can be read by group or others, it must be mode 0600"
            ));
        }
        let dir = state_file
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let owner = match std::fs::metadata(dir) {
            Ok(dir_meta) => dir_meta.uid(),
            Err(e) => {
                return Some(format!(
                    "the state directory {} cannot be read: {e}",
                    dir.display()
                ))
            }
        };
        if meta.uid() != owner {
            return Some(format!(
                "the state key file {path} is not owned by the owner of the state directory {}",
                dir.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (&meta, state_file);
    if !state_key_configured() {
        return Some(format!(
            "the state key file {path} holds fewer than {MIN_STATE_KEY_BYTES} bytes"
        ));
    }
    None
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
