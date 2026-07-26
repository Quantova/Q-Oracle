// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

pub struct GuardStore {
    path: PathBuf,
}

impl GuardStore {
    pub fn new<P: Into<PathBuf>>(path: P) -> GuardStore {
        GuardStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> io::Result<Option<Vec<u8>>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, encoded: &[u8]) -> io::Result<()> {
        let mut temp = self.path.clone().into_os_string();
        temp.push(".tmp");
        let temp = PathBuf::from(temp);
        {
            let mut file = File::create(&temp)?;
            file.write_all(encoded)?;
            file.sync_all()?;
        }
        fs::rename(&temp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("q-oracle-guard-{tag}-{}-{nanos}.snap", std::process::id()));
        path
    }

    #[test]
    fn a_saved_snapshot_loads_back_byte_for_byte() {
        let path = temp_path("roundtrip");
        let store = GuardStore::new(path.clone());
        assert!(store.load().unwrap().is_none(), "an absent snapshot loads as none");
        store.save(&[1, 2, 3, 4, 5]).expect("save");
        assert_eq!(store.load().unwrap().as_deref(), Some(&[1, 2, 3, 4, 5][..]));
        let mut temp = path.clone().into_os_string();
        temp.push(".tmp");
        assert!(
            !Path::new(&temp).exists(),
            "the temp file is renamed away, not left behind"
        );
        fs::remove_file(&path).ok();
    }
}
