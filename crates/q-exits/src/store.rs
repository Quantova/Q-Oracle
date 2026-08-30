// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

pub struct ReplayStore {
    path: PathBuf,
}

impl ReplayStore {
    pub fn new<P: Into<PathBuf>>(path: P) -> ReplayStore {
        ReplayStore { path: path.into() }
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

    pub fn append(&self, bytes: &[u8]) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
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
        path.push(format!(
            "q-oracle-replay-{tag}-{}-{nanos}.led",
            std::process::id()
        ));
        path
    }

    #[test]
    fn a_saved_ledger_loads_back_byte_for_byte() {
        let path = temp_path("roundtrip");
        let store = ReplayStore::new(path.clone());
        assert!(store.load().unwrap().is_none());
        store.save(&[9, 8, 7, 6]).expect("save");
        assert_eq!(store.load().unwrap().as_deref(), Some(&[9, 8, 7, 6][..]));
        let mut temp = path.clone().into_os_string();
        temp.push(".tmp");
        assert!(!Path::new(&temp).exists());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn a_save_into_a_missing_directory_fails() {
        let store = ReplayStore::new("/no-such-q-oracle-exit-dir/replay.led");
        assert!(store.save(&[1, 2, 3]).is_err());
    }
}
