// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File, TryLockError};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub struct GuardStore {
    path: PathBuf,
    lock: OnceLock<File>,
}

fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf().into_os_string();
    p.push(".lock");
    PathBuf::from(p)
}

impl GuardStore {
    pub fn new<P: Into<PathBuf>>(path: P) -> GuardStore {
        GuardStore {
            path: path.into(),
            lock: OnceLock::new(),
        }
    }

    pub fn claim(&self) -> io::Result<()> {
        if self.lock.get().is_some() {
            return Ok(());
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path(&self.path))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!(
                        "another live process holds the guard snapshot at {}; two oracles sharing \
                         one snapshot would each mint on their own replay set and overwrite the other",
                        self.path.display()
                    ),
                ))
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }
        let _ = self.lock.set(file);
        Ok(())
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
                File::open(parent)?.sync_all()?;
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
        path.push(format!(
            "q-oracle-guard-{tag}-{}-{nanos}.snap",
            std::process::id()
        ));
        path
    }

    #[test]
    fn a_held_snapshot_is_refused_however_long_its_holder_stays_idle() {
        let path = temp_path("claim");
        let holder = GuardStore::new(path.clone());
        holder.claim().expect("a free snapshot is claimed");
        holder.save(&[1, 2, 3]).expect("save");
        holder
            .claim()
            .expect("the holder re-claiming its own snapshot is a no-op");

        let long_ago = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
        for idle in [path.clone(), lock_path(&path)] {
            File::options()
                .write(true)
                .open(&idle)
                .and_then(|file| file.set_modified(long_ago))
                .expect("the holder looks idle for decades");
        }
        let refused = GuardStore::new(path.clone()).claim();
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(ErrorKind::AddrInUse),
            "an idle but live holder keeps its lock, so two oracles never share one replay set"
        );

        drop(holder);
        let successor = GuardStore::new(path.clone());
        successor
            .claim()
            .expect("the lock dies with its holder, so the snapshot is claimable again");
        drop(successor);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path(&path));
    }

    #[test]
    fn a_saved_snapshot_loads_back_byte_for_byte() {
        let path = temp_path("roundtrip");
        let store = GuardStore::new(path.clone());
        assert!(
            store.load().unwrap().is_none(),
            "an absent snapshot loads as none"
        );
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
