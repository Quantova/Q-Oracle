// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

pub struct GuardStore {
    path: PathBuf,
}

const HOLDER_FRESH: std::time::Duration = std::time::Duration::from_secs(30);

fn holder_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf().into_os_string();
    p.push(".holder");
    PathBuf::from(p)
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

fn another_process_is_live(path: &Path) -> bool {
    let holder = holder_path(path);
    let Ok(meta) = fs::metadata(&holder) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let fresh = std::time::SystemTime::now()
        .duration_since(modified)
        .map(|age| age < HOLDER_FRESH)
        .unwrap_or(false);
    if !fresh {
        return false;
    }
    let Ok(text) = fs::read_to_string(&holder) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return false;
    };
    if pid == std::process::id() {
        return false;
    }
    process_is_alive(pid)
}

fn touch_holder(path: &Path) {
    let _ = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(holder_path(path))
        .and_then(|mut f| f.write_all(std::process::id().to_string().as_bytes()));
}

impl GuardStore {
    pub fn new<P: Into<PathBuf>>(path: P) -> GuardStore {
        GuardStore { path: path.into() }
    }

    pub fn claim(&self) -> io::Result<()> {
        if another_process_is_live(&self.path) {
            return Err(io::Error::new(
                ErrorKind::AddrInUse,
                format!(
                    "another live process holds the guard snapshot at {}; two oracles sharing one \
                     snapshot would each mint on their own replay set and overwrite the other",
                    self.path.display()
                ),
            ));
        }
        touch_holder(&self.path);
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
        touch_holder(&self.path);
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
