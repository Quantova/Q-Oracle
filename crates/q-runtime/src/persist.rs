// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::{self, File, TryLockError};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use q_codec::{Reader, Writer};
use q_exits::state_mac::state_tag;
use q_gateway::{AdminRecord, Gateway};

const AUDIT_MAGIC: &[u8; 4] = b"QADM";
const AUDIT_VERSION: u8 = 1;
const AUDIT_HEADER_LEN: usize = 5;

struct AuditLog {
    seq: u64,
    head: [u8; 32],
    len: u64,
}

pub struct GuardStore {
    path: PathBuf,
    lock: OnceLock<File>,
    audit: Mutex<Option<AuditLog>>,
}

fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf().into_os_string();
    p.push(".lock");
    PathBuf::from(p)
}

fn audit_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf().into_os_string();
    p.push(".audit");
    PathBuf::from(p)
}

fn audit_entry(seq: u64, prev: &[u8; 32], record: &AdminRecord) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::new();
    w.u64(seq);
    w.fixed(prev);
    w.bytes_u32(&record.action());
    w.u32(record.signatures.len() as u32);
    for sig in &record.signatures {
        w.u32(sig.operator_id);
        w.bytes_u32(&sig.signature);
    }
    let body = w.finish();
    let hash = state_tag(b"admin-audit", &body);
    let mut frame = Writer::new();
    frame.bytes_u32(&body);
    frame.fixed(&hash);
    (frame.finish(), hash)
}

fn verify_audit(bytes: &[u8], anchor: (u64, [u8; 32])) -> Result<(u64, [u8; 32]), String> {
    let (anchor_seq, anchor_head) = anchor;
    if bytes.is_empty() {
        if anchor_seq != 0 {
            return Err(format!(
                "is missing or empty but the guard snapshot anchors {anchor_seq} entries"
            ));
        }
        return Ok((0, [0u8; 32]));
    }
    if bytes.len() < AUDIT_HEADER_LEN || &bytes[..4] != AUDIT_MAGIC || bytes[4] != AUDIT_VERSION {
        return Err("has an unknown header".to_string());
    }
    let mut r = Reader::new(&bytes[AUDIT_HEADER_LEN..]);
    let mut seq = 0u64;
    let mut head = [0u8; 32];
    let mut anchored = anchor_seq == 0;
    while r.remaining() > 0 {
        let next = seq + 1;
        let torn = |_| format!("is torn inside entry {next}");
        let body = r.bytes_u32().map_err(torn)?;
        let hash = r.array32().map_err(torn)?;
        if state_tag(b"admin-audit", body) != hash {
            return Err(format!("entry {next} does not match its hash"));
        }
        let mut b = Reader::new(body);
        let malformed = |_| format!("entry {next} is malformed");
        let entry_seq = b.u64().map_err(malformed)?;
        let prev = b.array32().map_err(malformed)?;
        if entry_seq != next || prev != head {
            return Err(format!("entry {next} breaks the hash chain"));
        }
        b.bytes_u32().map_err(malformed)?;
        for _ in 0..b.u32().map_err(malformed)? {
            b.u32().map_err(malformed)?;
            b.bytes_u32().map_err(malformed)?;
        }
        b.finish().map_err(malformed)?;
        seq = next;
        head = hash;
        if seq == anchor_seq {
            if head != anchor_head {
                return Err(format!(
                    "entry {seq} differs from the one the guard snapshot anchors"
                ));
            }
            anchored = true;
        }
    }
    if !anchored {
        return Err(format!(
            "ends at entry {seq} but the guard snapshot anchors {anchor_seq} entries, so it was truncated"
        ));
    }
    Ok((seq, head))
}

impl GuardStore {
    pub fn new<P: Into<PathBuf>>(path: P) -> GuardStore {
        GuardStore {
            path: path.into(),
            lock: OnceLock::new(),
            audit: Mutex::new(None),
        }
    }

    pub fn audit_path(&self) -> PathBuf {
        audit_path(&self.path)
    }

    fn load_audit(&self, anchor: (u64, [u8; 32])) -> io::Result<AuditLog> {
        let path = self.audit_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let (seq, head) = verify_audit(&bytes, anchor).map_err(|why| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "the admin audit log at {} {why}; refusing to start on an altered audit trail",
                    path.display()
                ),
            )
        })?;
        Ok(AuditLog {
            seq,
            head,
            len: bytes.len() as u64,
        })
    }

    pub fn open_audit(&self, anchor: (u64, [u8; 32])) -> io::Result<(u64, [u8; 32])> {
        let log = self.load_audit(anchor)?;
        let head = (log.seq, log.head);
        *self.audit.lock().unwrap_or_else(|e| e.into_inner()) = Some(log);
        Ok(head)
    }

    pub fn record_admin(&self, gateway: &mut Gateway) -> io::Result<()> {
        if gateway.pending_admin_records().is_empty() {
            return Ok(());
        }
        let mut audit = self.audit.lock().unwrap_or_else(|e| e.into_inner());
        if audit.is_none() {
            *audit = Some(self.load_audit(gateway.audit_anchor())?);
        }
        let Some(log) = audit.as_mut() else {
            return Err(io::Error::other("the admin audit log is not open"));
        };
        let mut out = Vec::new();
        if log.len == 0 {
            out.extend_from_slice(AUDIT_MAGIC);
            out.push(AUDIT_VERSION);
        }
        let (mut seq, mut head) = (log.seq, log.head);
        for record in gateway.pending_admin_records() {
            seq += 1;
            let (frame, hash) = audit_entry(seq, &head, record);
            out.extend_from_slice(&frame);
            head = hash;
        }
        let path = self.audit_path();
        let mut opts = fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;
        if file.metadata()?.len() != log.len {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "the admin audit log at {} changed under the running oracle",
                    path.display()
                ),
            ));
        }
        if let Err(e) = file.write_all(&out).and_then(|()| file.sync_all()) {
            let _ = file.set_len(log.len);
            return Err(e);
        }
        let created = log.len == 0;
        log.len += out.len() as u64;
        log.seq = seq;
        log.head = head;
        if created {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    File::open(parent)?.sync_all()?;
                }
            }
        }
        gateway.settle_admin_records(seq, head);
        Ok(())
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
        let mut bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if bytes.len() < 32 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "the guard snapshot carries no state tag",
            ));
        }
        let tag = bytes.split_off(bytes.len() - 32);
        if state_tag(b"guard-snapshot", &bytes)[..] != tag[..] {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "the guard snapshot does not match its state tag",
            ));
        }
        Ok(Some(bytes))
    }

    pub fn save(&self, encoded: &[u8]) -> io::Result<()> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut temp = self.path.clone().into_os_string();
        temp.push(format!(".tmp.{}.{nonce}", std::process::id()));
        let temp = PathBuf::from(temp);
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&temp)?;
            file.write_all(encoded)?;
            file.write_all(&state_tag(b"guard-snapshot", encoded))?;
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
