//! Maildir delivery — the /intake leg's only filesystem effect.
//!
//! A submitted transaction is written to `tmp/`, fsync'd, then
//! atomically renamed into `new/` where ANTIE picks it up. The filename
//! is server-generated: the webclient cannot influence the path TOT
//! writes (AXIOM_DESIGN_TOT.md §5).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A handle to the one validator inbox TOT is permitted to write.
pub struct Inbox {
    tmp: PathBuf,
    new: PathBuf,
}

impl Inbox {
    /// Resolve the inbox maildir and ensure `tmp/`, `new/`, `cur/` exist.
    /// Called at startup, before the sandbox seals the filesystem.
    pub fn open(inbox_dir: &Path) -> io::Result<Inbox> {
        let tmp = inbox_dir.join("tmp");
        let new = inbox_dir.join("new");
        let cur = inbox_dir.join("cur");
        for d in [&tmp, &new, &cur] {
            fs::create_dir_all(d)?;
        }
        Ok(Inbox { tmp, new })
    }

    /// Deliver one submission: write to `tmp/`, fsync, atomically rename
    /// into `new/`, then fsync `new/` so the rename itself is durable.
    pub fn deliver(&self, bytes: &[u8]) -> io::Result<()> {
        let name = unique_name();
        let tmp_path = self.tmp.join(&name);
        let new_path = self.new.join(&name);

        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);

        if let Err(e) = fs::rename(&tmp_path, &new_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        fs::File::open(&self.new)?.sync_all()?;
        Ok(())
    }
}

/// A server-generated, collision-free maildir filename. The `.tot`
/// suffix marks the message's origin.
fn unique_name() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!(
        "{}.{}.M{}P{}.tot",
        now.as_secs(),
        now.subsec_nanos(),
        seq,
        std::process::id()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliver_writes_to_new_with_a_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::open(dir.path()).unwrap();
        inbox.deliver(b"hello-axiom").unwrap();

        let new_entries: Vec<_> = fs::read_dir(dir.path().join("new"))
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        assert_eq!(new_entries.len(), 1, "exactly one message in new/");
        assert_eq!(fs::read(new_entries[0].path()).unwrap(), b"hello-axiom");

        // tmp/ is empty — the write was atomically renamed out.
        assert_eq!(fs::read_dir(dir.path().join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn deliver_generates_distinct_names() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = Inbox::open(dir.path()).unwrap();
        inbox.deliver(b"a").unwrap();
        inbox.deliver(b"b").unwrap();
        assert_eq!(fs::read_dir(dir.path().join("new")).unwrap().count(), 2);
    }
}
