//! ANTIE → UNCLE tee for the witness-delivery carrier path.
//!
//! When ANTIE writes a response that carries a txid (witness signature
//! or cheque-for-receiver), it ALSO drops a verbatim copy of the
//! outbound email bytes into a directory UNCLE watches. UNCLE's
//! `witness_observer` (in the axiom-uncle crate) reads each file,
//! looks up the txid in its in-flight `SubmitSend` registry, and
//! ships the bytes back to the awaiting client on the held TCP
//! connection.
//!
//! This is a **tee**, not a replacement: ANTIE still calls
//! `self.sender.send(...)` for SMTP / maildir delivery, so non-UNCLE
//! clients (regular wallets receiving via SMTP) are unaffected. When
//! `OutboundConfig::uncle` is `None`, this module is never invoked.
//!
//! License note: ANTIE is GPL, UNCLE is Apache 2.0. This module
//! lives in ANTIE and writes plain bytes to disk — no import of any
//! UNCLE type. UNCLE reads the directory without importing any
//! ANTIE type. The boundary stays clean in both directions.

use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, warn};

use crate::error::AntieError;

/// Handle to the on-disk sink. Cheap to clone (Arc-wrapped path).
#[derive(Debug, Clone)]
pub struct UncleSink {
    outbox_path: PathBuf,
}

impl UncleSink {
    /// Construct + ensure the outbox directory exists. Called once at
    /// gateway startup; subsequent `tee` calls are non-fallible aside
    /// from the file I/O itself.
    pub async fn new(outbox_path: PathBuf) -> Result<Self, AntieError> {
        fs::create_dir_all(&outbox_path).await?;
        Ok(Self { outbox_path })
    }

    /// Drop `bytes` (the verbatim email-formatted response) at
    /// `<outbox>/<txid_hex>.cbor` via atomic tmp+rename so a
    /// concurrent reader never observes a partial file.
    ///
    /// Errors are logged but NOT propagated to the caller — the
    /// primary SMTP send must not fail because a tee target was
    /// unavailable (the tee is best-effort by design). Returns the
    /// final destination path on success for callers that want to
    /// log it.
    pub async fn tee(&self, txid: &[u8; 32], bytes: &[u8]) -> Option<PathBuf> {
        let filename = format!("{}.cbor", hex::encode(txid));
        let dest = self.outbox_path.join(&filename);
        let tmp = self.outbox_path.join(format!(
            ".uncle_tee.tmp.{}.{}",
            std::process::id(),
            // Nanos-since-epoch makes the tmp name unique even across
            // simultaneous tees from the same pid.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));

        match fs::write(&tmp, bytes).await {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    "uncle_sink: write {}: {e} — primary SMTP still proceeds",
                    tmp.display()
                );
                return None;
            }
        }
        match fs::rename(&tmp, &dest).await {
            Ok(()) => {
                debug!(
                    "uncle_sink: teed {} bytes to {}",
                    bytes.len(),
                    dest.display()
                );
                Some(dest)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp).await;
                warn!(
                    "uncle_sink: rename {} -> {}: {e} — primary SMTP still proceeds",
                    tmp.display(),
                    dest.display()
                );
                None
            }
        }
    }

    /// Directory path — used by tests and by gateway logging at
    /// startup. Not the canonical I/O path.
    pub fn outbox_path(&self) -> &Path {
        &self.outbox_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn tee_writes_file_with_txid_hex_filename() {
        let dir = tempdir().unwrap();
        let sink = UncleSink::new(dir.path().join("witness_outbox"))
            .await
            .unwrap();

        let txid = [0xABu8; 32];
        let bytes = b"raw email bytes here";
        let dest = sink.tee(&txid, bytes).await.expect("tee succeeded");

        // Filename matches hex(txid) + .cbor.
        assert_eq!(
            dest.file_name().unwrap().to_string_lossy(),
            format!("{}.cbor", "ab".repeat(32))
        );

        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk, bytes);
    }

    #[tokio::test]
    async fn tee_is_atomic_no_partial_file_visible() {
        // Standard rename(2) atomicity test: write a large blob,
        // assert no `.uncle_tee.tmp.` leftovers in the dir.
        let dir = tempdir().unwrap();
        let sink = UncleSink::new(dir.path().to_path_buf()).await.unwrap();

        let blob = vec![0xCD; 1_000_000];
        sink.tee(&[0u8; 32], &blob).await.expect("tee succeeded");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".uncle_tee.tmp.")
            })
            .collect();
        assert!(leftovers.is_empty(), "tmp file must not survive rename");
    }

    #[tokio::test]
    async fn tee_overwrites_existing_file() {
        let dir = tempdir().unwrap();
        let sink = UncleSink::new(dir.path().to_path_buf()).await.unwrap();
        let txid = [0x77u8; 32];

        sink.tee(&txid, b"first").await.unwrap();
        sink.tee(&txid, b"second").await.unwrap();

        let on_disk = std::fs::read(dir.path().join(format!("{}.cbor", "77".repeat(32))))
            .unwrap();
        assert_eq!(on_disk, b"second");
    }

    #[tokio::test]
    async fn tee_returns_none_on_io_error_does_not_panic() {
        // Construct a sink pointing at a path that DOES exist
        // (otherwise `new` errors), then delete the dir so `tee`
        // fails. Asserts the failure path doesn't propagate.
        let dir = tempdir().unwrap();
        let sink = UncleSink::new(dir.path().to_path_buf()).await.unwrap();
        // Remove the directory under the sink's feet.
        std::fs::remove_dir(dir.path()).unwrap();
        let out = sink.tee(&[0u8; 32], b"x").await;
        assert!(out.is_none());
    }
}
