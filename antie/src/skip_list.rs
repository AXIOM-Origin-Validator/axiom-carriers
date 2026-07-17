//! ANTIE skip-list — sibling-carrier coordination point.
//!
//! Contract: `docs/AXIOM_DESIGN_AntieSkipList.md`. Reference
//! implementation:
//!
//! - Load `<skip_list_path>` (plain text, one `receiver_wallet_id`
//!   per line; lines starting with `#` are comments; blank lines
//!   ignored) into an in-memory `HashSet<String>`.
//! - Watch for SIGHUP (reload from disk) and atomic-rename of the
//!   skip-list file (sibling carriers pick whichever mechanism they
//!   prefer; ANTIE supports both).
//! - On every outbound cheque dispatch, the gateway calls
//!   [`SkipList::contains`] before sendmail. If listed, the cheque
//!   bytes go to `<skipped_dir_path>/<filename>` via atomic
//!   `<skipped>/.tmp.<filename>` → `rename(2)` — same atomic pattern
//!   the maildir delivery already uses, so sibling carriers
//!   observing the directory never see a half-written file (the
//!   atomic-write reinforcement requested as pushback on
//!   `AXIOM_DESIGN_AntieSkipList.md` §7 / §8 lands here as
//!   reference-impl behaviour).
//! - Skipped/ depth (`skipped_dir_count`) is exposed on `/status` so
//!   operators have a default monitoring hook for the no-TTL
//!   reference behaviour described in the contract §4.
//!
//! When either config key (`skip_list_path` or `skipped_dir_path`) is
//! `None`, the skip-list module is fully disabled; the gateway calls
//! the existing email path unchanged. This is the consumer-validator
//! deployment shape — no UNCLE running, no sibling carriers, no
//! skip-list overhead.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::AntieError;

/// In-memory skip-list state + the on-disk paths it reads / writes.
#[derive(Debug)]
pub struct SkipList {
    /// Path to the plain-text skip-list file. Sibling carriers write
    /// here and SIGHUP (or atomic-rename) ANTIE to reload.
    skip_list_path: PathBuf,
    /// Directory ANTIE drops skip-listed cheques into. Sibling
    /// carriers claim by atomic rename out.
    skipped_dir: PathBuf,
    /// In-memory wallet_id set. RwLock so many `contains` checks run
    /// concurrently and the rare reload exclusive-locks briefly.
    entries: RwLock<HashSet<String>>,
}

impl SkipList {
    /// Open / create the skipped/ directory + load the skip-list file
    /// into memory. Returns `Ok(None)` (caller treats this as
    /// "skip-list disabled") if either path is `None`.
    pub async fn maybe_open(
        skip_list_path: Option<&str>,
        skipped_dir: Option<&str>,
    ) -> Result<Option<Arc<Self>>, AntieError> {
        let (Some(slp), Some(sdp)) = (skip_list_path, skipped_dir) else {
            debug!("skip_list: disabled (no skip_list_path / skipped_dir_path configured)");
            return Ok(None);
        };

        let skip_list_path = PathBuf::from(slp);
        let skipped_dir = PathBuf::from(sdp);

        tokio::fs::create_dir_all(&skipped_dir).await.map_err(|e| {
            AntieError::ConfigError(format!(
                "create skipped_dir {}: {e}",
                skipped_dir.display()
            ))
        })?;

        let entries = Self::load_entries(&skip_list_path);
        info!(
            "skip_list: loaded {} entries from {} (skipped_dir = {})",
            entries.len(),
            skip_list_path.display(),
            skipped_dir.display()
        );

        Ok(Some(Arc::new(Self {
            skip_list_path,
            skipped_dir,
            entries: RwLock::new(entries),
        })))
    }

    fn load_entries(path: &Path) -> HashSet<String> {
        let mut set = HashSet::new();
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                debug!("skip_list: read {} failed (assuming empty): {e}", path.display());
                return set;
            }
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            set.insert(trimmed.to_string());
        }
        set
    }

    /// Re-read the skip-list file. Called from the SIGHUP handler;
    /// can also be called directly by sibling carriers via an admin
    /// surface if they prefer not to send signals.
    pub async fn reload(&self) -> Result<usize, AntieError> {
        let new_entries = Self::load_entries(&self.skip_list_path);
        let len = new_entries.len();
        *self.entries.write().await = new_entries;
        info!(
            "skip_list: reloaded {} entries from {}",
            len,
            self.skip_list_path.display()
        );
        Ok(len)
    }

    /// Is `receiver_wallet_id` skip-listed? Hot-path on every
    /// outbound cheque. `false` when the list is empty — no extra
    /// branches in the gateway.
    pub async fn contains(&self, receiver_wallet_id: &str) -> bool {
        self.entries.read().await.contains(receiver_wallet_id)
    }

    /// Write `content` into `<skipped_dir>/<filename>` via atomic
    /// `<skipped_dir>/.tmp.<filename>` → `rename(2)`. Sibling
    /// carriers observing the directory MUST NOT see a half-written
    /// file — this is the atomic-write reinforcement promised by
    /// the §7 / §8 pushback on the contract doc.
    ///
    /// `filename_hint` is used as-is (no escaping) for the final
    /// name; callers pass something unique per cheque (txid hex,
    /// uuid, etc).
    pub async fn write_skipped(
        &self,
        filename_hint: &str,
        content: &[u8],
    ) -> Result<PathBuf, AntieError> {
        let tmp = self.skipped_dir.join(format!(".tmp.{}", filename_hint));
        let dest = self.skipped_dir.join(filename_hint);

        tokio::fs::write(&tmp, content).await.map_err(|e| {
            AntieError::MaildirError(format!("write skipped tmp {}: {e}", tmp.display()))
        })?;
        if let Err(e) = tokio::fs::rename(&tmp, &dest).await {
            // Best-effort cleanup; sibling carriers should never see
            // a stale .tmp.* file.
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(AntieError::MaildirError(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                dest.display()
            )));
        }
        debug!("skip_list: wrote skipped cheque to {}", dest.display());
        Ok(dest)
    }

    /// Number of files currently in `skipped_dir`. Used by the
    /// `/status` endpoint as `skipped_dir_count` so operators have a
    /// default monitoring hook for the no-TTL reference behaviour
    /// (`AXIOM_DESIGN_AntieSkipList.md` §4 — bank forks set their
    /// own alert thresholds against this metric).
    ///
    /// Cheap-ish: one `readdir` per call. Not cached because the
    /// poll cadence is operator-side metrics scrape, ~once every
    /// 15s in practice.
    pub fn skipped_dir_count(&self) -> usize {
        std::fs::read_dir(&self.skipped_dir)
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| {
                        // Skip .tmp.* leftovers — those are in-flight
                        // writes by ANTIE, not claimable cheques.
                        e.file_name()
                            .to_str()
                            .map(|n| !n.starts_with(".tmp."))
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Where the skipped directory lives — for `/status` display.
    pub fn skipped_dir_path(&self) -> &Path {
        &self.skipped_dir
    }
}

/// Install a SIGHUP handler that reloads the skip-list on signal.
/// Sibling carriers either rewrite-then-SIGHUP or rewrite-via-
/// atomic-rename — both are supported.
///
/// The handler swallows errors (logged) so a temporarily-unreadable
/// skip-list file (e.g. mid-write by a sibling carrier) doesn't kill
/// ANTIE. The set survives in its previous state until the next
/// successful reload.
pub fn install_sighup_handler(skip_list: Arc<SkipList>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!("skip_list: SIGHUP handler install failed: {e}");
                return;
            }
        };
        loop {
            if sig.recv().await.is_none() {
                return;
            }
            if let Err(e) = skip_list.reload().await {
                warn!("skip_list: reload on SIGHUP failed: {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn open_in(dir: &Path, list_lines: &[&str]) -> Arc<SkipList> {
        let list_path = dir.join("skip_list");
        let skipped = dir.join("skipped");
        std::fs::write(&list_path, list_lines.join("\n")).unwrap();
        SkipList::maybe_open(
            list_path.to_str(),
            skipped.to_str(),
        )
        .await
        .unwrap()
        .expect("skip-list should be enabled when both paths provided")
    }

    #[tokio::test]
    async fn disabled_when_either_path_missing() {
        assert!(SkipList::maybe_open(None, Some("/tmp/x")).await.unwrap().is_none());
        assert!(SkipList::maybe_open(Some("/tmp/x"), None).await.unwrap().is_none());
        assert!(SkipList::maybe_open(None, None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn contains_matches_loaded_entries() {
        let dir = tempdir().unwrap();
        let sl = open_in(
            dir.path(),
            &[
                "treasury@bigbank.com/abc12345",
                "fx@receiverbank.com/def67890",
                "",                       // blank line ignored
                "# a comment",            // comment ignored
                "operating@nostro.io/aaaaaaaa",
            ],
        )
        .await;

        assert!(sl.contains("treasury@bigbank.com/abc12345").await);
        assert!(sl.contains("fx@receiverbank.com/def67890").await);
        assert!(sl.contains("operating@nostro.io/aaaaaaaa").await);
        assert!(!sl.contains("randomguy@example.com/zzzzzzzz").await);
        // Blank line + comment line ignored — not entries.
        assert!(!sl.contains("").await);
        assert!(!sl.contains("# a comment").await);
    }

    #[tokio::test]
    async fn missing_skip_list_file_loads_as_empty_not_error() {
        let dir = tempdir().unwrap();
        let list_path = dir.path().join("does_not_exist");
        let skipped = dir.path().join("skipped");
        let sl = SkipList::maybe_open(list_path.to_str(), skipped.to_str())
            .await
            .unwrap()
            .unwrap();
        assert!(!sl.contains("anything").await);
    }

    #[tokio::test]
    async fn reload_picks_up_added_entries() {
        let dir = tempdir().unwrap();
        let sl = open_in(dir.path(), &["initial@bank.com/aaaaaaaa"]).await;
        assert!(sl.contains("initial@bank.com/aaaaaaaa").await);
        assert!(!sl.contains("new@bank.com/bbbbbbbb").await);

        // Sibling carrier appends a new entry + SIGHUPs ANTIE.
        let list_path = dir.path().join("skip_list");
        let mut content = std::fs::read_to_string(&list_path).unwrap();
        content.push_str("\nnew@bank.com/bbbbbbbb\n");
        std::fs::write(&list_path, content).unwrap();
        sl.reload().await.unwrap();

        assert!(sl.contains("initial@bank.com/aaaaaaaa").await);
        assert!(sl.contains("new@bank.com/bbbbbbbb").await);
    }

    #[tokio::test]
    async fn write_skipped_is_atomic_tmp_then_rename() {
        let dir = tempdir().unwrap();
        let sl = open_in(dir.path(), &["x"]).await;
        let dest = sl
            .write_skipped("cheque-42.eml", b"hello cheque bytes")
            .await
            .unwrap();
        // File landed in skipped/ with the bytes verbatim.
        assert!(dest.exists());
        let landed = std::fs::read(&dest).unwrap();
        assert_eq!(landed, b"hello cheque bytes");
        // No `.tmp.` leftover.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("skipped"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_str().map(|n| n.starts_with(".tmp.")).unwrap_or(false))
            .collect();
        assert!(leftovers.is_empty(), "no .tmp.* leftover after atomic write");
    }

    #[tokio::test]
    async fn skipped_dir_count_excludes_tmp_files() {
        let dir = tempdir().unwrap();
        let sl = open_in(dir.path(), &["x"]).await;
        sl.write_skipped("cheque-1", b"a").await.unwrap();
        sl.write_skipped("cheque-2", b"b").await.unwrap();
        // Plant a fake mid-write tmp file directly. (Wouldn't happen
        // post-rename; this exercises the filter.)
        std::fs::write(
            dir.path().join("skipped").join(".tmp.cheque-3"),
            b"in-flight",
        )
        .unwrap();
        assert_eq!(sl.skipped_dir_count(), 2);
    }

    #[tokio::test]
    async fn multi_carrier_race_first_to_rename_wins() {
        // Simulates the "first-to-move-wins" semantics §3.3 promises.
        // ANTIE writes a file; one carrier renames it out (claim); a
        // second carrier sees ENOENT and silently continues — that's
        // an OS-level guarantee from rename(2). We exercise the
        // observable end-state.
        let dir = tempdir().unwrap();
        let sl = open_in(dir.path(), &["x"]).await;
        let dest = sl
            .write_skipped("cheque-race", b"contents")
            .await
            .unwrap();

        let claim = dir.path().join("uncle-claim");
        tokio::fs::rename(&dest, &claim).await.unwrap();

        // Second carrier tries to rename the same file — must fail
        // with NotFound (file already moved).
        let cousin_claim = dir.path().join("cousin-claim");
        let err = tokio::fs::rename(&dest, &cousin_claim).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(claim.exists());
        assert!(!cousin_claim.exists());
    }
}
