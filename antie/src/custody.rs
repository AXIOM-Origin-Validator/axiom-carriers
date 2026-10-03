//! Custody deposit — where a reply goes when the client has no mailbox.
//!
//! YPX-023 RULE 3. A client that cannot hold a mailbox (the webclient) reaches
//! its validator over a connection held open by a carrier (TOT). That carrier
//! stamps the envelope with a custody header on the way into
//! `maildir/inbox/`; ANTIE matches the header against its configured routing
//! table and deposits the reply here instead of mailing it. The carrier claims
//! it by atomic rename and pushes it back down the socket.
//!
//! ANTIE's whole involvement is this file: match a header name, write a file.
//! It learns nothing about sessions, holds no connection, and the deposit is
//! deliberately NOT a security check — the stamp is routing, never
//! authentication (YPX-023 §3.2).
//!
//! **Atomicity is the contract.** The carrier claims by rename, so it must
//! never observe a partially-written file: write to `tmp/`, fsync, then
//! `rename(2)` into place. This mirrors `uncle_sink::tee` and the Maildir
//! discipline TOT already uses on the way in.

use std::io;
use std::path::{Path, PathBuf};

/// Write `bytes` to `<dir>/<name>` atomically, creating `<dir>` and its
/// sibling `tmp/` as needed. Returns the final path.
///
/// `dir` is the per-session directory (`<outbox>/<id>`) and `name` is
/// `<request_id>.cbor` — a per-ID SUBDIRECTORY rather than a flat
/// `<id>.cbor`, because one k=3 round produces THREE replies for a single
/// session id and UNCLE's flat convention would collide three times. It also
/// makes the carrier's cleanup on disconnect one directory removal instead of
/// a prefix scan.
pub async fn deposit(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    // Reject a name that could escape the directory. `request_id` is a UUID on
    // every production path, but this function must not depend on that: it is
    // handed a value that originated in a client-supplied envelope, and a
    // `../` in it would let a reply be written outside the session dir.
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("custody: refusing unsafe deposit name {name:?}"),
        ));
    }

    let tmp_dir = dir.join("tmp");
    tokio::fs::create_dir_all(&tmp_dir).await?;

    let tmp_path = tmp_dir.join(name);
    let final_path = dir.join(name);

    // write + fsync the file, then rename, then fsync the directory so the
    // rename itself survives a crash — same durability the Maildir intake uses.
    {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::File::create(&tmp_path).await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
    }
    tokio::fs::rename(&tmp_path, &final_path).await?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RULE 4 (YPX-023 §2B.4) in its smallest form: the normal-session stamp
    /// and a dev sender DISAGREE, and disagreement must reject.
    ///
    /// The guard itself lives at the `send_response` site in gateway.rs (it
    /// needs the live config); this pins the PREDICATE it turns on, so a
    /// change to `is_dev_wallet`'s meaning surfaces here rather than as a
    /// silently-widened session path.
    ///
    /// Why it matters more than the reverse direction: a dev message riding
    /// the normal path carries the dev class's higher in-mesh trust — a
    /// privilege escalation, not merely a misdelivery.
    #[test]
    fn dev_sender_is_recognised_so_the_normal_stamp_can_be_refused() {
        use axiom_core_logic::wallet_id::is_dev_wallet;
        // dev — must be caught and refused at the send_response guard
        assert!(is_dev_wallet("alice@axiom.internal/7785e81311"));
        assert!(is_dev_wallet("s2r53509_001@axiom.internal"));
        // normal — the only senders allowed to carry X-TOT-Session
        assert!(!is_dev_wallet("axiomdevwallet001@purelymail.com/abc123"));
        assert!(!is_dev_wallet("someone@example.com"));
        // ⚠ NOT a suffix match: a hostile lookalike must not read as dev.
        assert!(!is_dev_wallet("evil@axiom.internal.attacker.com"));
        assert!(!is_dev_wallet("evil@not-axiom.internal"));
    }

    #[tokio::test]
    async fn deposit_writes_and_is_claimable() {
        let root = std::env::temp_dir().join(format!("axiom_custody_{}", std::process::id()));
        let dir = root.join("abc123");
        let p = deposit(&dir, "req-1.cbor", b"hello").await.expect("deposit");
        assert_eq!(tokio::fs::read(&p).await.unwrap(), b"hello");
        // The claimer renames out; nothing must be left in tmp/.
        let tmp_left = std::fs::read_dir(dir.join("tmp")).unwrap().count();
        assert_eq!(tmp_left, 0, "tmp/ must be empty — a leftover means a torn write is visible");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Three replies from ONE k=3 round must not collide. This is the reason
    /// the layout is `<outbox>/<id>/<request_id>.cbor` and not UNCLE's flat
    /// `<id>.cbor` — with the flat form these three writes are one file.
    #[tokio::test]
    async fn three_replies_one_session_do_not_collide() {
        let root = std::env::temp_dir().join(format!("axiom_custody_k3_{}", std::process::id()));
        let dir = root.join("session-id");
        for r in ["req-a.cbor", "req-b.cbor", "req-c.cbor"] {
            deposit(&dir, r, r.as_bytes()).await.expect("deposit");
        }
        let n = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "tmp")
            .count();
        assert_eq!(n, 3, "a k=3 round deposits THREE distinct replies");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The name reaches us from a client-supplied envelope. A traversal must be
    /// refused BY THE GUARD rather than escaping the session directory.
    ///
    /// ⚠ MUTATION-CHECKED, and the first version of this test was WORTHLESS: it
    /// asserted only `is_err()`, which passed even with the `..` check deleted —
    /// because the FILESYSTEM refuses to create a file named `..`. A test that
    /// cannot tell "my guard refused" from "the OS happened to refuse" pins
    /// nothing ([[feedback_checks_that_cannot_fail]]). It now asserts the error
    /// KIND is `InvalidInput`, which only this guard produces; the OS paths
    /// return `IsADirectory`/`NotFound`. Delete the `..` clause and it goes red.
    #[tokio::test]
    async fn deposit_refuses_path_traversal() {
        let root = std::env::temp_dir().join(format!("axiom_custody_esc_{}", std::process::id()));
        let dir = root.join("s");
        for bad in ["../escape.cbor", "a/b.cbor", "", "..", "..\\win.cbor"] {
            let err = deposit(&dir, bad, b"x").await.expect_err(
                "must refuse unsafe deposit name — a reply written outside the \
                 session dir is a misdelivery",
            );
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidInput,
                "name {bad:?} must be refused BY THE GUARD (InvalidInput), not \
                 incidentally by the filesystem — got {err:?}"
            );
        }
        // Positive control: a legitimate name is NOT refused, so the guard is
        // not simply rejecting everything.
        deposit(&dir, "req-ok.cbor", b"x").await.expect("a normal name must pass");
        let _ = std::fs::remove_dir_all(&root);
    }
}
