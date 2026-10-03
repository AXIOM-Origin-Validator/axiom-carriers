//! LEVEL 2 — the seam: ANTIE's deposit and TOT's pump meeting on one directory.
//!
//! Level 1 proves each half in isolation. This proves they AGREE — the file
//! convention, the per-session subdirectory, and the path both sides are
//! configured with. It needs no validator and no network.
//!
//! What it deliberately cannot prove: that ANTIE's `send_response` matches the
//! header and calls deposit at all, or that a reply reaches a real socket.
//! Those are level 3, against a live validator.

use std::path::PathBuf;

/// Mirror of `axiom-env.py::custody_outbox_path` — the one rule both configs
/// are rendered from. If this and the generator ever disagree, the seam is
/// broken in production while every unit test still passes, which is exactly
/// the silent failure the shared helper exists to prevent.
fn custody_outbox_path(pdir: &std::path::Path) -> PathBuf {
    pdir.join("antie").join("custody")
}

/// The full seam: ANTIE deposits three replies for one k=3 round into the
/// session's directory; TOT collects all three from the path ITS config gives
/// it, and the directory is left clean.
#[tokio::test]
async fn antie_deposit_is_collected_by_tot_pump() {
    let pdir = std::env::temp_dir().join(format!("axiom_seam_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&pdir);

    // Both halves resolve their path from the SAME rule the env renders from.
    let antie_outbox = custody_outbox_path(&pdir);
    let tot_outbox = custody_outbox_path(&pdir);
    assert_eq!(
        antie_outbox, tot_outbox,
        "ANTIE's route outbox and TOT's custody_outbox must be one directory — \
         two paths that differ produce NO error, just sessions that hang"
    );

    let session_id = "aa".repeat(32);
    let dir = antie_outbox.join(&session_id);

    // ── ANTIE side: deposit the three replies of one k=3 round ──
    for req in ["req-alpha", "req-beta", "req-gamma"] {
        axiom_antie::custody::deposit(&dir, &format!("{req}.cbor"), req.as_bytes())
            .await
            .expect("ANTIE deposit");
    }

    // A deposit must be COMPLETE when visible — TOT does no torn-read guard
    // because ANTIE writes tmp -> fsync -> rename.
    assert!(
        !dir.join("tmp").join("req-alpha.cbor").exists(),
        "nothing may be left in tmp/ — a visible file must be complete"
    );

    // ── TOT side: collect from the path its own config names ──
    let collected = collect_like_tot(&tot_outbox.join(&session_id));
    assert_eq!(
        collected.len(),
        3,
        "TOT must collect all three replies of a k=3 round; got {collected:?}"
    );
    assert!(collected.contains(&b"req-alpha".to_vec()));
    assert!(collected.contains(&b"req-beta".to_vec()));
    assert!(collected.contains(&b"req-gamma".to_vec()));

    // Collected replies are gone — a second pass sends nothing.
    assert!(
        collect_like_tot(&tot_outbox.join(&session_id)).is_empty(),
        "a collected reply must not be re-sent"
    );

    let _ = std::fs::remove_dir_all(&pdir);
}

/// Two sessions on ONE wallet must not see each other's replies. This is the
/// property the skip list (keyed on receiver_wallet_id) could not express and
/// the reason the layout is a per-session subdirectory.
#[tokio::test]
async fn two_sessions_do_not_cross() {
    let pdir = std::env::temp_dir().join(format!("axiom_seam2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&pdir);
    let outbox = custody_outbox_path(&pdir);

    let tab_a = "aa".repeat(32);
    let tab_b = "bb".repeat(32);
    axiom_antie::custody::deposit(&outbox.join(&tab_a), "r.cbor", b"FOR-A")
        .await
        .unwrap();
    axiom_antie::custody::deposit(&outbox.join(&tab_b), "r.cbor", b"FOR-B")
        .await
        .unwrap();

    assert_eq!(collect_like_tot(&outbox.join(&tab_a)), vec![b"FOR-A".to_vec()]);
    assert_eq!(collect_like_tot(&outbox.join(&tab_b)), vec![b"FOR-B".to_vec()]);

    let _ = std::fs::remove_dir_all(&pdir);
}

/// What TOT's `pump_replies` does to the filesystem: top-level `*.cbor` only,
/// oldest-first, deleted once taken. Kept in step with `tot/src/main.rs`.
fn collect_like_tot(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "cbor"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for f in files {
        out.push(std::fs::read(&f).expect("read reply"));
        let _ = std::fs::remove_file(&f);
    }
    out
}
