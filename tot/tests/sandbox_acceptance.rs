//! Sandbox acceptance tests — the §10 gating tests
//! (`AXIOM_DESIGN_TOT.md` §10).
//!
//! These complement the in-process `execve` test
//! (`sandbox::tests::execve_is_sigsys_killed_after_install`) by
//! covering the other two gates:
//!
//!   1. opening any file outside the one `maildir/inbox` fails
//!   2. connecting to any non-Nabla address fails
//!
//! TOT's confinement is layered (§4): the systemd unit
//! `deploy/tot@.service` is layer 1 (declarative — `ProtectSystem=`,
//! `ReadWritePaths=`, `IPAddressDeny=`, …), and the in-process
//! seccomp filter is layer 2. The runtime tests below exercise
//! layer-1 enforcement via `systemd-run --user --wait`.
//!
//! The runtime tests detect their toolchain and **skip cleanly** on
//! a host where `systemd-run --user` is unavailable, so a missing
//! user-session systemd never breaks `cargo test`.

use std::path::PathBuf;
use std::process::Command;

/// Substrings every shipped `deploy/tot@.service` must contain. A
/// missing line means we silently dropped a hardening guarantee the
/// design doc claims (§4).
const REQUIRED_DIRECTIVES: &[&str] = &[
    "DynamicUser=yes",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "ReadWritePaths=",
    "IPAddressDeny=any",
    "RestrictAddressFamilies=AF_INET AF_INET6",
    "SystemCallFilter=@system-service",
    "MemoryDenyWriteExecute=yes",
    "RestrictNamespaces=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectProc=invisible",
];

fn unit_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("deploy")
        .join("tot@.service")
}

/// **Static gate.** The shipped unit file contains every required
/// hardening directive. Catches "someone deleted `ProtectSystem=` in
/// a refactor" at `cargo test` time, regardless of the host.
#[test]
fn unit_file_has_all_required_hardening() {
    let path = unit_file();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    for d in REQUIRED_DIRECTIVES {
        assert!(
            text.contains(d),
            "deploy/tot@.service is missing required directive: {d}",
        );
    }
}

/// True iff `systemd-run --user` works on this host. Runtime tests
/// skip when this returns false — the static gate above still runs.
fn systemd_run_user_available() -> bool {
    if Command::new("systemd-run").arg("--version").output().is_err() {
        return false;
    }
    let r = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "default.target"])
        .status();
    matches!(r, Ok(s) if s.success())
}

fn skipped(reason: &str) {
    eprintln!("sandbox_acceptance: skipped — {reason}");
}

/// **Runtime gate 1 — FS confinement.** Under the same directives
/// the unit applies (`ProtectSystem=strict`, `ReadWritePaths=<inbox>`,
/// `ProtectHome=yes`, `PrivateTmp=yes`), a write to the inbox
/// succeeds but writes to any other path (host-`/tmp`, `/etc`,
/// `/usr`) are blocked.
#[test]
fn fs_outside_inbox_is_blocked() {
    if !systemd_run_user_available() {
        skipped("systemd-run --user unavailable on this host");
        return;
    }

    let inbox = tempfile::tempdir().expect("tempdir");
    let inbox_path = inbox.path().to_path_buf();

    // Note: /tmp is NOT tested. PrivateTmp=yes gives the unit its own
    // private tmpfs at /tmp — writes succeed but go to throwaway scratch
    // invisible to the host. That's hardening (isolation), not a block.
    // ProtectSystem=strict makes /etc, /usr, /var read-only.
    let script = format!(
        r#"
if touch {inbox}/probe 2>/dev/null; then echo INBOX_OK; else echo INBOX_BLOCKED; fi
if touch /etc/sb-test-etc-$$ 2>/dev/null; then echo ETC_OK; else echo ETC_BLOCKED; fi
if touch /usr/sb-test-usr-$$ 2>/dev/null; then echo USR_OK; else echo USR_BLOCKED; fi
if touch /var/sb-test-var-$$ 2>/dev/null; then echo VAR_OK; else echo VAR_BLOCKED; fi
"#,
        inbox = inbox_path.display(),
    );

    let output = Command::new("systemd-run")
        .arg("--user")
        .arg("--wait")
        .arg("--collect")
        .arg("--pipe")
        .arg("--quiet")
        .arg("-p")
        .arg("ProtectSystem=strict")
        .arg("-p")
        .arg(format!("ReadWritePaths={}", inbox_path.display()))
        .arg("-p")
        .arg("ProtectHome=yes")
        .arg("-p")
        .arg("PrivateTmp=yes")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("spawn systemd-run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n");

    assert!(
        stdout.contains("INBOX_OK"),
        "inbox write must succeed inside the sandbox; got:\n{combined}"
    );
    assert!(
        stdout.contains("ETC_BLOCKED"),
        "/etc write must be blocked (ProtectSystem=strict); got:\n{combined}"
    );
    assert!(
        stdout.contains("USR_BLOCKED"),
        "/usr write must be blocked (ProtectSystem=strict); got:\n{combined}"
    );
    assert!(
        stdout.contains("VAR_BLOCKED"),
        "/var write must be blocked (ProtectSystem=strict); got:\n{combined}"
    );
}

/// **Runtime gate 2 — network confinement.** The production unit uses
/// `IPAddressDeny=any` + `IPAddressAllow=<nabla>` (eBPF cgroup, root
/// only — not exercisable under `systemd-run --user`). The closest
/// equivalent we can apply unprivileged is
/// `RestrictAddressFamilies=AF_UNIX`, which blocks the AF_INET socket
/// family at the kernel level. That's *coarser* than per-IP allowlisting,
/// but for the §10 assertion "connecting to any non-Nabla address fails,"
/// it is a strict subset — if no AF_INET socket can be created, no IP
/// connect, Nabla or otherwise, can succeed.
#[test]
fn non_nabla_connect_is_blocked() {
    if !systemd_run_user_available() {
        skipped("systemd-run --user unavailable on this host");
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        skipped("python3 unavailable on this host");
        return;
    }

    let script = r#"
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect(("1.1.1.1", 53))
    print("CONNECTED")
except OSError as e:
    print(f"BLOCKED:{type(e).__name__}")
sys.exit(0)
"#;

    let output = Command::new("systemd-run")
        .arg("--user")
        .arg("--wait")
        .arg("--collect")
        .arg("--pipe")
        .arg("--quiet")
        .arg("-p")
        .arg("RestrictAddressFamilies=AF_UNIX")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("spawn systemd-run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n");

    assert!(
        stdout.contains("BLOCKED:"),
        "AF_INET socket creation must be blocked; got:\n{combined}"
    );
    assert!(
        !stdout.contains("CONNECTED"),
        "no connect must succeed; got:\n{combined}"
    );
}
