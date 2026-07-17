//! TOT sandbox — layer 2 (in-process seccomp-bpf).
//!
//! The PRIMARY confinement is the systemd unit (`deploy/tot@.service`):
//! a read-only filesystem except the one `maildir/inbox`, an egress
//! allowlist of only the attested Nabla nodes, and no capabilities.
//! This module is DEFENSE IN DEPTH — it holds the crown-jewel invariant
//! no matter how TOT is launched (a misconfigured unit, run outside
//! systemd, run inside a container): TOT can never exec another
//! program, never ptrace, never manipulate mounts or namespaces.
//!
//! The filter is a denylist (default action: Allow). A tight in-process
//! *allowlist* that misses one syscall the async runtime needs is a
//! fragile crash; the curated allowlist belongs in systemd's
//! `SystemCallFilter`. This filter's job is the small, unambiguous set
//! of syscalls that must NEVER succeed. See AXIOM_DESIGN_TOT.md §4.

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;

/// Syscalls TOT must never make. A bug in WebSocket frame parsing — the
/// most-exposed code — cannot turn into code execution or a host escape
/// while these are dead.
const DENIED: &[i64] = &[
    libc::SYS_execve, // no exec — the crown jewel
    libc::SYS_execveat,
    libc::SYS_ptrace, // no inspecting/altering other processes
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_mount, // no filesystem remapping
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_setns, // no namespace escape
    libc::SYS_unshare,
    libc::SYS_bpf, // no loading eBPF
];

fn target_arch() -> Result<TargetArch, String> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err("seccomp: unsupported target architecture".to_string())
    }
}

/// Compile the seccomp filter to a BPF program.
fn compile() -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in DENIED {
        // An empty rule vec means "match this syscall unconditionally".
        rules.insert(nr, Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,       // syscalls not in DENIED: allowed
        SeccompAction::KillProcess, // a DENIED syscall: SIGSYS-kill the process
        target_arch()?,
    )
    .map_err(|e| format!("seccomp: build filter: {e}"))?;
    filter
        .try_into()
        .map_err(|e| format!("seccomp: compile filter: {e}"))
}

/// Apply a compiled filter to the calling thread. seccomp filters are
/// inherited across `clone()`, so every thread spawned afterwards is
/// covered automatically.
fn apply(prog: &BpfProgram) -> Result<(), String> {
    seccompiler::apply_filter(prog).map_err(|e| format!("seccomp: apply filter: {e}"))
}

/// Install the seccomp sandbox. Call once, on the main thread, before
/// the tokio runtime spawns any worker thread.
pub fn install() -> Result<(), String> {
    apply(&compile()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance gate (AXIOM_DESIGN_TOT.md §10): once the filter is
    /// installed, `execve` must be impossible. Compile in the parent,
    /// fork, apply + attempt `execve` in the child, and assert the
    /// child was SIGSYS-killed by the kernel.
    #[test]
    fn execve_is_sigsys_killed_after_install() {
        let prog = compile().expect("compile seccomp filter");
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // child
                if apply(&prog).is_err() {
                    libc::_exit(101);
                }
                let path = c"/bin/true".as_ptr();
                let argv = [path, std::ptr::null()];
                let envp = [std::ptr::null()];
                libc::execve(path, argv.as_ptr(), envp.as_ptr());
                // execve must never return — the filter kills it first.
                libc::_exit(102);
            }
            let mut status: libc::c_int = 0;
            let waited = libc::waitpid(pid, &mut status, 0);
            assert_eq!(waited, pid, "waitpid");
            assert!(
                libc::WIFSIGNALED(status),
                "child exited normally (code {}) — execve was NOT blocked",
                libc::WEXITSTATUS(status)
            );
            assert_eq!(
                libc::WTERMSIG(status),
                libc::SIGSYS,
                "child killed by signal {} — expected SIGSYS from seccomp",
                libc::WTERMSIG(status)
            );
        }
    }
}
