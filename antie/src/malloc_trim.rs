//! KI#23 mitigation — periodic `malloc_trim(0)` + SIGUSR1 handler.
//!
//! Background: under sustained load, glibc's per-thread arenas retain
//! freed memory in their internal free lists rather than returning
//! pages to the kernel. Rust drops + libc free() fire correctly; the
//! bytes just stay in the pool. Measured 2026-06-01 (soak Session 17):
//! ANTIE peaks at ~422 MiB/process vs ~64 MiB fresh idle (6.6× growth)
//! across 10 processes ⇒ ~3.6 GiB held captive at steady state.
//!
//! `malloc_trim(0)` asks glibc to release as much as possible back to
//! the kernel. Combined with `MALLOC_ARENA_MAX=2` on the process env
//! (see `scripts/axiom-env.py`), the effect compounds — fewer arenas
//! to fragment + active release pressure.
//!
//! Two triggers:
//!   * **Periodic** — tokio task fires every `MALLOC_TRIM_INTERVAL_SECS`
//!     seconds (default 60). Always on; cost is a single syscall.
//!   * **On-demand** — SIGUSR1 handler runs the same call. Operators
//!     send `kill -USR1 <pid>` for an emergency release.
//!
//! Linux-only. `malloc_trim` is a GNU extension; on other targets these
//! functions are no-ops so the call sites stay portable.

use tracing::{debug, info};

const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Call `malloc_trim(0)`. Returns 1 if any memory was released, 0
/// otherwise. No-op on non-Linux.
#[cfg(target_os = "linux")]
pub fn trim() -> i32 {
    // SAFETY: malloc_trim is async-signal-safe per glibc docs.
    unsafe { libc::malloc_trim(0) }
}

#[cfg(not(target_os = "linux"))]
pub fn trim() -> i32 {
    0
}

/// Spawn the periodic-trim background task. Interval is read from
/// `ANTIE_MALLOC_TRIM_INTERVAL_SECS` env var, defaulting to 60s. A
/// value of 0 disables the periodic task (SIGUSR1 still wired).
pub fn spawn_periodic() -> Option<tokio::task::JoinHandle<()>> {
    let secs = std::env::var("ANTIE_MALLOC_TRIM_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    if secs == 0 {
        info!("malloc_trim: periodic task disabled (interval=0)");
        return None;
    }
    info!("malloc_trim: periodic task every {secs}s");
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        // First tick fires immediately; skip it to wait one full interval.
        tick.tick().await;
        loop {
            tick.tick().await;
            let released = trim();
            debug!("malloc_trim: periodic call returned {released}");
        }
    }))
}

/// Wire a SIGUSR1 handler that calls `malloc_trim(0)`. Operator runs
/// `kill -USR1 <pid>` for an on-demand release. Idempotent — safe to
/// call multiple times (the handler just respawns).
#[cfg(target_os = "linux")]
pub fn install_sigusr1_handler() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut stream = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        loop {
            stream.recv().await;
            let released = trim();
            info!("malloc_trim: SIGUSR1 triggered, returned {released}");
        }
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn install_sigusr1_handler() -> std::io::Result<()> {
    Ok(())
}
