//! The watchdog that locks the vault when you walk away.
//!
//! One thread, polling every few seconds. Three reasons to lock, all of them
//! FR-1.4:
//!
//!   - idle longer than the configured timeout (default 10 minutes)
//!   - the workstation was locked
//!   - the machine woke from sleep
//!
//! Polling rather than event subscription is a deliberate trade: a few seconds
//! of latency in exchange for no window procedures, no power-notification
//! registration, and code that is possible to read. The security cost is
//! bounded - an attacker who has physical access during those few seconds also
//! had it during the ten minutes before.

use std::time::{Duration, Instant, SystemTime};

use keyring_vault::{db, LockReason};
use tauri::{AppHandle, Emitter, Manager};

use crate::model::dto::LockedEvent;
use crate::platform::{self, PlatformOps};
use crate::state::AppState;

/// How often to check. Fast enough to feel responsive, slow enough to be free.
const POLL: Duration = Duration::from_secs(5);

/// A wall-clock jump larger than this, relative to monotonic time, means the
/// machine was suspended.
const SLEEP_THRESHOLD_SECS: u64 = 45;

/// FR-1.4 default, configurable 1-120 minutes.
const DEFAULT_IDLE_SECS: i64 = 600;

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        let ops: Box<dyn PlatformOps> = platform::current();
        tracing::info!(platform = ops.name(), "auto-lock watchdog started");

        let mut last_monotonic = Instant::now();
        let mut last_wall = SystemTime::now();
        let mut was_workstation_locked = false;

        loop {
            std::thread::sleep(POLL);

            let Some(state) = app.try_state::<AppState>() else {
                return;
            };

            // Detect suspend before anything else: if the machine slept, the
            // idle counter is meaningless for this tick anyway.
            let monotonic_elapsed = last_monotonic.elapsed();
            let wall_elapsed = SystemTime::now()
                .duration_since(last_wall)
                .unwrap_or(monotonic_elapsed);
            last_monotonic = Instant::now();
            last_wall = SystemTime::now();

            let slept = wall_elapsed
                .as_secs()
                .saturating_sub(monotonic_elapsed.as_secs())
                > SLEEP_THRESHOLD_SECS
                || wall_elapsed.as_secs() > POLL.as_secs() + SLEEP_THRESHOLD_SECS;

            if state.is_locked() {
                was_workstation_locked = ops.workstation_locked().unwrap_or(false);
                continue;
            }

            if slept {
                lock(&app, &state, LockReason::Sleep, LockedEvent::Sleep);
                continue;
            }

            // Workstation lock: fire on the transition, not on every poll
            // while it stays locked.
            let workstation_locked = ops.workstation_locked().unwrap_or(false);
            if workstation_locked && !was_workstation_locked {
                was_workstation_locked = true;
                lock(&app, &state, LockReason::Sleep, LockedEvent::Sleep);
                continue;
            }
            was_workstation_locked = workstation_locked;

            // Idle.
            let timeout = idle_timeout_secs(&state);
            if timeout > 0 {
                if let Some(idle_ms) = ops.idle_millis() {
                    if idle_ms / 1000 >= timeout as u64 {
                        lock(&app, &state, LockReason::Idle, LockedEvent::Idle);
                    }
                }
            }
        }
    });
}

fn lock(app: &AppHandle, state: &AppState, reason: LockReason, event: LockedEvent) {
    tracing::info!(?reason, "auto-locking");
    let _ = state.lock_vault(reason);
    let _ = app.emit("vault-locked", event);
}

fn idle_timeout_secs(state: &AppState) -> i64 {
    state
        .with_session(|s| {
            Ok(db::settings::get_i64(
                s.conn()?,
                db::settings::IDLE_LOCK_SECS,
                DEFAULT_IDLE_SECS,
            ))
        })
        .unwrap_or(DEFAULT_IDLE_SECS)
}
