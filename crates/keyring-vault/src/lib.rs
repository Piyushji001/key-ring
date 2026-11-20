//! # keyring-vault
//!
//! Vault format, storage and the record model. Everything Keyring does that
//! is not cryptography and not user interface.
//!
//! This crate has no Tauri dependency and no network dependency, which means
//! it can be tested from a plain `cargo test` and driven from the CLI in
//! `src/bin/keyring_cli.rs` without a GUI toolchain.
//!
//! ## Layering
//!
//! ```text
//!  keyring-cli / (Phase 3) Tauri commands
//!            |
//!      VaultSession          <- holds KEK + DEK, saves, locks
//!            |
//!    db::records / db::fields / db::attachments
//!            |                      ^ encryption boundary: plaintext exists
//!      keyring-crypto                 only in Zeroizing buffers below here
//! ```
//!
//! ## Rules
//!
//! 1. No `unwrap()` or `expect()` outside tests.
//! 2. Nothing in this crate returns a plaintext secret as a `String`. Use
//!    `Zeroizing<Vec<u8>>` so the buffer wipes itself.
//! 3. Every error that could be caused by a wrong password renders as
//!    "Could not unlock this vault."

// `deny` rather than `forbid`: exactly one function needs `unsafe`, the Win32
// process-liveness check in vault/lockfile.rs, and it carries a written
// justification. `forbid` cannot be overridden even with a justification, which
// would mean shelling out to tasklist instead - worse in every way.
#![deny(unsafe_code)]
// `unwrap()` and `expect()` are forbidden in library code (Architecture 11).
// Test builds are exempt, which is why this is `cfg_attr(not(test), ...)`.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod backup;
pub mod db;
pub mod error;
pub mod portable;
pub mod model;
pub mod search;
pub mod util;
pub mod vault;

pub use error::{Result, VaultError};
pub use model::{FieldKind, NewRecord, RecordFilter, RecordRow, RecordType};
pub use vault::session::{LockReason, OpenMode, VaultSession, MIN_PASSWORD_LEN};
pub use search::{SearchHit, SearchIndex};
pub use vault::{VaultHeader, FORMAT_VERSION};

// Phase 7.
pub use backup::{
    create_snapshot, last_backup_at, list_snapshots, prune, restore_snapshot, BackupScheduler,
    RetentionOutcome, SchedulerConfig, Snapshot, Trigger,
};
pub use db::activity::{Action as LogAction, LogEntry};
pub use portable::{
    ExportFormat, ExportSummary, ImportReport, ImportSource, PortableRecord, SkipReason,
};

/// Re-exported so callers do not need to depend on the crypto crate directly.
pub use keyring_crypto::{calibrate_kdf, KdfParams};

/// Rough strength signal for the master password field (FR-1.2).
///
/// Deliberately simple: length and character variety only, no dictionary,
/// because a dictionary check that needs a wordlist is a dependency and a
/// breach check would need a network.
pub fn password_strength(password: &str) -> u8 {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return 0;
    }
    let mut variety = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        variety += 1;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        variety += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        variety += 1;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        variety += 1;
    }

    let length_score = match len {
        0..=11 => 0,
        12..=15 => 1,
        16..=19 => 2,
        20..=27 => 3,
        _ => 4,
    };
    let score = length_score + variety.min(4).saturating_sub(1);
    score.min(4) as u8
}
