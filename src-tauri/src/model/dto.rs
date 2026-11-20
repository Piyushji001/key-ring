// ============================================================================
//  AUDIT THIS FILE.
//
//  Every type that crosses the IPC boundary into JavaScript is defined here,
//  and nowhere else. This file is the boundary. If a secret value can appear
//  in a field of any struct below, the product's central security claim is
//  false.
//
//  THE RULE
//  --------
//  No field of any type in this file may ever hold a decrypted secret: no
//  password, no API key, no private key, no TOTP seed, no note body, no
//  attachment content, and no key material.
//
//  WHAT THE FRONTEND IS ALLOWED TO KNOW
//  ------------------------------------
//  Record ids, titles, types, folders, tags, usernames, hostnames, ports,
//  URLs, timestamps, use counts, attachment filenames and sizes, and a
//  boolean per field saying whether an encrypted value exists.
//
//  WHAT THE FRONTEND NEVER RECEIVES
//  --------------------------------
//  Anything that was encrypted. Actions on secrets - copy to clipboard,
//  launch RDP, write a temp file - execute entirely in Rust and return
//  nothing but success or failure.
//
//  HOW TO REVIEW A CHANGE HERE
//  ---------------------------
//  For every new field, ask: "if an attacker could read the JavaScript heap,
//  would this hurt?" If yes, it does not belong. `String` fields are the
//  danger; `bool` and counts are safe.
//
//  Note on direction: the master password travels the OTHER way, from the
//  webview into Rust, because the user types it into a text field. That is
//  unavoidable in any GUI. It is wrapped in `Zeroizing` the moment it arrives
//  and is never returned, logged, or stored. See decision D-14.
// ============================================================================

use serde::{Deserialize, Serialize};

/// Everything the UI needs to render its lock state and vault chrome.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// Drives `data-locked` on `<html>` and therefore the entire palette.
    pub locked: bool,
    pub read_only: bool,
    /// Directory holding vault.kr. Shown on the unlock screen.
    pub vault_path: Option<String>,
    pub vault_id: Option<String>,
    pub format_version: Option<u16>,
    pub record_count: u32,
    pub created_at: Option<i64>,
    pub modified_at: Option<i64>,
    pub kdf: Option<KdfSummary>,
}

impl VaultStatus {
    /// The locked state. Note every identifying field is `None`: a locked
    /// vault reveals nothing, not even how many records it holds.
    pub fn locked() -> Self {
        VaultStatus {
            locked: true,
            read_only: false,
            vault_path: None,
            vault_id: None,
            format_version: None,
            record_count: 0,
            created_at: None,
            modified_at: None,
            kdf: None,
        }
    }
}

/// KDF cost parameters. Not secret - they are stored in the plaintext header
/// by design, and showing them is how the user knows unlocking is expensive.
/// The salt is deliberately absent: the UI has no use for it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfSummary {
    pub memory_mib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Result of timing Argon2id on this machine, for the setup wizard's step 4.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalibrationResult {
    pub memory_mib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// What the derivation actually took, so the wizard can say "about 1.0 s".
    pub measured_ms: u32,
    pub target_ms: u32,
}

/// Password strength for the meter in the setup wizard. A number, not the
/// password, and not a reason - reasons leak information about the password
/// into the UI layer and into any screen recording.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordAssessment {
    /// 0 = too short to accept, 1 = weak, 2 = fair, 3 = good, 4 = strong.
    pub score: u8,
    pub length: u32,
    pub meets_minimum: bool,
}

/// Why the vault locked, pushed to the frontend as the `vault-locked` event so
/// the UI can explain itself instead of just going cold.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockedEvent {
    Manual,
    Idle,
    Sleep,
    Exit,
}

// ---------------------------------------------------------------- records
//
// Everything below arrived in Phase 4. The rule at the top of this file did not
// change: `FieldView.value` is `Some` only for fields that were never
// encrypted. For secret fields it is `None` and `hasValue` carries the only
// information the frontend gets - that something is stored.

/// A row in the record list. Never carries a secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordSummary {
    pub id: String,
    pub title: String,
    pub record_type: String,
    pub type_label: String,
    pub folder: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    /// A non-secret identifying line - `deploy@10.0.0.7`, `Stripe`, a URL.
    /// Assembled in Rust from plaintext fields only.
    pub subtitle: Option<String>,
    pub used_at: Option<i64>,
    pub modified_at: i64,
    pub use_count: i64,
    pub attachment_count: u32,
    pub in_trash: bool,
}

/// One field, as the UI may see it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub name: String,
    pub label: String,
    pub kind: String,
    /// True when this field is stored encrypted.
    pub is_secret: bool,
    /// Plaintext value. `None` for every secret field, always.
    pub value: Option<String>,
    /// For secret fields: whether anything is stored. This is the entire
    /// extent of what the frontend learns about a secret.
    pub has_value: bool,
    /// Whether previous versions exist, so the UI can offer the history drawer.
    pub history_count: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub id: String,
    pub filename: String,
    pub size_bytes: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordDetail {
    pub summary: RecordSummary,
    pub fields: Vec<FieldView>,
    pub attachments: Vec<AttachmentView>,
    pub created_at: i64,
    /// The field the primary action operates on, e.g. `password`.
    pub primary_field: Option<String>,
}

/// A search result. `matchedContext` is drawn only from non-secret values;
/// note bodies are searchable but never echoed back.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHitDto {
    pub record_id: String,
    pub title: String,
    pub record_type: String,
    pub type_label: String,
    pub folder: String,
    pub favorite: bool,
    pub matched_field: Option<String>,
    pub matched_context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CountedItem {
    pub key: String,
    pub label: String,
    pub count: i64,
}

/// Everything the sidebar renders, in one call.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SidebarData {
    pub total: i64,
    pub favorites: i64,
    pub trash: i64,
    pub types: Vec<CountedItem>,
    pub folders: Vec<CountedItem>,
    pub tags: Vec<CountedItem>,
}

/// The definition of a record type, so the form can be driven by data rather
/// than a switch statement duplicated in TypeScript.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordTypeInfo {
    pub key: String,
    pub label: String,
    pub primary_field: Option<String>,
    pub fields: Vec<FieldTemplateInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldTemplateInfo {
    pub name: String,
    pub label: String,
    pub kind: String,
    pub secret: bool,
}

// ============================================================================
//  THE ONE EXCEPTION. READ THIS BEFORE USING IT.
//
//  `RevealedValue` carries a decrypted secret into JavaScript. It is the only
//  type in this file that does, and it exists because UI Spec section 4 has a
//  reveal button and there is no way to draw text on screen without the webview
//  holding it. Pretending otherwise would be dishonest architecture.
//
//  Constraints that make it tolerable:
//    - It is returned ONLY by `reveal_field`, which the user must explicitly
//      trigger, never as part of loading a record.
//    - The UI must drop it after the countdown in `expires_in_ms` and must
//      never store it in component state that outlives the reveal.
//    - Copy-to-clipboard does NOT use this path. Copying happens entirely in
//      Rust (Phase 5), which is why copy is the default action and reveal is
//      the deliberate one.
//
//  If you are looking for a way to make the UI "more convenient" by fetching
//  secrets ahead of time, this is the type you would reach for. Do not.
//  Decision D-21.
// ============================================================================
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedValue {
    pub record_id: String,
    pub field: String,
    pub value: String,
    pub expires_in_ms: u32,
}

// ---------------------------------------------------------------- Phase 5

/// State of the clipboard hold, so the toast can show a live countdown.
///
/// Carries no value - only whether something of ours is on the clipboard, for
/// how much longer, and which field it came from (a name, not a value).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardStatus {
    pub active: bool,
    pub field: Option<String>,
    pub seconds_remaining: u32,
    /// False when Windows refused one of the exclusion formats. The UI must
    /// say so rather than imply a guarantee we did not get.
    pub excluded_from_history: bool,
}

impl ClipboardStatus {
    pub fn idle() -> Self {
        ClipboardStatus {
            active: false,
            field: None,
            seconds_remaining: 0,
            excluded_from_history: true,
        }
    }
}

/// Result of writing an attachment to disk. The path is not secret; the file
/// is, which is why it has a deadline.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    pub path: String,
    pub filename: String,
    pub expires_in_seconds: u32,
}

// ---------------------------------------------------------------- Phase 6

/// Result of launching an external application. Carries a sentence for the UI,
/// never a credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchResult {
    pub launched: bool,
    pub detail: String,
}

/// A built SSH command. Safe to display: it contains a host, a user and
/// possibly a key path, and by construction no password.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshCommand {
    pub command: String,
    pub copied: bool,
}

/// A TOTP code.
///
/// This does cross the boundary, and unlike `RevealedValue` it does not need a
/// banner. A code is derived, six digits wide, and worthless in under thirty
/// seconds. The seed it came from never leaves Rust, which is the thing worth
/// protecting.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u32,
    pub digits: u32,
}
