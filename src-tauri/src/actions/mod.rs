//! Actions: things the backend *does* with a secret, rather than returning it.
//!
//! This module is the reason the IPC boundary holds. A copy command takes a
//! record id and a field name, decrypts inside Rust, writes to the clipboard,
//! and returns `()`. The plaintext never becomes a JavaScript string, never
//! enters the V8 heap, and never waits on a garbage collector to disappear.
//!
//! Contrast with `reveal_field`, which must return a value because the webview
//! has to draw it. That one is the audited exception (decision D-21); these are
//! the rule.

pub mod askpass;
pub mod autolock;
pub mod clipboard;
pub mod cloud;
pub mod connect;
pub mod generator;
pub mod rdp;
pub mod ssh;
pub mod tempfile;
pub mod terminal;
pub mod totp;
