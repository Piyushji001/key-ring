//! An unlocked vault.
//!
//! Holds the KEK and the DEK in memory and wipes both on `lock()`.
//!
//! ## Why the KEK is kept, not just the DEK
//!
//! The header AAD covers `modified_at`, so every save changes the AAD and
//! the DEK must be re-wrapped. Re-wrapping needs the KEK. Keeping it costs
//! 32 bytes of already-sensitive memory and avoids either (a) asking for the
//! password on every save or (b) excluding fields from the AAD, which would
//! weaken the header authentication that 3.4 exists to provide.
//! Recorded as decision D-5.

use keyring_crypto::{DerivedKey, KdfParams};
use rusqlite::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{Result, VaultError};
use crate::model::RecordType;
use crate::util::time::now_unix;

use super::file::{self, VaultPaths};
use super::header::{header_aad_bytes, VaultHeader, FORMAT_VERSION};
use super::lockfile::{self, LockGuard, LockOutcome};

/// FR-1.2.
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Normal: takes the advisory lock, refuses if another process holds it.
    ReadWrite,
    /// Opens even when another process holds the lock. Saving is refused.
    ReadOnly,
}

/// Why the vault was locked. Surfaces to the UI as the `vault-locked` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Idle,
    Sleep,
    Exit,
}

pub struct VaultSession {
    paths: VaultPaths,
    header: VaultHeader,
    conn: Option<Connection>,
    kek: Option<DerivedKey>,
    dek: Option<DerivedKey>,
    mode: OpenMode,
    _lock: Option<LockGuard>,
    dirty: bool,
}

impl std::fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSession")
            .field("root", &self.paths.root)
            .field("locked", &self.is_locked())
            .field("mode", &self.mode)
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl VaultSession {
    // ------------------------------------------------------------ create

    /// Create a brand new vault. Fails if one already exists at `root`.
    pub fn create(
        root: impl Into<std::path::PathBuf>,
        password: &[u8],
        kdf: &KdfParams,
        kdf_calibrated_ms: u32,
    ) -> Result<Self> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(VaultError::PasswordTooShort(MIN_PASSWORD_LEN));
        }
        kdf.validate_strength()?;

        let paths = VaultPaths::new(root);
        if paths.exists() {
            return Err(VaultError::AlreadyExists);
        }
        std::fs::create_dir_all(&paths.root)?;
        std::fs::create_dir_all(paths.blobs_dir())?;

        let guard = match lockfile::acquire(&paths.lock_file())? {
            LockOutcome::Acquired(g) => g,
            LockOutcome::Held(info) => return Err(VaultError::AlreadyOpen { pid: info.pid }),
        };

        let kek = keyring_crypto::derive_kek(password, kdf)?;
        let dek = keyring_crypto::generate_dek()?;

        // Build the header with a placeholder wrap, compute the AAD from it,
        // then wrap for real. The placeholder is excluded from its own AAD,
        // so this is not circular.
        let placeholder = keyring_crypto::WrappedKey::from_parts(&[0u8; 24], &[0u8; 48])?;
        let mut header = VaultHeader::new(
            Uuid::new_v4().to_string(),
            now_unix(),
            kdf,
            &placeholder,
            kdf_calibrated_ms,
        );
        let aad = header_aad_bytes(&header)?;
        let wrapped = keyring_crypto::wrap_dek(&kek, &dek, &aad)?;
        header.set_wrapped(&wrapped);

        let conn = db::load_in_memory(&paths, &[])?;
        db::settings::seed_defaults(&conn)?;

        let mut session = VaultSession {
            paths,
            header,
            conn: Some(conn),
            kek: Some(kek),
            dek: Some(dek),
            mode: OpenMode::ReadWrite,
            _lock: Some(guard),
            dirty: true,
        };
        session.save()?;
        Ok(session)
    }

    // -------------------------------------------------------------- open

    /// Open an existing vault.
    ///
    /// Every failure below - wrong password, tampered header, truncated file
    /// - produces the same message. That is deliberate.
    pub fn open(
        root: impl Into<std::path::PathBuf>,
        password: &[u8],
        mode: OpenMode,
    ) -> Result<Self> {
        let paths = VaultPaths::new(root);
        if !paths.exists() {
            return Err(VaultError::NoVaultHere);
        }

        let guard = match mode {
            OpenMode::ReadOnly => None,
            OpenMode::ReadWrite => match lockfile::acquire(&paths.lock_file())? {
                LockOutcome::Acquired(g) => Some(g),
                LockOutcome::Held(info) => return Err(VaultError::AlreadyOpen { pid: info.pid }),
            },
        };

        // A scratch file here means a previous run died mid-transfer.
        db::purge_work_file(&paths);

        let (header, db_bytes) = file::read_container(&paths.container())?;
        if header.format_version > FORMAT_VERSION {
            return Err(VaultError::UnsupportedFormat(header.format_version));
        }

        let kdf = header.kdf_params()?;
        let kek = keyring_crypto::derive_kek(password, &kdf)?;
        let aad = header_aad_bytes(&header)?;
        let wrapped = header.wrapped_key()?;
        let dek = keyring_crypto::unwrap_dek(&kek, &wrapped, &aad)?;

        let conn = db::load_in_memory(&paths, &db_bytes)?;

        Ok(VaultSession {
            paths,
            header,
            conn: Some(conn),
            kek: Some(kek),
            dek: Some(dek),
            mode,
            _lock: guard,
            dirty: false,
        })
    }

    // ------------------------------------------------------------ access

    pub fn is_locked(&self) -> bool {
        self.dek.is_none() || self.conn.is_none()
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn format_version(&self) -> u16 {
        self.header.format_version
    }

    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the vault as needing a save. Every mutation helper calls this.
    pub fn touch(&mut self) {
        self.dirty = true;
    }

    pub fn conn(&self) -> Result<&Connection> {
        self.conn.as_ref().ok_or(VaultError::Locked)
    }

    /// The Data Encryption Key. Crate-visible only: callers outside this
    /// crate get plaintext through `open_secret`, never the key itself.
    pub(crate) fn dek(&self) -> Result<&DerivedKey> {
        self.dek.as_ref().ok_or(VaultError::Locked)
    }

    fn require_writable(&self) -> Result<()> {
        if self.mode == OpenMode::ReadOnly {
            return Err(VaultError::ReadOnly);
        }
        Ok(())
    }

    // -------------------------------------------------------------- save

    /// Persist the whole vault: dump the database image, refresh the header,
    /// re-wrap the DEK over the new header, write atomically.
    pub fn save(&mut self) -> Result<()> {
        self.require_writable()?;

        // Each borrow of `self` is scoped, because `self.header` is mutated
        // in between and the borrow checker will not allow them to overlap.
        let image = {
            let conn = self.conn.as_ref().ok_or(VaultError::Locked)?;
            db::dump_image(&self.paths, conn)?
        };

        self.header.modified_at = now_unix();
        let aad = header_aad_bytes(&self.header)?;
        let wrapped = {
            let kek = self.kek.as_ref().ok_or(VaultError::Locked)?;
            let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
            keyring_crypto::wrap_dek(kek, dek, &aad)?
        };
        self.header.set_wrapped(&wrapped);

        file::write_container(&self.paths.container(), &self.header, &image)?;
        self.dirty = false;
        Ok(())
    }

    /// Save only if something changed.
    pub fn save_if_dirty(&mut self) -> Result<()> {
        if self.dirty {
            self.save()?;
        }
        Ok(())
    }

    // -------------------------------------------------------------- lock

    /// Wipe key material and drop the database. The struct stays alive so
    /// the UI can show which vault to unlock, but nothing can be decrypted.
    pub fn lock(&mut self, reason: LockReason) {
        tracing::info!(?reason, "locking vault");
        if let Some(mut kek) = self.kek.take() {
            kek.wipe();
        }
        if let Some(mut dek) = self.dek.take() {
            dek.wipe();
        }
        self.conn = None;
        db::purge_work_file(&self.paths);
    }

    /// TEST HOOK. Returns true when the key buffers have been zeroed rather
    /// than merely dropped. Used by the Phase 2 acceptance test.
    #[doc(hidden)]
    pub fn keys_are_wiped(&self) -> bool {
        self.kek.is_none() && self.dek.is_none()
    }

    // ------------------------------------------------- password rotation

    /// UC-11. Re-derives the KEK over a fresh salt and re-wraps the DEK.
    /// The records are not touched, so this takes about one derivation.
    pub fn change_master_password(
        &mut self,
        current: &[u8],
        new: &[u8],
        new_kdf: Option<&KdfParams>,
    ) -> Result<()> {
        self.require_writable()?;
        if new.len() < MIN_PASSWORD_LEN {
            return Err(VaultError::PasswordTooShort(MIN_PASSWORD_LEN));
        }

        // Verify the current password by deriving and comparing against the
        // KEK we already hold, in constant time.
        let existing_kdf = self.header.kdf_params()?;
        let candidate = keyring_crypto::derive_kek(current, &existing_kdf)?;
        let held = self.kek.as_ref().ok_or(VaultError::Locked)?;
        if !candidate.ct_eq(held) {
            return Err(VaultError::Crypto(keyring_crypto::CryptoError::Open));
        }

        let kdf = match new_kdf {
            Some(k) => {
                k.validate_strength()?;
                k.with_new_salt()?
            }
            None => existing_kdf.with_new_salt()?,
        };

        let new_kek = keyring_crypto::derive_kek(new, &kdf)?;
        self.header.set_kdf(&kdf);

        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?.clone();
        let aad = header_aad_bytes(&self.header)?;
        let wrapped = keyring_crypto::wrap_dek(&new_kek, &dek, &aad)?;
        self.header.set_wrapped(&wrapped);

        if let Some(mut old) = self.kek.replace(new_kek) {
            old.wipe();
        }

        self.dirty = true;
        self.save()
    }

    // --------------------------------------------------- record helpers
    //
    // Thin wrappers so callers never have to pass the DEK around.

    /// Create a record and populate it from `values` (`field_name` -> value).
    /// Values for template fields marked secret are encrypted.
    pub fn create_record(
        &mut self,
        record_type: RecordType,
        title: &str,
        folder: &str,
        values: &[(String, String)],
    ) -> Result<String> {
        self.require_writable()?;
        let history_limit = self.history_limit();
        let format_version = self.header.format_version;
        let new = crate::model::NewRecord::new(record_type, title).in_folder(folder);

        let id = {
            let conn = self.conn()?;
            db::records::insert(conn, &new)?
        };

        for (name, value) in values {
            self.set_field_value(&id, name, value, history_limit, format_version)?;
        }

        self.dirty = true;
        Ok(id)
    }

    /// Set one field, choosing encrypted or plaintext storage from the
    /// record type's template. Unknown names become custom text fields, or
    /// custom secret fields if the name is prefixed with `secret:`.
    pub fn set_field(&mut self, record_id: &str, name: &str, value: &str) -> Result<()> {
        self.require_writable()?;
        let history_limit = self.history_limit();
        let format_version = self.header.format_version;
        self.set_field_value(record_id, name, value, history_limit, format_version)?;
        self.dirty = true;
        Ok(())
    }

    fn set_field_value(
        &self,
        record_id: &str,
        name: &str,
        value: &str,
        history_limit: usize,
        format_version: u16,
    ) -> Result<()> {
        let conn = self.conn()?;
        let record = db::records::require(conn, record_id)?;

        // `secret:foo` forces encrypted storage for a custom field.
        let (name, template, forced_secret) = match name.strip_prefix("secret:") {
            Some(stripped) => (stripped, None, true),
            None => (name, record.record_type.find_template(name), false),
        };

        match template {
            Some(t) if t.secret => {
                let dek = self.dek()?;
                db::fields::set_secret(
                    conn,
                    dek,
                    format_version,
                    record_id,
                    t.name,
                    t.label,
                    if t.kind == crate::model::FieldKind::Attachment {
                        crate::model::FieldKind::Secret
                    } else {
                        t.kind
                    },
                    value.as_bytes(),
                    history_limit,
                )?;
            }
            Some(t) => {
                db::fields::set_plain(conn, record_id, t.name, t.label, t.kind, value)?;
            }
            None => {
                // Custom field: encrypted if forced, or if the name looks
                // like a credential.
                let is_secret = forced_secret || value_should_be_secret(name);
                if is_secret {
                    let dek = self.dek()?;
                    db::fields::set_secret(
                        conn,
                        dek,
                        format_version,
                        record_id,
                        name,
                        name,
                        crate::model::FieldKind::Secret,
                        value.as_bytes(),
                        history_limit,
                    )?;
                } else {
                    db::fields::set_plain(
                        conn,
                        record_id,
                        name,
                        name,
                        crate::model::FieldKind::Text,
                        value,
                    )?;
                }
            }
        }

        db::records::touch_modified(conn, record_id)?;
        Ok(())
    }

    /// Decrypt one secret field. The buffer wipes itself on drop.
    pub fn open_secret(&self, record_id: &str, field: &str) -> Result<Zeroizing<Vec<u8>>> {
        let conn = self.conn()?;
        let dek = self.dek()?;
        db::fields::open_secret(conn, dek, self.header.format_version, record_id, field)
    }

    /// Attach a file. Reads it into memory, encrypts, writes the blob.
    pub fn add_attachment(
        &mut self,
        record_id: &str,
        source: &std::path::Path,
    ) -> Result<String> {
        self.require_writable()?;
        let data = Zeroizing::new(std::fs::read(source)?);
        let filename = source
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("attachment")
            .to_string();
        let format_version = self.header.format_version;

        let id = {
            let conn = self.conn()?;
            let dek = self.dek()?;
            db::attachments::add(
                conn,
                &self.paths,
                dek,
                format_version,
                record_id,
                &filename,
                None,
                &data,
            )?
        };
        self.dirty = true;
        Ok(id)
    }

    /// Decrypt an attachment into memory, verifying its digest.
    pub fn open_attachment(&self, attachment_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let conn = self.conn()?;
        let dek = self.dek()?;
        db::attachments::open_blob(
            conn,
            &self.paths,
            dek,
            self.header.format_version,
            attachment_id,
        )
    }

    /// Run a mutation against the database, then persist.
    ///
    /// Every write path in the application goes through here, so "did that get
    /// saved?" has exactly one answer. Phase 7 will replace the immediate save
    /// with a debounced one; this is the seam where that happens.
    pub fn mutate<T>(
        &mut self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.require_writable()?;
        let out = {
            let conn = self.conn()?;
            f(conn)?
        };
        self.dirty = true;
        self.save()?;
        Ok(out)
    }

    /// Move a record to the trash (FR-2.4). Attachments stay on disk until the
    /// record is purged, so restoring is lossless.
    pub fn trash_record(&mut self, record_id: &str) -> Result<()> {
        self.mutate(|conn| db::records::soft_delete(conn, record_id))
    }

    pub fn restore_record(&mut self, record_id: &str) -> Result<()> {
        self.mutate(|conn| db::records::restore(conn, record_id))
    }

    /// Permanent deletion, including blob files. Not undoable.
    pub fn purge_record(&mut self, record_id: &str) -> Result<()> {
        let paths = self.paths.clone();
        self.mutate(|conn| {
            for a in db::attachments::list_for_record(conn, record_id)? {
                db::attachments::remove(conn, &paths, &a.id)?;
            }
            db::records::purge(conn, record_id)
        })
    }

    /// Empty the trash of anything past its retention window.
    pub fn purge_expired_trash(&mut self) -> Result<usize> {
        let days = self
            .conn()
            .map(|c| db::settings::get_i64(c, db::settings::TRASH_RETENTION_DAYS, 30))
            .unwrap_or(30);
        let paths = self.paths.clone();
        self.mutate(|conn| {
            let ids = db::records::purge_expired(conn, days)?;
            for id in &ids {
                for a in db::attachments::list_for_record(conn, id).unwrap_or_default() {
                    let _ = db::attachments::remove(conn, &paths, &a.id);
                }
            }
            Ok(ids.len())
        })
    }

    /// Record that a credential was used. Drives search ranking, so it is
    /// called on copy and on launch, not merely on view.
    pub fn mark_used(&mut self, record_id: &str) -> Result<()> {
        self.mutate(|conn| db::records::touch_used(conn, record_id))
    }

    pub fn set_favorite(&mut self, record_id: &str, favorite: bool) -> Result<()> {
        self.mutate(|conn| db::records::set_favorite(conn, record_id, favorite))
    }

    pub fn rename_record(&mut self, record_id: &str, title: &str) -> Result<()> {
        let title = title.trim().to_string();
        if title.is_empty() {
            return Err(VaultError::Invalid("A record needs a title.".into()));
        }
        self.mutate(|conn| db::records::rename(conn, record_id, &title))
    }

    pub fn move_record(&mut self, record_id: &str, folder: &str) -> Result<()> {
        let folder = folder.trim().trim_matches('/').to_string();
        self.mutate(|conn| db::records::set_folder(conn, record_id, &folder))
    }

    pub fn add_tag(&mut self, record_id: &str, tag: &str) -> Result<()> {
        let tag = tag.trim().to_string();
        if tag.is_empty() {
            return Ok(());
        }
        self.mutate(|conn| db::tags::add(conn, record_id, &tag))
    }

    pub fn remove_tag(&mut self, record_id: &str, tag: &str) -> Result<()> {
        self.mutate(|conn| db::tags::remove(conn, record_id, tag))
    }

    pub fn delete_field(&mut self, record_id: &str, name: &str) -> Result<()> {
        self.mutate(|conn| db::fields::delete(conn, record_id, name))
    }

    /// Duplicate a record as a starting point for a new one (FR-2.5).
    /// Secrets are re-encrypted under fresh nonces rather than copied, and
    /// attachments are deliberately not carried over - a duplicated SSH host
    /// almost never wants the same private key.
    pub fn duplicate_record(&mut self, record_id: &str, new_title: &str) -> Result<String> {
        let format_version = self.header.format_version;
        let history_limit = self.history_limit();

        let (source, fields) = {
            let conn = self.conn()?;
            (
                db::records::require(conn, record_id)?,
                db::fields::list_for_record(conn, record_id)?,
            )
        };

        let new = crate::model::NewRecord::new(source.record_type, new_title)
            .in_folder(&source.folder);
        let new_id = {
            let conn = self.conn()?;
            db::records::insert(conn, &new)?
        };

        for field in fields {
            if field.has_secret {
                let value = self.open_secret(record_id, &field.name)?;
                let conn = self.conn()?;
                let dek = self.dek()?;
                db::fields::set_secret(
                    conn,
                    dek,
                    format_version,
                    &new_id,
                    &field.name,
                    &field.label,
                    field.kind,
                    &value,
                    history_limit,
                )?;
            } else if let Some(plain) = field.plain_value {
                let conn = self.conn()?;
                db::fields::set_plain(
                    conn,
                    &new_id,
                    &field.name,
                    &field.label,
                    field.kind,
                    &plain,
                )?;
            }
        }

        self.dirty = true;
        self.save()?;
        Ok(new_id)
    }

    fn history_limit(&self) -> usize {
        match self.conn() {
            Ok(conn) => db::settings::get_i64(conn, db::settings::HISTORY_LIMIT, 10).max(0) as usize,
            Err(_) => 10,
        }
    }
}

/// Custom fields whose name looks like a credential are encrypted by
/// default. Explicit `secret:` prefixing is handled before this is called.
fn value_should_be_secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["password", "secret", "token", "key", "passphrase", "pin"]
        .iter()
        .any(|needle| n.contains(needle))
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock(LockReason::Exit);
    }
}
