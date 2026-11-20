//! Crash-safe file replacement.
//!
//! Protocol (Architecture 4.4):
//!   1. write everything to `<name>.tmp` in the same directory
//!   2. fsync the file handle
//!   3. fsync the directory (POSIX only; NTFS metadata is journalled)
//!   4. rename over the target - atomic on NTFS and on POSIX
//!   5. on any failure, delete the temp file; the original is untouched
//!
//! `std::fs::rename` maps to `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` on
//! Windows, so replacing an existing file is a single atomic operation.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Replace `target` with `bytes`, atomically.
pub fn atomic_write(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        )
    })?;
    fs::create_dir_all(dir)?;

    let file_name = target
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "target path has no name")
        })?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!("{file_name}.tmp"));

    let write_result = (|| -> std::io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Durability of the directory entry itself. Not available on Windows,
    // where NTFS journals metadata; not an error there.
    #[cfg(unix)]
    {
        if let Ok(dir_handle) = File::open(dir) {
            let _ = dir_handle.sync_all();
        }
    }

    Ok(())
}
