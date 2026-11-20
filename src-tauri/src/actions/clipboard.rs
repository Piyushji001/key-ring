//! Clipboard writes that Windows will not remember.
//!
//! ## The problem this solves
//!
//! Copying a password to the Windows clipboard normally puts it in three
//! places: the clipboard itself, the clipboard *history* (`Win+V`, which keeps
//! the last 25 entries indefinitely), and the cloud clipboard, which syncs it
//! to every machine signed into the same Microsoft account. A password manager
//! that ignores the last two is leaking on every copy.
//!
//! ## How exclusion works
//!
//! Windows has no API for "copy privately". It has three *registered clipboard
//! formats* that the shell honours if they are present in the same clipboard
//! session as the data:
//!
//!   - `ExcludeClipboardContentFromMonitorProcessing` — keeps it away from
//!     clipboard monitors and cloud upload
//!   - `CanIncludeInClipboardHistory`   set to DWORD 0
//!   - `CanUploadToCloudClipboard`      set to DWORD 0
//!
//! All three must be set between `EmptyClipboard` and `CloseClipboard`, by the
//! process that owns the clipboard. That is why this cannot be layered on top
//! of a clipboard crate: the exclusion has to happen inside the same open
//! session as the write.
//!
//! ## Verification
//!
//! FR-6.4 is not satisfied by this code compiling. Copy a password, press
//! `Win+V`, and confirm it is absent. That test is in the Phase 5 checklist and
//! there is no substitute for performing it.

use crate::error::{AppError, Result};

/// What actually happened, so the UI can be honest rather than reassuring.
#[derive(Debug, Clone, Copy)]
pub struct CopyOutcome {
    /// True only if every exclusion format was accepted.
    pub excluded_from_history: bool,
}

#[cfg(windows)]
mod win {
    #![allow(unsafe_code)] // Clipboard ownership is a raw Win32 protocol. Every
                           // open is paired with a close on all paths.

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
        SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    use crate::error::{AppError, Result};

    /// Copy a NUL-terminated wide string into a moveable global buffer, which
    /// is what `SetClipboardData` requires. Ownership passes to the clipboard
    /// on success, so we must NOT free it in that case.
    unsafe fn alloc_global(bytes: &[u8]) -> Result<HGLOBAL> {
        let handle = GlobalAlloc(GMEM_MOVEABLE, bytes.len())
            .map_err(|_| AppError::internal("GlobalAlloc failed"))?;
        let ptr = GlobalLock(handle);
        if ptr.is_null() {
            return Err(AppError::internal("GlobalLock failed"));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
        let _ = GlobalUnlock(handle);
        Ok(handle)
    }

    unsafe fn register(name: &str) -> u32 {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        RegisterClipboardFormatW(PCWSTR(wide.as_ptr()))
    }

    /// Set one of the DWORD-valued exclusion formats to zero.
    unsafe fn deny_format(name: &str) -> bool {
        let id = register(name);
        if id == 0 {
            return false;
        }
        let zero: u32 = 0;
        let Ok(handle) = alloc_global(&zero.to_ne_bytes()) else {
            return false;
        };
        SetClipboardData(id, HANDLE(handle.0 as isize)).is_ok()
    }

    pub fn write_excluded(text: &str) -> Result<bool> {
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        wide.push(0);
        let bytes = unsafe {
            std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2)
        };

        unsafe {
            OpenClipboard(HWND(0)).map_err(|_| {
                AppError::internal("another application is holding the clipboard")
            })?;

            // From here on, every exit path must close the clipboard.
            let result = (|| -> Result<bool> {
                EmptyClipboard().map_err(|_| AppError::internal("EmptyClipboard failed"))?;

                let handle = alloc_global(bytes)?;
                SetClipboardData(CF_UNICODETEXT.0 as u32, HANDLE(handle.0 as isize))
                    .map_err(|_| AppError::internal("SetClipboardData failed"))?;

                // Order matters only in that these must land in the same
                // session as the text. All three, or we report partial.
                let a = deny_format("ExcludeClipboardContentFromMonitorProcessing");
                let b = deny_format("CanIncludeInClipboardHistory");
                let c = deny_format("CanUploadToCloudClipboard");

                Ok(a && b && c)
            })();

            let _ = CloseClipboard();
            result
        }
    }

    /// Read the clipboard back as text, so a scheduled clear can check that it
    /// is still ours before wiping it (FR-6.3).
    pub fn read_text() -> Option<String> {
        unsafe {
            if OpenClipboard(HWND(0)).is_err() {
                return None;
            }
            let out = (|| -> Option<String> {
                let handle = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
                let hglobal = HGLOBAL(handle.0 as *mut core::ffi::c_void);
                let ptr = GlobalLock(hglobal) as *const u16;
                if ptr.is_null() {
                    return None;
                }
                let mut len = 0usize;
                while *ptr.add(len) != 0 && len < 1024 * 1024 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                let text = String::from_utf16_lossy(slice);
                let _ = GlobalUnlock(hglobal);
                Some(text)
            })();
            let _ = CloseClipboard();
            out
        }
    }

    pub fn clear() -> Result<()> {
        unsafe {
            OpenClipboard(HWND(0))
                .map_err(|_| AppError::internal("could not open the clipboard to clear it"))?;
            let result = EmptyClipboard().map_err(|_| AppError::internal("EmptyClipboard failed"));
            let _ = CloseClipboard();
            result
        }
    }
}

#[cfg(not(windows))]
mod win {
    use crate::error::{AppError, Result};

    pub fn write_excluded(_text: &str) -> Result<bool> {
        Err(AppError::internal("clipboard is Windows-only in v1"))
    }
    pub fn read_text() -> Option<String> {
        None
    }
    pub fn clear() -> Result<()> {
        Ok(())
    }
}

/// Fingerprint of what we last wrote, so a clear can verify ownership without
/// keeping the plaintext around to compare against.
pub fn fingerprint(text: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// Write to the clipboard with history and cloud sync suppressed.
pub fn write(text: &str) -> Result<CopyOutcome> {
    let excluded = win::write_excluded(text)?;
    if !excluded {
        // Do not fail the copy - the user asked for it and has it. But say so,
        // and log it, because it means a Windows behaviour changed.
        tracing::warn!("clipboard exclusion formats were not all accepted");
    }
    Ok(CopyOutcome {
        excluded_from_history: excluded,
    })
}

/// Clear the clipboard, but only if it still holds what we put there.
///
/// FR-6.3 exists because wiping whatever the user copied in the meantime -
/// a paragraph of text, a file path - would be its own small disaster.
pub fn clear_if_ours(expected: &[u8; 32]) -> Result<bool> {
    match win::read_text() {
        Some(current) if &fingerprint(&current) == expected => {
            win::clear()?;
            Ok(true)
        }
        Some(_) => {
            tracing::debug!("clipboard changed since we wrote it, leaving it alone");
            Ok(false)
        }
        None => Ok(false),
    }
}

/// Unconditional clear, used on lock and exit.
pub fn clear_now() -> Result<()> {
    win::clear()
}

pub fn read_for_verification() -> Option<String> {
    win::read_text()
}

#[allow(dead_code)]
fn _unused(_: AppError) {}
