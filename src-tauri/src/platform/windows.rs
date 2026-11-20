//! Windows: idle detection, workstation lock, and resume-from-sleep.
//!
//! ## Idle
//!
//! `GetLastInputInfo` reports the tick count of the last keyboard or mouse
//! input, system-wide. Note the consequence: idle means *the machine* is idle,
//! not that Keyring is unfocused. Someone working in another window keeps the
//! vault unlocked, which is what you want - locking a credential manager while
//! its owner is typing in a terminal beside it would be user-hostile.
//!
//! ## Workstation lock
//!
//! The documented way is `WTSRegisterSessionNotification`, which needs a window
//! procedure to receive `WM_WTSSESSION_CHANGE`. Tauri owns the window
//! procedures, so instead we ask whether the input desktop can be opened:
//! when the workstation is locked, the secure desktop is active and
//! `OpenInputDesktop` fails. It is a poll rather than an event, which costs a
//! few seconds of latency and no complexity. Decision D-32.
//!
//! ## Sleep
//!
//! Also a poll, and deliberately so. Rather than registering for power
//! notifications, the monitor compares elapsed wall-clock time with elapsed
//! monotonic time. If the wall clock jumped much further than the loop slept,
//! the machine was suspended in between. This catches sleep, hibernate and lid
//! close without a single extra API.

use super::PlatformOps;

pub struct WindowsPlatform;

impl WindowsPlatform {
    /// Check whether a debugger or dynamic analysis tool is attached.
    /// Returns false in debug builds so developers are never blocked.
    pub fn is_debugger_present() -> bool {
        #[cfg(all(target_os = "windows", not(debug_assertions)))]
        {
            #[allow(unsafe_code)]
            unsafe {
                windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool()
            }
        }
        #[cfg(any(not(target_os = "windows"), debug_assertions))]
        {
            false
        }
    }
}

#[cfg(target_os = "windows")]
impl PlatformOps for WindowsPlatform {
    fn idle_millis(&self) -> Option<u64> {
        #[allow(unsafe_code)] // Two Win32 reads into stack structs we own.
        unsafe {
            use windows::Win32::System::SystemInformation::GetTickCount;
            use windows::Win32::UI::Input::KeyboardAndMouse::{
                GetLastInputInfo, LASTINPUTINFO,
            };

            let mut info = LASTINPUTINFO {
                cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                dwTime: 0,
            };
            if !GetLastInputInfo(&mut info).as_bool() {
                return None;
            }
            // GetTickCount wraps every 49.7 days; wrapping_sub handles it.
            Some(GetTickCount().wrapping_sub(info.dwTime) as u64)
        }
    }

    fn workstation_locked(&self) -> Option<bool> {
        #[allow(unsafe_code)] // Opens a desktop handle and closes it.
        unsafe {
            use windows::Win32::System::StationsAndDesktops::{
                CloseDesktop, OpenInputDesktop, DESKTOP_ACCESS_FLAGS,
            };

            match OpenInputDesktop(Default::default(), false, DESKTOP_ACCESS_FLAGS(0x0001)) {
                Ok(desktop) => {
                    let _ = CloseDesktop(desktop);
                    Some(false)
                }
                // Failure here overwhelmingly means the secure desktop has the
                // input, i.e. the workstation is locked.
                Err(_) => Some(true),
            }
        }
    }

    fn name(&self) -> &'static str {
        "windows"
    }
}

#[cfg(not(target_os = "windows"))]
impl PlatformOps for WindowsPlatform {
    fn idle_millis(&self) -> Option<u64> {
        None
    }
    fn workstation_locked(&self) -> Option<bool> {
        None
    }
    fn name(&self) -> &'static str {
        "unsupported"
    }
}

/// Stand-in for macOS and Linux until those builds exist. Reports nothing,
/// which means idle locking simply does not fire rather than firing wrongly.
pub struct UnsupportedPlatform;

impl PlatformOps for UnsupportedPlatform {
    fn idle_millis(&self) -> Option<u64> {
        None
    }
    fn workstation_locked(&self) -> Option<bool> {
        None
    }
    fn name(&self) -> &'static str {
        "unsupported"
    }
}
