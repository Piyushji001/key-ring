//! Platform-specific behaviour, behind one trait so the core stays portable.
//!
//! Everything here is about *when to lock*. FR-1.4 requires locking on idle,
//! on system sleep, and on workstation lock, and each of those is a different
//! OS question with a different answer on each platform.

pub mod windows;

/// What the rest of the application needs from the operating system.
pub trait PlatformOps: Send + Sync {
    /// Milliseconds since the user last touched the keyboard or mouse.
    fn idle_millis(&self) -> Option<u64>;
    /// Is the workstation locked (Win+L, screensaver with password, fast user
    /// switch)? `None` when it cannot be determined.
    fn workstation_locked(&self) -> Option<bool>;
    fn name(&self) -> &'static str;
}

pub fn current() -> Box<dyn PlatformOps> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsPlatform)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Box::new(windows::UnsupportedPlatform)
    }
}
