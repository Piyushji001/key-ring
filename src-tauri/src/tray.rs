//! Tray icon, close-to-tray, and start-with-Windows (FR-10.6).
//!
//! ## The trap this module is built around
//!
//! Before close-to-tray existed, closing the main window destroyed it, and the
//! `Destroyed` handler in `lib.rs` locked the vault — wiping keys, purging
//! extracted files and clearing the clipboard. That behaviour is correct and
//! must survive this feature.
//!
//! With close-to-tray on, closing the window *hides* it instead. The window is
//! never destroyed, so the destroy handler never runs, so **nothing locks the
//! vault**. A user who thinks they closed Keyring would be leaving an unlocked
//! vault resident in memory indefinitely.
//!
//! This module therefore locks explicitly on hide. Minimising to the tray is a
//! window state; it is not a reason to keep keys in memory. The tray icon
//! shows locked/unlocked so the state is never a guess.
//!
//! ## Autostart
//!
//! Starting with Windows starts a *locked* vault. There is no stored password
//! and no unattended unlock, and there never will be — that is the product.

use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use keyring_vault::LockReason;

use crate::state::AppState;

/// Build the tray icon and its menu.
pub fn setup<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Open Keyring", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock now", true, Some("Ctrl+L"))?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &lock, &separator, &quit])?;

    TrayIconBuilder::with_id("keyring-tray")
        .icon(app.default_window_icon().cloned().ok_or_else(|| {
            tauri::Error::AssetNotFound("default window icon missing".into())
        })?)
        .tooltip("Keyring — locked")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(handle_menu_event)
        .on_tray_icon_event(|tray, event| {
            // Left click opens the window. Right click opens the menu, which
            // Tauri handles for us.
            if let TrayIconEvent::Click { button, .. } = event {
                if button == tauri::tray::MouseButton::Left {
                    show_main(tray.app_handle());
                }
            }
        })
        .build(app)?;

    Ok(())
}

fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id.as_ref() {
        "show" => show_main(app),
        "lock" => {
            if let Some(state) = app.try_state::<AppState>() {
                let _ = state.lock_vault(LockReason::Manual);
                let _ = tauri::Emitter::emit(app, "vault-locked", "manual");
            }
        }
        "quit" => {
            // Lock before exiting rather than relying on process teardown to
            // tidy up. Extracted files and the clipboard need an explicit
            // purge; a killed process does neither.
            if let Some(state) = app.try_state::<AppState>() {
                let _ = state.lock_vault(LockReason::Exit);
            }
            app.exit(0);
        }
        _ => {}
    }
}

fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Reflect lock state in the tray tooltip.
///
/// Small thing, but the whole point of a tray icon is answering "is it running
/// and what is it doing" without opening anything.
pub fn set_locked_state<R: Runtime>(app: &AppHandle<R>, locked: bool) {
    if let Some(tray) = app.tray_by_id("keyring-tray") {
        let _ = tray.set_tooltip(Some(if locked {
            "Keyring — locked"
        } else {
            "Keyring — unlocked"
        }));
    }
}

/// Whether the user asked for close-to-tray.
///
/// Read from the vault's settings when one is open. When the vault is locked
/// we cannot read the setting — there is no session — so we default to
/// destroying the window. Defaulting the other way would hide a window whose
/// vault we cannot inspect, which is the more surprising outcome.
pub fn close_to_tray_enabled(app: &AppHandle) -> bool {
    let Some(state) = app.try_state::<AppState>() else {
        return false;
    };
    state
        .with_session(|session| {
            Ok(keyring_vault::db::settings::get_i64(
                session.conn()?,
                keyring_vault::db::settings::CLOSE_TO_TRAY,
                1,
            ) != 0)
        })
        .unwrap_or(false)
}

/// Hide to the tray **and lock**.
///
/// The lock is not optional and is the entire reason this function exists
/// rather than a bare `window.hide()`. See the module banner.
pub fn hide_to_tray(app: &AppHandle) {
    if let Some(state) = app.try_state::<AppState>() {
        let _ = state.lock_vault(LockReason::Manual);
        let _ = tauri::Emitter::emit(app, "vault-locked", "hidden-to-tray");
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    set_locked_state(app, true);
}
