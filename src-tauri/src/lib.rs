//! Keyring desktop shell.
//!
//! This crate is deliberately thin. All business logic lives in
//! `keyring-vault`, and all cryptography in `keyring-crypto`. What happens
//! here is: hold one session behind a Mutex, expose a small set of commands,
//! and configure a window.
//!
//! The thinness is the point. This is the only crate that links a webview, so
//! it is the only crate where a mistake can leak something to JavaScript.

#![deny(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod actions;
pub mod error;
pub mod ipc;
pub mod model;
pub mod platform;
pub mod state;
pub mod tray;

use tauri::{Emitter, Listener, Manager};

use state::AppState;

/// FR-5.1 default. User-configurable in Settings (Phase 8).
const DEFAULT_HOTKEY: &str = "CmdOrCtrl+Shift+Space";

/// Show the overlay centred on the active monitor and hand it focus.
///
/// The window is created hidden at startup rather than on demand, because
/// FR-5.2 gives us 200 ms and creating a webview costs more than that.
fn show_overlay(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("overlay") else {
        tracing::warn!("overlay window is missing");
        return;
    };

    // Centre on whichever monitor the cursor is on, not the primary one - the
    // overlay should appear where the user is looking.
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit("overlay-shown", ());
}

fn hide_overlay(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("overlay") {
        let _ = window.hide();
        let _ = window.emit("overlay-hidden", ());
    }
}

/// Set up local file logging. Logs go next to the app's data directory and
/// contain no secrets - `keyring-vault` and `keyring-crypto` are both written
/// so that no plaintext or key material is ever passed to `tracing`.
fn init_logging(app: &tauri::AppHandle) {
    let dir = app
        .path()
        .app_log_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);

    let appender = tracing_appender::rolling::daily(&dir, "keyring.log");
    let subscriber = tracing_subscriber::fmt()
        .with_writer(appender)
        .with_ansi(false)
        .with_target(false)
        .finish();

    // If a subscriber is already installed (tests, repeated setup) that is fine.
    let _ = tracing::subscriber::set_global_default(subscriber);
    tracing::info!("Keyring starting");
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(AppState::new())
        .setup(|app| {
            init_logging(app.handle());

            if let Some(state) = app.try_state::<AppState>() {
                state.load_recents(app.handle());
                // A previous run may have died holding extracted files.
                state.temp_files().purge_all();
            }

            // Global hotkey. Registered here rather than lazily, so a clash
            // with another application surfaces at startup instead of the
            // first time the user reaches for it.
            {
                use tauri_plugin_global_shortcut::{
                    Builder as ShortcutBuilder, ShortcutState,
                };

                let handle = app.handle().clone();
                app.handle().plugin(
                    ShortcutBuilder::new()
                        .with_handler(move |app, _shortcut, event| {
                            if event.state() != ShortcutState::Pressed {
                                return;
                            }
                            let visible = app
                                .get_webview_window("overlay")
                                .and_then(|w| w.is_visible().ok())
                                .unwrap_or(false);
                            if visible {
                                hide_overlay(app);
                            } else {
                                show_overlay(app);
                            }
                        })
                        .build(),
                )?;

                use tauri_plugin_global_shortcut::GlobalShortcutExt;
                if let Err(e) = handle.global_shortcut().register(DEFAULT_HOTKEY) {
                    // Not fatal: the application is still usable from its
                    // window. But the user needs to know their hotkey is dead.
                    tracing::warn!(error = %e, hotkey = DEFAULT_HOTKEY, "could not register the global hotkey");
                    let _ = handle.emit("hotkey-unavailable", DEFAULT_HOTKEY);
                }
            }

            // Dismiss on focus loss (FR-5.4).
            if let Some(overlay) = app.get_webview_window("overlay") {
                let handle = app.handle().clone();
                overlay.on_window_event(move |event| {
                    if let tauri::WindowEvent::Focused(false) = event {
                        hide_overlay(&handle);
                    }
                });
            }

            // The overlay asks to be dismissed after acting on a result.
            {
                let handle = app.handle().clone();
                app.listen("overlay-dismiss", move |_| hide_overlay(&handle));
            }
            {
                let handle = app.handle().clone();
                app.listen("overlay-open-main", move |_| {
                    hide_overlay(&handle);
                    if let Some(main) = handle.get_webview_window("main") {
                        let _ = main.show();
                        let _ = main.unminimize();
                        let _ = main.set_focus();
                    }
                });
            }

            // FR-10.6: tray icon, close-to-tray, start with Windows.
            if let Err(e) = crate::tray::setup(app.handle()) {
                // Not fatal: the application works without a tray icon.
                tracing::warn!(error = %e, "could not create the tray icon");
            }

            crate::ipc::action_cmds::spawn_sweeper(app.handle().clone());
            // FR-8.1: debounced backup after writes. The worker only ever asks
            // the scheduler whether a backup is owed, so it cannot contend with
            // a save in progress.
            crate::ipc::backup_cmds::spawn_backup_worker(app.handle().clone());
            // FR-1.4: lock on idle, on sleep, and on workstation lock.
            crate::actions::autolock::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::vault_cmds::vault_status,
            ipc::vault_cmds::is_locked,
            ipc::vault_cmds::recent_vaults,
            ipc::vault_cmds::last_vault,
            ipc::vault_cmds::vault_exists,
            ipc::vault_cmds::assess_password,
            ipc::vault_cmds::calibrate_kdf,
            ipc::vault_cmds::create_vault,
            ipc::vault_cmds::open_vault,
            ipc::vault_cmds::open_vault_read_only,
            ipc::vault_cmds::lock_vault,
            ipc::vault_cmds::change_master_password,
            ipc::vault_cmds::touch_activity,
            ipc::vault_cmds::idle_seconds,
            // Phase 4 - records
            ipc::record_cmds::list_records,
            ipc::record_cmds::get_record,
            ipc::record_cmds::create_record,
            ipc::record_cmds::create_record_with_fields,
            ipc::record_cmds::set_field,
            ipc::record_cmds::delete_field,
            ipc::record_cmds::add_custom_field,
            ipc::record_cmds::rename_record,
            ipc::record_cmds::move_record,
            ipc::record_cmds::set_favorite,
            ipc::record_cmds::add_tag,
            ipc::record_cmds::remove_tag,
            ipc::record_cmds::duplicate_record,
            ipc::record_cmds::trash_record,
            ipc::record_cmds::restore_record,
            ipc::record_cmds::purge_record,
            ipc::record_cmds::mark_used,
            ipc::record_cmds::record_types,
            ipc::record_cmds::field_kinds,
            ipc::record_cmds::sidebar_data,
            ipc::record_cmds::reveal_field,
            // Phase 4 - search
            ipc::search_cmds::search,
            ipc::search_cmds::index_size,
            ipc::search_cmds::rebuild_index,
            ipc::search_cmds::type_keys,
            // Phase 5 - actions
            ipc::action_cmds::copy_field,
            ipc::action_cmds::copy_primary,
            ipc::action_cmds::copy_username,
            ipc::action_cmds::clear_clipboard,
            ipc::action_cmds::clipboard_status,
            ipc::action_cmds::extract_attachment,
            ipc::action_cmds::extracted_files,
            ipc::action_cmds::purge_extracted,
            ipc::action_cmds::open_url,
            // Phase 6 - integrations
            ipc::integration_cmds::launch_rdp,
            ipc::integration_cmds::clear_rdp_credential,
            ipc::integration_cmds::ssh_command,
            ipc::integration_cmds::ssh_command_with_key,
            ipc::integration_cmds::extract_ssh_key,
            ipc::integration_cmds::totp_code,
            ipc::integration_cmds::copy_totp,
            ipc::integration_cmds::validate_totp_secret,
            // Phase 7 - attachments (closes the FR-3.1 gap: until now the
            // backend could store attachments but no command exposed it)
            ipc::attachment_cmds::add_attachment,
            ipc::attachment_cmds::remove_attachment,
            ipc::attachment_cmds::preview_attachment,
            // Phase 7 - backup, restore, import, export
            ipc::backup_cmds::backup_status,
            ipc::backup_cmds::list_backups,
            ipc::backup_cmds::backup_now,
            ipc::backup_cmds::set_backup_dir,
            ipc::backup_cmds::set_backup_retention,
            ipc::backup_cmds::set_backup_automatic,
            ipc::backup_cmds::restore_backup,
            ipc::backup_cmds::preview_import,
            ipc::backup_cmds::run_import,
            ipc::backup_cmds::begin_plaintext_export,
            ipc::backup_cmds::run_export,
            ipc::backup_cmds::import_keyring_export,
            // Phase 7.5 - one-click connect
            ipc::connect_cmds::ssh_connect,
            ipc::connect_cmds::cloud_connect,
            ipc::connect_cmds::connect_capabilities,
            ipc::connect_cmds::cancel_askpass,
            // Phase 8 - settings, generator, activity log
            ipc::settings_cmds::get_settings,
            ipc::settings_cmds::set_setting,
            ipc::settings_cmds::apply_hotkey,
            ipc::settings_cmds::generate_password,
            ipc::settings_cmds::generate_passphrase,
            ipc::settings_cmds::activity_log,
            ipc::settings_cmds::activity_count,
            ipc::settings_cmds::clear_activity_log,
        ])
        .on_window_event(|window, event| {
            // Close-to-tray intercepts the close *request* before the window is
            // destroyed. `hide_to_tray` locks the vault itself - see the banner
            // in tray.rs for why that is not optional.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" && crate::tray::close_to_tray_enabled(window.app_handle())
                {
                    api.prevent_close();
                    crate::tray::hide_to_tray(window.app_handle());
                    return;
                }
            }

            // Closing the window must wipe keys, not just hide a surface.
            if let tauri::WindowEvent::Destroyed = event {
                if window.label() != "main" {
                    return;
                }
                if let Some(state) = window.try_state::<AppState>() {
                    // Locking purges extracted files and clears the clipboard.
                    let _ = state.lock_vault(keyring_vault::LockReason::Exit);
                    tracing::info!("main window destroyed, vault locked and temp files purged");
                }
            }
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            // No `expect` here: the crate denies it, and a panic at startup
            // gives the user a stack trace instead of a sentence.
            eprintln!("Keyring failed to start: {e}");
            std::process::exit(1);
        });
}
