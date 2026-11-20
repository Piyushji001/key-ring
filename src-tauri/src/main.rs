// Hide the console window in release builds. In debug it stays, because
// `tracing` output and panics are worth seeing while developing.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    keyring_app_lib::run()
}
