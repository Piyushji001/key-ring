//! Launching a terminal, with secrets in the environment block and never on
//! the command line.
//!
//! ## The one rule
//!
//! Everything in this module exists to keep secrets out of `argv`. A command
//! line is visible to Task Manager, Process Explorer, `wmic process get
//! commandline`, every EDR agent, and any process running as the same user.
//! An environment block is not: it is readable by a debugger attached to the
//! process and by anything with `PROCESS_VM_READ`, which is a strictly higher
//! bar and the same bar that protects Keyring's own memory.
//!
//! So: hostnames, usernames, ports and file paths may appear in a command
//! line. Passwords, secret keys, tokens and passphrases may not, ever.
//!
//! ## Terminal selection
//!
//! Windows Terminal when it is present, PowerShell otherwise. `wt.exe` is not
//! on `PATH` in the usual sense — it is an execution alias under
//! `%LOCALAPPDATA%\Microsoft\WindowsApps`, which is why this probes for the
//! file rather than trusting a bare `Command::new("wt")` to work.
//!
//! A subtlety worth knowing: `wt.exe` **launches and exits immediately**,
//! handing the real work to the Windows Terminal process. So a `Child` from
//! `wt.exe` tells you nothing about whether the session succeeded, and the
//! environment we set is inherited by the shell because `wt` passes its own
//! environment through. That works, but it means the credential lifetime is
//! bounded by the shell's lifetime, not by anything Keyring can observe.
//! Which is precisely why cloud credentials get a TTL and a temp directory
//! that gets purged.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use zeroize::Zeroizing;

use crate::error::{AppError, Result};

/// Which terminal to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalKind {
    /// Windows Terminal if present, PowerShell if not. The default.
    Auto,
    WindowsTerminal,
    PowerShell,
    /// `cmd.exe`. Offered because some tooling still misbehaves under
    /// PowerShell's argument parsing.
    Cmd,
}

impl TerminalKind {
    pub fn parse(s: &str) -> Self {
        match s {
            "windows_terminal" | "wt" => TerminalKind::WindowsTerminal,
            "powershell" | "pwsh" => TerminalKind::PowerShell,
            "cmd" => TerminalKind::Cmd,
            _ => TerminalKind::Auto,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TerminalKind::Auto => "auto",
            TerminalKind::WindowsTerminal => "windows_terminal",
            TerminalKind::PowerShell => "powershell",
            TerminalKind::Cmd => "cmd",
        }
    }
}

/// A resolved terminal: the program to run and how to hand it a command.
#[derive(Debug, Clone)]
pub struct ResolvedTerminal {
    pub program: PathBuf,
    pub label: &'static str,
    kind: TerminalKind,
}

/// Find Windows Terminal.
///
/// The `WindowsApps` alias is a zero-byte reparse point that only resolves for
/// the interactive user, so `is_file()` is a genuine presence check.
pub fn find_windows_terminal() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")?;
    let path = PathBuf::from(local)
        .join("Microsoft")
        .join("WindowsApps")
        .join("wt.exe");
    path.is_file().then_some(path)
}

pub fn find_powershell() -> Option<PathBuf> {
    // Prefer PowerShell 7 if it is installed; fall back to the one that ships
    // with Windows.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let pwsh = dir.join("pwsh.exe");
            if pwsh.is_file() {
                return Some(pwsh);
            }
        }
    }
    let system_root = std::env::var_os("SystemRoot")?;
    let path = PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    path.is_file().then_some(path)
}

fn find_cmd() -> Option<PathBuf> {
    let system_root = std::env::var_os("SystemRoot")?;
    let path = PathBuf::from(system_root).join("System32").join("cmd.exe");
    path.is_file().then_some(path)
}

/// Resolve a preference into something runnable.
///
/// Falls back rather than failing: a user whose Windows Terminal was uninstalled
/// last week should get a PowerShell window, not an error dialog.
pub fn resolve(preference: TerminalKind) -> Result<ResolvedTerminal> {
    let attempt = |kind: TerminalKind| -> Option<ResolvedTerminal> {
        match kind {
            TerminalKind::WindowsTerminal => find_windows_terminal().map(|program| {
                ResolvedTerminal {
                    program,
                    label: "Windows Terminal",
                    kind,
                }
            }),
            TerminalKind::PowerShell => find_powershell().map(|program| ResolvedTerminal {
                program,
                label: "PowerShell",
                kind,
            }),
            TerminalKind::Cmd => find_cmd().map(|program| ResolvedTerminal {
                program,
                label: "Command Prompt",
                kind,
            }),
            TerminalKind::Auto => None,
        }
    };

    let order = match preference {
        TerminalKind::Auto => [
            TerminalKind::WindowsTerminal,
            TerminalKind::PowerShell,
            TerminalKind::Cmd,
        ],
        TerminalKind::WindowsTerminal => [
            TerminalKind::WindowsTerminal,
            TerminalKind::PowerShell,
            TerminalKind::Cmd,
        ],
        TerminalKind::PowerShell => [
            TerminalKind::PowerShell,
            TerminalKind::WindowsTerminal,
            TerminalKind::Cmd,
        ],
        TerminalKind::Cmd => [
            TerminalKind::Cmd,
            TerminalKind::PowerShell,
            TerminalKind::WindowsTerminal,
        ],
    };

    for kind in order {
        if let Some(resolved) = attempt(kind) {
            return Ok(resolved);
        }
    }

    Err(AppError::invalid(
        "Keyring could not find Windows Terminal, PowerShell or Command Prompt on this machine.",
    ))
}

/// What to run once the terminal is open.
#[derive(Debug, Clone, Default)]
pub struct Launch {
    /// Program and arguments. **Never contains a secret.** Every value here
    /// ends up in a process command line.
    pub argv: Vec<String>,
    /// Variables for the child's environment block. Secrets go here.
    pub env: BTreeMap<String, Zeroizing<String>>,
    /// Working directory, if any.
    pub cwd: Option<PathBuf>,
    /// Title for the Windows Terminal tab. Cosmetic, but a screen with six
    /// identical black rectangles is its own kind of security problem.
    pub title: Option<String>,
    /// Keep the shell open after the command finishes. On for cloud shells
    /// (the point is the session), off for SSH (the point is the connection).
    pub keep_open: bool,
}

impl Launch {
    /// Assert the invariant this module exists to maintain.
    ///
    /// Called immediately before spawning. Cheap, and it turns a future
    /// refactor that puts a password in `argv` into a failed launch rather
    /// than a silent leak.
    fn assert_no_secret_in_argv(&self) -> Result<()> {
        for secret in self.env.values() {
            if secret.trim().is_empty() {
                continue;
            }
            for arg in &self.argv {
                if arg.contains(secret.as_str()) {
                    tracing::error!(
                        "refusing to launch: a value from the environment appeared in the command line"
                    );
                    return Err(AppError::internal(
                        "a secret reached a command line; launch aborted",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Spawn the terminal.
///
/// Returns the process id of whatever was started, for logging. As noted in
/// the module banner, for `wt.exe` that pid belongs to a launcher that exits
/// immediately and says nothing about the session.
pub fn spawn(terminal: &ResolvedTerminal, launch: Launch) -> Result<u32> {
    launch.assert_no_secret_in_argv()?;

    if launch.argv.is_empty() {
        return Err(AppError::internal("nothing to run in the terminal"));
    }

    let mut command = Command::new(&terminal.program);

    match terminal.kind {
        TerminalKind::WindowsTerminal => {
            // `wt new-tab --title X -- program args...`
            command.arg("new-tab");
            if let Some(title) = &launch.title {
                command.arg("--title").arg(title);
            }
            if let Some(cwd) = &launch.cwd {
                command.arg("--startingDirectory").arg(cwd);
            }
            command.arg("--");

            if launch.keep_open {
                // Run the command, then drop into an interactive shell so the
                // window survives. `-NoExit` alone would not run the command.
                let shell = find_powershell().unwrap_or_else(|| PathBuf::from("powershell.exe"));
                command.arg(shell);
                command.arg("-NoExit");
                command.arg("-Command");
                command.arg(join_for_powershell(&launch.argv));
            } else {
                for arg in &launch.argv {
                    command.arg(arg);
                }
            }
        }
        TerminalKind::PowerShell => {
            if launch.keep_open {
                command.arg("-NoExit");
            }
            command.arg("-Command");
            command.arg(join_for_powershell(&launch.argv));
        }
        TerminalKind::Cmd => {
            command.arg(if launch.keep_open { "/K" } else { "/C" });
            command.arg(launch.argv.join(" "));
        }
        TerminalKind::Auto => {
            return Err(AppError::internal("terminal was not resolved before spawn"));
        }
    }

    if let Some(cwd) = &launch.cwd {
        if terminal.kind != TerminalKind::WindowsTerminal {
            command.current_dir(cwd);
        }
    }

    // The environment block. This is the part that carries secrets, and the
    // only part that does.
    for (key, value) in &launch.env {
        command.env(key, value.as_str());
    }

    let child = command.spawn().map_err(|e| {
        tracing::warn!(error = %e, terminal = terminal.label, "could not start the terminal");
        AppError::invalid(format!(
            "Keyring could not start {}. Check that it is installed.",
            terminal.label
        ))
    })?;

    let pid = child.id();
    tracing::info!(
        terminal = terminal.label,
        pid,
        env_keys = launch.env.len(),
        "terminal launched"
    );
    Ok(pid)
}

/// Quote an argv into a single PowerShell command string.
///
/// PowerShell's parser needs the call operator for a quoted program path, and
/// single quotes with doubling for embedded quotes. Getting this wrong turns a
/// hostname with a hyphen into an arithmetic expression.
fn join_for_powershell(argv: &[String]) -> String {
    let mut out = String::from("& ");
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('\'');
        out.push_str(&arg.replace('\'', "''"));
        out.push('\'');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_quoting_escapes_embedded_quotes() {
        let argv = vec!["ssh".to_string(), "o'brien@host".to_string()];
        assert_eq!(join_for_powershell(&argv), "& 'ssh' 'o''brien@host'");
    }

    #[test]
    fn a_secret_in_argv_aborts_the_launch() {
        let mut launch = Launch {
            argv: vec!["ssh".into(), "-p".into(), "hunter2".into()],
            ..Default::default()
        };
        launch.env.insert(
            "SOME_SECRET".to_string(),
            Zeroizing::new("hunter2".to_string()),
        );

        let err = launch.assert_no_secret_in_argv().unwrap_err();
        assert!(matches!(err.kind, crate::error::ErrorKind::Internal));
    }

    #[test]
    fn a_clean_launch_passes_the_check() {
        let mut launch = Launch {
            argv: vec!["ssh".into(), "deploy@10.0.0.7".into()],
            ..Default::default()
        };
        launch.env.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            Zeroizing::new("abc123".to_string()),
        );
        assert!(launch.assert_no_secret_in_argv().is_ok());
    }

    #[test]
    fn empty_env_values_do_not_trip_the_substring_check() {
        // An empty string is a substring of every argument. Without the
        // guard, any record with a blank optional secret would refuse to
        // launch.
        let mut launch = Launch {
            argv: vec!["ssh".into(), "host".into()],
            ..Default::default()
        };
        launch
            .env
            .insert("EMPTY".to_string(), Zeroizing::new(String::new()));
        assert!(launch.assert_no_secret_in_argv().is_ok());
    }

    #[test]
    fn terminal_preferences_round_trip() {
        for kind in [
            TerminalKind::Auto,
            TerminalKind::WindowsTerminal,
            TerminalKind::PowerShell,
            TerminalKind::Cmd,
        ] {
            assert_eq!(TerminalKind::parse(kind.as_str()), kind);
        }
        assert_eq!(TerminalKind::parse("nonsense"), TerminalKind::Auto);
    }
}
