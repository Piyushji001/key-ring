# Keyring

<div align="center">

![Keyring Logo](assets/logo.png)

### Zero-Trust, Offline Desktop Credential Vault for DevOps & Security Engineers

[![Rust](https://img.shields.io/badge/Rust-1.77%2B-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB.svg?logo=tauri)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?logo=react)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Zeroize](https://img.shields.io/badge/Security-Zeroized_Memory-success.svg)](https://crates.io/crates/zeroize)

[Features](#key-features) • [Keyring Copilot](#keyring-copilot-100-offline-assistant) • [Architecture](#system-architecture) • [Security Model](#cryptographic-architecture--security-model) • [SSH & Cloud Workflows](#ssh--cloud-workflows-guide) • [Getting Started](#getting-started) • [Benchmarks](#performance-benchmarks)

</div>

---

## Overview

**Keyring** is an offline, zero-trust desktop credential vault engineered for DevOps engineers, cloud architects, and security professionals who demand absolute data sovereignty. 

Unlike traditional cloud password managers that introduce third-party attack surfaces and complex cloud sync synchronizers, Keyring is built with a **verifiable zero-network architecture**: no sockets, no telemetry, no remote syncing, and zero HTTP/TLS client libraries compiled into the binary.

Keyring bridges high-assurance local encryption with seamless DevOps productivity — featuring instant **one-click SSH sessions** (via single-use Windows named pipes), **secure Windows RDP credential handoffs** (`CredWriteW`), **cloud identity environment isolation** (AWS, GCP, Azure, Kubernetes), and a global **sub-50ms HUD search overlay**.

---

## Key Features

- 🔒 **Provable Zero-Network Guarantee**: Mechanically verified with zero sockets, no telemetry, and no remote synchronizers. The webview operates under strict `connect-src 'none'` Content Security Policy.
- ✦ **Keyring Copilot (100% Offline AI & Support Agent)**: In-built local assistant (`Ctrl + J`) capable of interactive connection setup wizards, one-shot natural language parsing (e.g. `ssh root@94.136.186.9 pass: secret`), root-cause troubleshooting for SSH errors, and direct vault automation — running 100% locally with zero internet dependencies.
- 🔑 **Defense-in-Depth Cryptography**: Master password derived via **Argon2id** (calibrated per host); vault records and data keys encrypted with **XChaCha20-Poly1305** envelope encryption with record-specific Additional Authenticated Data (AAD).
- 🚀 **One-Click Native DevOps Connections**:
  - **SSH Launcher**: Secure terminal launching with automatic private key extraction (NTFS ACL-locked via `icacls`) and password handoffs via single-use named pipes (`keyring-askpass`). Plaintext credentials are **never exposed on command-line arguments**.
  - **Secure RDP Connect**: Launches Remote Desktop sessions by securely staging credentials through the Win32 `CredWriteW` Credential Manager without exposing passwords to task lists or process logs.
  - **Cloud & Kubernetes Shells**: Native CLI integrations for **AWS**, **Google Cloud**, **Azure**, and **Kubernetes** (`KUBECONFIG`), injecting credentials strictly through process environment blocks or bounded temp files.
- 🛡️ **Memory Protection & Anti-Decompilation**:
  - Memory zeroized immediately on drop with `zeroize`.
  - Windows release builds feature active Win32 debugger detection (`IsDebuggerPresent`) to abort execution if debuggers or reverse-engineering engines attach.
  - Production bundles strip sourcemaps, comments, and console outputs.
  - Secure Win32 clipboard integration with SHA-256 fingerprint validation, auto-clearing timers, and clipboard history exclusion flags (`CanIncludeInClipboardHistory = 0`).
- 📁 **Encrypted File Attachments**: Store PEM keys, certificates, VPN configs, and service account JSON with independent cryptographic envelopes and SHA-256 integrity verification.
- ⚡ **Blazing Fast In-Memory Search**: Sub-50ms query latency across 10,000+ records with typo tolerance, fuzzy scoring, tag indexing, and recency weighting.
- 🕒 **RFC 6238 TOTP Authenticator**: Built-in two-factor authentication codes with live countdown timers and instant clipboard copy.
- 🔄 **Automated Snapshots & Universal Import/Export**: Debounced automated encrypted backups with rotation scheduling, plus seamless import from 1Password, Bitwarden, KeePass, and CSV.

---

## Keyring Copilot (100% Offline Assistant)

Keyring features an **in-built local AI Copilot** designed to guide users, troubleshoot connection issues, and automate record management while strictly respecting the zero-network security model.

<div align="center">
  <sub>Open anytime via <code>Ctrl + J</code> or the <code>[ ✦ Copilot ]</code> button in the window title bar.</sub>
</div>

### What Copilot Can Do:

1. **Interactive Server & Cloud Connection Wizards**:
   - Walks users step-by-step through setting up servers and clouds: prompts for IP/Hostname $\rightarrow$ Username $\rightarrow$ Auth Type (Password vs Key) $\rightarrow$ Credentials $\rightarrow$ Generates an executable Action Card.
   - 1-Click Actions: **`[ 🚀 Save & Connect Now ]`** (saves record and instantly launches terminal session) or **`[ 💾 Save to Vault ]`**.
2. **One-Shot Natural Language & Connection String Parsing**:
   - Paste raw commands or freeform connection strings:
     ```text
     ssh root@94.136.186.9 pass: s5i8U2jO7
     ```
   - Automatically parses host, port, username, and password into an instant connection Action Card.
3. **Built-In Troubleshooting Knowledge Base**:
   - **SSH "Wrong Password" / "Access Denied"**: Explains server-side defaults (`PermitRootLogin prohibit-password`, `PasswordAuthentication no`, Fail2ban IP bans) and provides copyable server fix commands.
   - **Host Key Verification Errors**: Explains IP recycling/fingerprint changes and generates `ssh-keygen -R <host>` commands.
   - **PuTTY `.ppk` Conversion**: Guides OpenSSH key conversion (`puttygen key.ppk -O private-openssh -o id_rsa`).
   - **Cloud Shell Verification**: Explains ephemeral environment injection and verification commands (`aws sts get-caller-identity`, `az account show`, `kubectl get nodes`).
4. **Direct Vault Automation**:
   - Instant password generation with entropy score and 1-click clipboard copy.
   - On-demand snapshot creation (`ipc.backupNow()`).
   - Real-time search query filtering and direct screen navigation.

### How Copilot Handles Out-of-Scope Queries:

To prevent security misconfigurations and preserve zero-knowledge integrity, Copilot explicitly enforces **Zero-Trust Boundaries**:
- **Internet / External Web Requests**: Explains the zero-network policy and provides instructions to run web/API requests in external browsers and store resulting API keys in Keyring.
- **Lost Master Password Recovery**: Explains zero-knowledge encryption (Argon2id + XChaCha20) and directs users to snapshot history (`Settings -> Backups`).
- **Unmonitored Remote Server Script Execution**: Explains that Keyring does not execute blind background scripts and provides a **`[ Connect ]`** button to launch an interactive, user-audited terminal.
- **Cloud Firewall / Security Group Alterations**: Provides exact console instructions for AWS EC2 / GCP Firewall rules to open TCP port 22 safely.

---

## System Architecture

Keyring follows strict compartmentalization principles. All business logic, cryptographic boundaries, and OS integrations reside in modular Rust crates, while the Tauri desktop shell presents a minimal, isolated interface.

```text
+---------------------------------------------------------------------------------+
|                                Frontend (UI)                                    |
|   React 18  *  TypeScript  *  Tailwind CSS  *  Vite  (CSP: connect-src 'none')  |
+---------------------------------------------------------------------------------+
                                       |
                       Tauri v2 IPC (Sanitized DTOs)
                                       v
+---------------------------------------------------------------------------------+
|                        Desktop Shell (src-tauri)                                |
|  - AppState (Single active session, Mutex-guarded)                             |
|  - TempRegistry (NTFS ACL-locked temporary key extraction & timed purge)        |
|  - Win32 API Integrations (CredWriteW, Named Pipes, Secure Clipboard)           |
|  - Global HUD Hotkey (Ctrl+Shift+Space Overlay Window)                          |
+---------------------------------------------------------------------------------+
            |                                           |
            v                                           v
+-----------------------+                   +-----------------------+
|  crates/keyring-vault |                   | crates/keyring-crypto |
|  - SQLite + CBOR      |  Zeroizing Buffers| - Argon2id KDF        |
|  - In-Memory Search   |<----------------->| - XChaCha20-Poly1305  |
|  - Automated Backups  |                   | - Envelope Encryption |
|  - Import / Export    |                   | - Zeroize & CSPRNG    |
+-----------------------+                   +-----------------------+
            ^
            | Single-use Named Pipe (\\.\pipe\keyring-askpass-*)
+-------------------------+
|  crates/keyring-askpass |
|  - Windows SSH_ASKPASS  |
|  - Ephemeral read & exit|
+-------------------------+
```

---

## Cryptographic Architecture & Security Model

Keyring enforces strict cryptographic boundaries inspired by military-grade offline key stores:

```text
Master Password
      │
      ▼  Argon2id (Salt, Memory: 64MiB+, Iterations: 3+, Parallelism: 4)
Key Encryption Key (KEK)  [Zeroized in RAM on lock]
      │
      ▼  XChaCha20-Poly1305 (AEAD Key Unwrapping)
Data Encryption Key (DEK)  [Zeroized in RAM on lock]
      │
      ├──────► Field Values: XChaCha20-Poly1305 (AAD = record_id | field_name | version)
      │
      └──────► Attachments: XChaCha20-Poly1305 (AAD = attachment_id | version)
```

### Security Guarantees & Threat Model

| Vector | Defense Mechanism |
|---|---|
| **Network Exfiltration** | **Zero sockets.** Offline by design: zero network crates in dependencies and webview strictly enforces `connect-src 'none'`. |
| **Command-Line Snooping** | Secrets **never** appear in process `argv`. SSH passwords pass via single-use Win32 named pipes; RDP uses `CredWriteW`; Cloud shells use inherited process environments. |
| **Process Memory Dumps** | All master keys, derived keys, and plaintext buffers wrap inside `zeroize::Zeroizing<T>`, scrubbing memory on drop. |
| **Disk Inspection** | Secrets and attachments are encrypted at rest with XChaCha20-Poly1305. Temp files (e.g. extracted keys) are restricted with Windows NTFS DACLs to the current user SID and purged on a strict timeout. |
| **Clipboard History Scraping** | Clipboard payloads set Windows-specific format flags `CanIncludeInClipboardHistory = 0` and `CanUploadToCloudStore = 0`, then auto-wipe after 30 seconds. |
| **Tampering & Swapping** | Header serialization uses CBOR with authenticated encryption. Record fields enforce AAD binding to prevent ciphertext splicing across records. |

---

## SSH & Cloud Workflows Guide

### 1. Setting Up One-Click SSH

Keyring provides two distinct, frictionless methods to connect to remote servers:

#### Option A: Key-Based Authentication (Recommended for Cloud & Linux)
1. In Keyring, press `Ctrl + N` and select **SSH server**.
2. Fill in:
   - **Title**: Descriptive name (e.g., `prod-api-01`).
   - **Host**: Domain or IP address only (e.g., `192.168.1.100` or `api.example.com`). *Do not prepend `user@`.*
   - **Username**: The remote user (e.g., `ubuntu`, `ec2-user`, `debian`, `root`).
   - **Port**: `22` (or your custom port).
3. Scroll down to the **Attachments** section and click **Attach a file**.
4. Select your OpenSSH private key file (`id_rsa`, `id_ed25519`, or `.pem`).
5. Click **Connect**. Keyring extracts the key to an isolated temporary location with user-only permissions (`icacls`), opens your preferred terminal (Windows Terminal / PowerShell), and launches `ssh -i <extracted_key> user@host`.

> **Note on Key Formats**: Ensure your key is in standard OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`). PuTTY `.ppk` files must be converted to OpenSSH format using PuTTYgen before attaching.

#### Option B: Password Authentication (via `keyring-askpass`)
1. Create or edit an **SSH server** record.
2. Fill in:
   - **Host**: Server IP or hostname (e.g. `10.0.0.5`).
   - **Username**: The login user (e.g. `admin` or `root`). *Crucial: If left blank, OpenSSH falls back to your Windows system username, which usually causes authentication failure.*
   - **Password**: Enter the remote user's password into the encrypted **Password** field.
3. *Important*: Ensure no old private key is attached to the record (Keyring prioritizes private keys if present).
4. Click **Connect**. Keyring launches an ephemeral Win32 named pipe, invokes `ssh.exe` with `SSH_ASKPASS_REQUIRE=force`, and pipes the password directly to OpenSSH without revealing it on the terminal or command line.

> **Server-Side Requirement**: Password login requires `PasswordAuthentication yes` in the remote host's `/etc/ssh/sshd_config`. Most public cloud instances (AWS EC2, GCP Compute) disable password auth by default in favor of keys.

---

### 2. Cloud & Kubernetes Shells

Launch pre-authenticated terminals for your infrastructure in one click:
- **AWS**: Injects `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and optional `AWS_SESSION_TOKEN` into the terminal process environment.
- **Google Cloud**: Extracts your service account JSON to a protected temp path and sets `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`.
- **Azure**: Sets service principal environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`).
- **Kubernetes**: Decrypts the target kubeconfig and exports `KUBECONFIG` directly for `kubectl`, `helm`, and `k9s`.

---

## Performance Benchmarks

All benchmarks measured on standard desktop hardware (AMD Ryzen / Intel Core i7, NVMe SSD):

| Operation | Target Spec | Actual Performance |
|---|---|---|
| **Argon2id Key Derivation** | High-security calibration | ~450 ms (configurable memory & iterations) |
| **Search 10,000 Records** | Sub-50ms fuzzy query latency | **< 35 ms** |
| **Vault Load & Decrypt** | Instant startup | **< 120 ms** |
| **One-Click SSH Launch** | Terminal spawn & pipe handshake | **< 200 ms** |
| **Memory Footprint (Idle)** | Lean desktop footprint | **~50 MB** RAM |

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [pnpm](https://pnpm.io/) (`corepack enable pnpm` or `npm i -g pnpm`)
- [Rust](https://www.rust-lang.org/) (1.77+ with MSVC toolchain on Windows)
- [OpenSSH Client](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) (shipped by default in Windows 10/11)

### Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Piyushji001/key-ring.git
   cd key-ring
   ```

2. **Install frontend dependencies**:
   ```bash
   pnpm install
   ```

3. **Build the askpass helper binary**:
   ```bash
   cargo build -p keyring-askpass
   ```

4. **Run the desktop development environment**:
   ```bash
   pnpm tauri dev
   ```

### Running Tests

Execute the comprehensive test suite verifying cryptography, atomic writes, SQLite storage, and Win32 integrations:

```bash
# Run all workspace unit, integration, and lifecycle tests (156+ tests)
cargo test --workspace

# Run frontend type checking & linter
pnpm typecheck
pnpm lint

# Verify zero-network compile boundary
cargo check -p keyring-app
```

---

## Project Structure

```text
key-ring/
├── crates/
│   ├── keyring-crypto/            # Core crypto: Argon2id, XChaCha20-Poly1305, zeroize
│   ├── keyring-vault/             # SQLite engine, in-memory search, backup scheduler
│   └── keyring-askpass/           # Windows named-pipe SSH password helper
├── src-tauri/                     # Tauri v2 desktop shell, Win32 APIs, IPC commands
│   ├── src/
│   │   ├── actions/               # SSH, RDP, Cloud, Askpass, Clipboard, Tempfile
│   │   ├── ipc/                   # Command endpoints mapped to React
│   │   ├── model/                 # DTO representations & type bridges
│   │   └── platform/              # Platform-specific Win32 bindings
├── src/                           # React 18 + TypeScript frontend
│   ├── components/                # Modular UI (Sidebar, RecordList, DetailPane, etc.)
│   ├── hooks/                     # Custom React hooks (useVault, useRecords)
│   ├── routes/                    # Views: Unlock, Setup, VaultWindow, Overlay HUD
│   └── styles/                    # Design tokens & Tailwind utility themes
└── package.json
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + Shift + Space` | Toggle Global Quick-Search HUD Overlay (from any app) |
| `Ctrl + J` | Toggle Keyring Copilot (100% Offline Local Assistant) |
| `Ctrl + L` | Instant Vault Lock & Memory Wipe |
| `Ctrl + N` | Create New Record |
| `Ctrl + ,` | Open Settings & Snapshot History |
| `/` | Focus Record Search Bar |
| `Esc` | Close Dialogs / Settings / Dismiss Overlay / Close Copilot |

---

## Roadmap

- [x] **Phase 1-2**: Argon2id KDF + XChaCha20-Poly1305 envelope encryption engine.
- [x] **Phase 3**: Tauri v2 desktop shell & lock-state lifecycle.
- [x] **Phase 4**: In-memory encrypted search index with sub-50ms ranking.
- [x] **Phase 5**: Win32 secure clipboard wiping & NTFS-isolated temp file registry.
- [x] **Phase 6**: Secure RDP (`CredWriteW`), SSH command builder, and RFC 6238 TOTP.
- [x] **Phase 7**: Encrypted file attachments, automated backups, and 1Password/Bitwarden import.
- [x] **Phase 7.5**: Named-pipe SSH password handoff (`keyring-askpass`) & Cloud terminal launchers.
- [x] **Phase 8**: Multi-Cloud CLI integrations (AWS, GCP, Azure, K8s) & Anti-Decompilation hardening.
- [x] **Phase 9**: In-built 100% Offline Keyring Copilot (Interactive wizards, NLP parsing, Troubleshooting).
- [ ] **v1.1**: Direct SSH agent injection over Windows OpenSSH named pipe.
- [ ] **v1.2**: Cross-platform desktop builds (macOS & Linux desktop shells).

---

## Contributing

Contributions, bug reports, and suggestions are welcome!
1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'feat: add amazing feature'`).
4. Ensure all tests and clippy checks pass (`cargo test --workspace && pnpm typecheck`).
5. Open a Pull Request.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<div align="center">
<sub>Crafted with precision in Rust & TypeScript. Designed for engineers who value zero-trust security.</sub>
</div>
