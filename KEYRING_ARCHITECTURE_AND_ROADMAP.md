# Keyring: Architecture Specification, System Blueprint & Future Roadmap

> **Context for AI Models / Claude**: This document provides an exhaustive, end-to-end technical overview of **Keyring** — an open-source, zero-trust, verifiable offline credential vault and DevOps connectivity hub built with Rust, Tauri v2, and React. Use this document to analyze system architecture, audit security boundaries, propose architectural refinements, and brainstorm next-phase feature expansions.

---

## 1. Executive Summary & Vision

### 1.1 The Problem
Modern DevOps and security engineers manage dozens of sensitive credentials: SSH keys, server root passwords, AWS IAM access keys, Google Cloud service account JSON files, Kubernetes kubeconfigs, database connections, and TOTP seeds. 

Today's landscape forces an unappealing compromise:
1. **Cloud-Synced Password Managers (1Password, Bitwarden, LastPass)**: Introduce significant supply-chain and cloud attack surfaces, forced subscription models, telemetry tracking, and awkward manual copy-pasting into terminal windows.
2. **Enterprise Secret Vaults (HashiCorp Vault, CyberArk)**: Heavyweight client-server architectures requiring dedicated infrastructure, remote network roundtrips, and high operational complexity — unsuitable for individual engineer workstations or air-gapped environments.
3. **Local Text Files / Flat Configs (`~/.ssh/config`, `~/.aws/credentials`)**: Unencrypted or weakly protected plaintext files sitting on developer disks, easily exfiltrated by malware or background processes.

### 1.2 The Keyring Solution
**Keyring** is an air-gapped, zero-network desktop credential vault and connectivity platform engineered specifically for workstations. It marries military-grade local envelope encryption with native DevOps automation — enabling **one-click SSH connections**, **cloud shell launches**, and **secure RDP sessions** without exposing secrets to command-line arguments (`argv`), disk plaintext, or cloud telemetry.

---

## 2. Core Architectural Tenets (Non-Negotiable)

1. **Provable Zero-Network Guarantee**:
   - Zero network crates (`reqwest`, `hyper`, `tokio::net`, `curl`) compiled into the binary.
   - Frontend enforces strict Content Security Policy: `connect-src 'none'; default-src 'self'`.
   - The application never dials out, updates over the air, tracks analytics, or makes telemetry calls.
2. **Zero-Knowledge Envelope Cryptography**:
   - Keys derived via host-calibrated **Argon2id**.
   - Data encrypted with **XChaCha20-Poly1305** using record-specific Additional Authenticated Data (AAD) to prevent ciphertext splicing across records.
3. **Zero Plaintext Leakage**:
   - Plaintext credentials never touch process command-line arguments (`argv`), where process monitors (`Get-Process`, Task Manager) could scrape them.
   - Sensitive memory is wrapped in `zeroize::Zeroizing<T>` to wipe RAM immediately on drop.
   - Windows Clipboard operations set `CanIncludeInClipboardHistory = 0` and auto-purge after 30 seconds.
4. **DevOps-First Ergonomics**:
   - Sub-50ms fuzzy search across 10,000+ records via a global HUD overlay (`Ctrl+Shift+Space`).
   - One-click native terminal launching with automated credential handoff.
   - Built-in 100% offline Copilot assistant (`Ctrl+J`) for interactive onboarding, troubleshooting, and direct actions.

---

## 3. Technology Stack & Modular Codebase

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
│   │   └── platform/              # Platform-specific Win32 bindings (DACL, Debugger)
├── src/                           # React 18 + TypeScript frontend
│   ├── components/                # CopilotDrawer, NewRecordDialog, DetailPane, Sidebar
│   ├── hooks/                     # Custom React hooks (useVault, useRecords)
│   ├── routes/                    # Views: Unlock, Setup, VaultWindow, Overlay HUD
│   └── styles/                    # Design tokens & Tailwind utility themes
└── package.json
```

### 3.1 Crate Architecture

#### `crates/keyring-crypto`
- **Argon2id KDF**: Derives a 256-bit Key Encryption Key (KEK) from the user's master password. Uses calibrated memory (default 64 MiB+), iterations (3+), and parallelism (4 threads).
- **XChaCha20-Poly1305**: Authenticated Encryption with Associated Data (AEAD). Uses 256-bit keys and 192-bit nonces, virtually eliminating nonce reuse hazards.
- **Envelope Hierarchy**: Master Password $\rightarrow$ KEK $\rightarrow$ Data Encryption Key (DEK) $\rightarrow$ Record Fields & Attachments.
- **Memory Zeroization**: Plaintext buffers implement Rust's `Zeroize` trait, which writes zeroes to memory upon drop using volatile writes that the compiler cannot optimize away.

#### `crates/keyring-vault`
- **Storage Engine**: Embedded SQLite database serialized with CBOR (`ciborium`) for deterministic, tamper-evident record payloads.
- **AAD Integrity Binding**: Every record field generates AAD from `record_id | field_name | version`, preventing attackers from copying ciphertext from one field/record to another.
- **In-Memory Fuzzy Search**: Builds an in-memory search index with sub-50ms query latency across 10,000+ records, featuring typo tolerance, tag weighting, and recency decay.
- **Automated Snapshots**: Debounced snapshot engine that creates timestamped backup copies before destructive mutations and applies configurable retention policies.
- **Universal Importers**: Parses KeePass CSV, Bitwarden JSON, and 1Password exports directly into encrypted records.

#### `crates/keyring-askpass`
- A dedicated, lightweight Windows executable that acts as an `SSH_ASKPASS` helper.
- Communicates with the main Keyring process via an ephemeral, single-use Win32 Named Pipe (`\\.\pipe\keyring-askpass-<uuid>`).
- OpenSSH invokes this binary when `SSH_ASKPASS_REQUIRE=force` is set; the helper reads the password from the pipe, writes it to standard output, and exits immediately. The pipe terminates upon first read.

#### `src-tauri` (Desktop Application Core)
- **Tauri v2 Shell**: Coordinates secure IPC between frontend TypeScript and backend Rust.
- **Win32 Platform Integration**:
  - `CredWriteW`: Stages RDP credentials directly into the Windows Credential Manager without exposing passwords in process arguments.
  - NTFS DACLs (`icacls`): Restricts extracted private key permissions strictly to the active user's SID (`(R)`), preventing other OS users or unprivileged processes from reading temporary keys.
  - Anti-Debugging (`IsDebuggerPresent`): Detects attached debuggers in release builds to resist memory dumping and dynamic analysis.
- **Global Hotkey Overlay**: Spawns an ephemeral HUD window via `Ctrl+Shift+Space` for instant credential searching and clipboard copying without switching windows.

#### `src/` (Modern React Frontend)
- **Zero-Network Sandboxed Webview**: Strict CSP blocks all outgoing connections.
- **Copilot Drawer (`src/components/CopilotDrawer.tsx`)**: 100% offline conversational assistant with step-by-step connection wizards, one-shot regex/NLP parsing, SSH/Cloud troubleshooting, and direct app automation.
- **Record Creation Dialog (`src/components/NewRecordDialog.tsx`)**: Multi-provider cloud tabs (AWS, GCP, Azure, Kubernetes), smart SSH string parser (`user@host:port`), password visibility toggles, and advanced options accordions.
- **Accessibility & Keyboard Shortcuts**: Fully operable via keyboard (<kbd>Ctrl+N</kbd>, <kbd>Ctrl+J</kbd>, <kbd>Ctrl+L</kbd>, <kbd>/</kbd>, <kbd>Esc</kbd>).

---

## 4. Full Inventory of Implemented Features

| Category | Capability | Implementation Detail |
|---|---|---|
| **Zero-Network Architecture** | Verifiable Offline Execution | Zero network sockets; webview CSP `connect-src 'none'`. Verified mechanically in build pipeline. |
| **Cryptographic Security** | Argon2id + XChaCha20-Poly1305 | Host-calibrated KDF derivation; AEAD envelope encryption with record-level AAD binding. |
| **Memory Protection** | Volatile Zeroization | Master keys and plaintexts implement `Zeroize` to overwrite RAM on drop. |
| **Anti-Decompilation & Debug** | Win32 IsDebuggerPresent | Detects attached analysis engines in release builds; production bundles strip sourcemaps, comments, and logs. |
| **Clipboard Defense** | Anti-Snoop & Auto-Clear | Sets `CanIncludeInClipboardHistory = 0` (Windows 10/11) and automatically wipes clipboard memory after 30s. |
| **One-Click SSH** | Private Key & Password Modes | Private keys extracted with user-only NTFS ACLs; passwords passed via single-use Named Pipes (`keyring-askpass`). Plaintext never touches `argv`. |
| **Secure RDP** | CredWriteW Win32 Integration | Launches Windows Remote Desktop by writing ephemeral credentials directly to Windows Credential Manager. |
| **Cloud CLI Shells** | AWS, GCP, Azure, Kubernetes | Injects credentials (`AWS_ACCESS_KEY_ID`, `KUBECONFIG`, `AZURE_CLIENT_SECRET`) directly into child PowerShell environment blocks. |
| **In-Built Offline Copilot** | Local Support & Automation | Conversational assistant (`Ctrl+J`) for connection wizards, regex/NLP string parsing, SSH troubleshooting, and direct actions. |
| **Fuzzy Search Index** | Sub-50ms In-Memory Search | Ranks 10,000+ records in <35ms with typo tolerance, prefix matching, tag filters, and recency weighting. |
| **Encrypted Attachments** | Secure File Storage | Encrypts PEM keys, configs, and certificates into SQLite; in-memory text previewing and TTL-based extraction. |
| **TOTP Authenticator** | RFC 6238 2FA Generator | Local TOTP calculation with live countdowns and instant copy without cloud dependency. |
| **Backup & Disaster Recovery** | Automated Snapshots | Debounced snapshot creation on record mutations; configurable retention policies and instant rollback. |
| **Import / Export** | Universal Migration | Imports Bitwarden, 1Password, and KeePass CSV; exports encrypted `.keyring` or gated plaintext (120s single-use token). |

---

## 5. Architectural Constraints & Trade-Offs

When discussing future development, keep these core constraints in mind:
1. **The Zero-Network Invariant**: Under no circumstances will Keyring introduce background cloud sync, external API calls, telemetry, or remote telemetry servers. Any synchronization or multi-device feature must be strictly peer-to-peer, local-network, air-gapped, or file-based.
2. **The Client Memory Boundary**: Plaintext credentials should never linger in JavaScript memory. Decrypted values are held temporarily in Rust memory and wiped immediately with `zeroize`.
3. **No Secrets in `argv`**: Process argument inspection is trivial on all desktop operating systems. Credentials must always be communicated via environment blocks, named pipes/UNIX domain sockets, or temporary ACL-restricted files.
4. **Offline Intelligence**: Any AI, parsing, or recommendation engine must execute on-device (client-side TypeScript or embedded Rust).

---

## 6. Strategic Questions & Consultation Prompts for Claude

Below are targeted prompt templates and exploration topics you can present to Claude to explore future development paths:

### Prompt 1: Cross-Platform Parity (macOS & Linux)
> *"Keyring currently implements Windows-specific integrations (Win32 `CredWriteW`, single-use Named Pipes `\\.\pipe\*`, `IsDebuggerPresent`, and NTFS `icacls`). How should we design an idiomatic cross-platform abstraction layer in Rust (`PlatformOps`) for macOS and Linux? Specifically:
> - On macOS: How to integrate with Keychain Services, POSIX permissions, Unix Domain Sockets for `SSH_ASKPASS`, and `ptrace(PT_DENY_ATTACH)` anti-debugging?
> - On Linux: How to interface with `libsecret` / Secret Service API, Wayland vs. X11 clipboard security, and Unix Domain Sockets?"*

### Prompt 2: Native SSH Agent & GPG Agent Emulation
> *"Instead of extracting SSH private keys to temporary files on disk (even with user-only ACLs), can Keyring implement a native OpenSSH Agent (`SSH_AUTH_SOCK`) in Rust?
> - How would the Rust backend listen on a Windows Named Pipe (`\\.\pipe\openssh-ssh-agent`) or Unix socket and respond to standard `ssh-agent` protocol requests (`SSH2_AGENTC_REQUEST_IDENTITIES`, `SSH2_AGENTC_SIGN_REQUEST`)?
> - How can we enforce per-request confirmation prompts in the UI before signing?"*

### Prompt 3: Zero-Network Local & Air-Gapped Sync Models
> *"Given Keyring's non-negotiable Zero-Network invariant (no cloud servers, no third-party APIs), what are the most secure, user-friendly architectures for syncing vaults across devices?
> - Option A: Local Wi-Fi / LAN P2P sync using mDNS and authenticated TLS (pinning self-signed certificates with a shared passphrase or QR code).
> - Option B: Ephemeral Animated QR Code streaming (for moving credentials from desktop to mobile without any network interface).
> - Option C: Git-backed encrypted storage (using an encrypted bundle format where only ciphertexts are committed to a user-owned private Git repo).
> What are the cryptographic tradeoffs, conflict resolution strategies (CRDTs vs. vector clocks), and UX implications of each?"*

### Prompt 4: Embedded Local SLM / On-Device AI
> *"Keyring Copilot currently uses an offline rule-based NLP intent parser and state machine in TypeScript. How could we upgrade this to support an embedded Small Language Model (SLM) like Gemma 2B, Phi-3, or Qwen 2.5 running 100% locally on user hardware?
> - Can we run quantized GGUF models via Rust (`candle` or `llama.cpp` bindings) or via WebGPU in the webview (e.g. `web-llm` / ONNX Runtime Web)?
> - How can we maintain a sub-100MB installer footprint if an SLM is optional (e.g. downloadable on-demand model weight packs)?
> - How can we ensure prompt injection defense and sandbox the model so it can only propose actions for user approval?"*

### Prompt 5: Hardware Security Token Integration (FIDO2 / YubiKey / Windows Hello)
> *"How should Keyring incorporate hardware-backed multi-factor unlock and key wrapping?
> - Implementing FIDO2 / WebAuthn `hmac-secret` extension with YubiKey to derive a secondary salt for Argon2id key derivation.
> - Integrating Windows Hello (Biometrics / PIN) via WinRT / CNG APIs to allow rapid unvaulting while keeping master keys wrapped in TPM-backed storage."*

### Prompt 6: Headless DevOps CLI Tool (`keyring-cli`)
> *"We have an initial `keyring_cli.rs` binary. How should a full-featured developer CLI be structured to support CI/CD pipelines, local Docker scripts, and terminal power users?
> - Designing commands like `keyring run --record 'prod-aws' -- aws s3 ls` (spawning child processes with injected secrets).
> - Designing an IPC daemon mode so the CLI can query an already-unlocked desktop vault over a local pipe without re-prompting for the master password."*

---

## 7. Next-Phase Roadmap Proposal

```text
+-----------------------------------------------------------------------------------+
| v1.0 (Current Stable)                                                             |
| [x] Argon2id + XChaCha20-Poly1305 Cryptographic Engine                            |
| [x] 100% Offline Zero-Network Architecture & Verifiable Sandbox                   |
| [x] One-Click SSH Launcher (Named Pipe Askpass + NTFS ACL Key Extraction)        |
| [x] Win32 RDP CredWriteW Integration & Multi-Cloud Shells (AWS, GCP, Azure, K8s)   |
| [x] Sub-50ms Fuzzy Search Index & Global HUD Overlay (Ctrl+Shift+Space)           |
| [x] Built-in Keyring Copilot (Interactive Wizards, NLP Parsing, Troubleshooting)  |
| [x] Anti-Decompilation & Win32 Debugger Detection                                 |
+-----------------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------------+
| v1.1 (Next Milestone: Native Agent & Hardware Security)                           |
| [ ] OpenSSH Agent Emulation (in-memory signing over named pipe/socket)            |
| [ ] FIDO2 / YubiKey hmac-secret Hardware Key Derivation                           |
| [ ] Windows Hello / Touch ID Biometric Quick Unlock (TPM-backed KEK cache)        |
+-----------------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------------+
| v1.2 (Cross-Platform & CLI Ecosystem)                                             |
| [ ] macOS Platform Engine (Keychain, UNIX domain sockets, ptrace hardening)       |
| [ ] Linux Platform Engine (Secret Service API, POSIX permissions, Wayland check)  |
| [ ] Developer CLI: `keyring run --record <id> -- <command>`                       |
+-----------------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------------+
| v2.0 (Air-Gapped P2P Sync & Embedded SLM Intelligence)                            |
| [ ] Zero-Knowledge Local LAN P2P Sync (TLS with pin verification & CRDT merge)    |
| [ ] Air-gapped QR-stream vault migration                                          |
| [ ] Optional Local Quantized SLM (Gemma 2B / Candle) for advanced DevOps Copilot  |
+-----------------------------------------------------------------------------------+
```

---

<div align="center">
<sub>Authored by Piyushji001 • Keyring Open Source Project • MIT License</sub>
</div>
