# Tauri Desktop App Plan

## Motivation

- **Signed binary = trust** — For a security tool, a signed desktop app is a major credibility signal vs "visit this website"
- **Native platform integrations** — Several features that are awkward or impossible in a browser
- **CLI feature parity** — Bring CLI capabilities into a GUI with better UX

## Architecture

Tauri v2 wrapping the existing web UI. The web frontend is already polished and works as a PWA, so minimal frontend changes needed. Add a Rust backend layer for native integrations.

Since secrt already has a Rust codebase (`secrt-core`, `secrt-cli`), the Tauri backend can potentially reuse `secrt-core` directly for crypto operations — running encryption/decryption natively instead of in WASM/JS.

## Feature Plan

### Phase 1: Basic Wrapper
- [ ] Scaffold Tauri v2 project pointing at existing web UI
- [ ] App icons, window config, metadata
- [ ] macOS + Windows + Linux builds
- [ ] Code signing (macOS notarization, Windows Authenticode)
- [ ] GitHub Actions CI for cross-platform builds
- [ ] Auto-updater (Tauri built-in)

### Phase 2: Native Integrations
- [ ] **Clipboard auto-clear** — Configurable timer (default 30s?) to wipe clipboard after copying a secret. User-configurable duration in settings.
- [ ] **Native file dialogs** — Open/save dialogs for file encryption, no browser download folder dance
- [ ] **Drag & drop** — Drop files onto app window or dock icon to encrypt
- [ ] **System notifications** — "Secret expires in 1 hour", "Clipboard cleared"
- [ ] **Deep links** — Register `secrt://` URL protocol so clicking secrt links opens the app

### Phase 3: Settings & Configuration
- [ ] **Settings UI** — Persistent app settings (stored via Tauri's config/store plugin)
- [ ] **Login / authentication** — Save session for self-hosted instances
- [ ] **Default passphrase** — Store default decryption passphrase in OS keychain (via Tauri stronghold or keyring plugin)
- [ ] **Auto-encrypt passphrase** — Option to automatically apply a keychain-stored passphrase when creating secrets
- [ ] **Custom host** — Configure the app to point at a self-hosted secrt server instead of secrt.ca
- [ ] **Clipboard auto-clear duration** — Configurable: off / 15s / 30s / 60s / custom

### Phase 4: CLI Feature Parity
- [ ] **Native crypto via secrt-core** — Use the Rust crate directly instead of JS/WASM for encryption/decryption (faster, no WASM overhead)
- [ ] **File encryption** — Encrypt/decrypt files with streaming (no browser memory limits)
- [ ] **Batch operations** — Multiple secrets at once
- [ ] **History/audit log** — Local log of secrets created (metadata only, never plaintext)

## Platform-Specific Notes

### macOS
- Notarization required for Gatekeeper
- Keychain integration for passphrase storage
- Dock icon drag & drop

### Windows
- Authenticode signing
- Windows Credential Manager for passphrase storage
- System tray option

### Linux
- AppImage or .deb/.rpm
- Secret Service API (GNOME Keyring / KWallet) for passphrase storage

## Ideas & Considerations

- **QR code on success screen** — Show QR code for the share link on the web UI success page too (not just desktop). Enables the "hey Bob, scan this" in-person sharing flow — scan with phone, drop into password manager. No copy-paste, no sending links over insecure channels.
- **Offline mode** — With native crypto, the app could create encrypted payloads offline and upload when connectivity returns
- **Biometric unlock** — Use Touch ID / Windows Hello to unlock stored passphrases
- **CLI integration** — Could the desktop app and CLI share config? Same keychain entries?
- **Tray mode** — Minimize to system tray, always ready for quick secret creation (global hotkey?)

## Technical Notes

- Tauri v2 uses Rust backend + system webview (WebKit on macOS, WebView2 on Windows, WebKitGTK on Linux)
- Existing crates (`secrt-core`) can be called directly from Tauri commands — no FFI needed, it's all Rust
- Frontend stays the same web code, with Tauri JS API calls for native features
- Bundle size should be small (no Electron/Chromium — just the app code)
