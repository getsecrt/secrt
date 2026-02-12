# secrt-cli CLI Testing Notes

**Date:** 2026-02-09  
**Version:** `secrt dev`  
**Tester:** Rachel 🦊

---

## Summary

Comprehensive CLI testing session. Found several issues, **fixed 4 of them** with tests, and documented remaining opportunities.

**Session results:**
- 🐛 **4 bugs fixed** (JSON plaintext, error duplication, config help, passphrase retry already done)
- ✅ **6 new tests added** (257 total, was 251)
- 📝 **4 polish items remaining** (non-critical)

---

## 🐛 Bugs Fixed This Session

### 1. JSON claim output missing plaintext → FIXED in 8fc99d8
JSON claim now includes `plaintext` field:
```json
{"expires_at":"...","plaintext":"the secret"}
```
Added tests for unicode and binary data handling.

### 2. Passphrase retry on wrong password → Already FIXED in b5fbf3b
TTY users get unlimited retries (envelope stays in memory). Non-TTY gets helpful error with flag suggestions.

### 3. Redundant error messages → FIXED in 5d52ea6
- Before: `error: decryption failed: decryption failed`
- After: `error: decryption failed`

### 4. `config --help` treated as unknown → FIXED in f7e9425
Both `secrt config --help` and `secrt help config` now work.

---

## 📋 Remaining Polish (Non-Critical)

### 1. Version shows "dev" in dev builds
`./secrt version` → `secrt dev`  
**Status:** Expected for dev builds. Ensure release builds show proper version.

### 2. Payload size limit not documented
Limit is ~128-175KB. Server returns generic `400: invalid request body`.  
**Suggestion:** Document limit in README, improve error message.

### 3. Some server errors could be friendlier
- `401: unauthorized` → "Invalid or missing API key"

**Note:** The `404: not found` response is intentionally opaque — revealing "already claimed" vs "expired" vs "never existed" would leak information to attackers probing the system. Keep it vague.

### 4. `--show --hidden` conflict silent
Conflicting flags silently resolve (--hidden wins).  
**Suggestion:** Warn or document precedence.

---

## 🚀 Future Enhancement Ideas

1. **`decrypt_passphrase` config option** — Auto-try this passphrase on claim, fall back to prompt on failure. Good for teams with shared passphrases.

2. **`--verbose` flag** — Show request size, timing, debug info.

3. **`--output <file>` for claim** — Write directly to file instead of stdout.

4. **Friendlier auth errors** — `401` could say "Invalid or missing API key" (but keep `404` opaque for security).

---

## ✅ Test Matrix (Updated)

| Feature | Status | Notes |
|---------|--------|-------|
| Create from stdin | ✅ | |
| Create from --text | ✅ | |
| Create from --file | ✅ | |
| Create with TTL | ✅ | 5m, 2h, 1d all work |
| Create with passphrase | ✅ | env, file, prompt |
| Create --json | ✅ | |
| Create --silent | ✅ | |
| Create --trim | ✅ | |
| Create large (~135KB) | ✅ | |
| Create huge (~175KB+) | ⚠️ | Server 400 (expected) |
| Create binary file | ✅ | |
| Claim basic | ✅ | |
| Claim with passphrase | ✅ | |
| Claim wrong passphrase | ✅ | TTY retries, non-TTY clear error |
| Claim --json | ✅ | **Fixed** — includes plaintext |
| Claim --json unicode | ✅ | **New test** |
| Claim --json binary | ✅ | **New test** — lossy UTF-8 |
| Claim --silent | ✅ | |
| Burn | ✅ | All paths tested |
| Config show | ✅ | |
| Config init | ✅ | |
| Config --help | ✅ | **Fixed** |
| Help config | ✅ | **Fixed** |
| Version | ✅ | |
| Completions | ✅ | bash/zsh/fish |
| Error messages | ✅ | **Fixed** — no duplication |

---

## Commits This Session

| Commit | Description |
|--------|-------------|
| `58694c3` | Initial CLI testing notes |
| `b510adb` | Updated notes (passphrase retry already implemented) |
| `8fc99d8` | **Fix:** JSON claim includes plaintext |
| `5d52ea6` | **Fix:** Remove redundant error prefixes |
| `f7e9425` | **Add:** config --help and help config |
| `90670a3` | **Add:** Tests for JSON unicode/binary |
| `14c4163` | Updated test coverage doc |

---

## Environment

- **OS:** Linux (OpenClaw container on Unraid)
- **Rust:** 1.93.0
- **Server:** https://secrt.ca (production)
- **Tests:** 257 passing, 6 E2E ignored
