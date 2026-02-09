# secrt-rs CLI Testing Notes

**Date:** 2026-02-09  
**Version:** `secrt dev`  
**Tester:** Rachel 🦊

---

## Summary

Overall the CLI is well-designed and follows good conventions. Most operations work correctly. Found a couple bugs and some UX polish opportunities.

**Note:** Initial testing was done before realizing the passphrase retry feature (b5fbf3b) was already implemented. Updated findings accordingly.

---

## 🐛 Bugs (2 remaining)

### 1. JSON claim output missing plaintext
**Severity:** Medium  
**Steps:** `./secrt claim <url> --json`  
**Expected:** JSON with plaintext and metadata  
**Actual:** Only returns `{"expires_at":"..."}` — no plaintext!
```json
{"expires_at":"2026-02-09T08:51:38.772553Z"}
```
**Impact:** Can't use JSON mode for scripted claim operations.

### 2. ~~Wrong passphrase burns the secret~~ → FIXED in b5fbf3b
**Status:** ✅ Resolved for TTY users

The CLI now auto-prompts for passphrase on TTY when claiming passphrase-protected secrets, with unlimited retries (envelope stays in memory). Non-TTY mode correctly shows error with flag suggestions.

**Verified behavior:**
- TTY: Auto-detects passphrase-protected secret, prompts, allows retries
- Non-TTY: `error: this secret is passphrase-protected; use -p, --passphrase-env, or --passphrase-file`

Great UX improvement! 👍

### 3. Redundant error messages
**Severity:** Low (polish)  
**Examples:**
- `error: decryption failed: decryption failed` (duplicate)
- `error: invalid TTL: invalid TTL: "invalid"` (duplicate)

---

## 🎨 UX/Polish Issues

### 4. `config --help` doesn't work
**Steps:** `./secrt config --help`  
**Actual:** `error: unknown config subcommand "--help" (try: init, path)`  
**Expected:** Should show help for config subcommand  
**Suggestion:** Support `--help` for all subcommands, or at least don't treat it as an unknown subcommand.

### 5. Version shows "dev" in dev builds
**Steps:** `./secrt version` or `./secrt -v`  
**Output:** `secrt dev`  
**Note:** Fine for dev, but ensure release builds show proper version (e.g., `secrt 0.1.0`).

### 6. No size limit feedback
**Finding:** Payload limit is approximately **128-175KB** (server returns 400 for larger)  
**Error:** `error: server error (400): invalid request body`  
**Suggestion:** 
- Document the limit in `--help` and README
- Better error message: "Secret too large (max ~128KB)" or similar
- Consider showing payload size in verbose mode

### 7. server error messages could be friendlier
**Examples:**
- `server error (404): not found` → "Secret not found (already claimed or expired)"
- `server error (401): unauthorized` → "Invalid or missing API key"
- `server error (400): invalid request body` → "Request failed — secret may be too large"

### 8. `--show --hidden` conflict not reported
**Steps:** `echo "test" | ./secrt create --show --hidden`  
**Result:** Silently works (--hidden wins)  
**Suggestion:** Warn about conflicting flags or document precedence.

---

## ✅ Things That Work Well

- **Round-trip encryption** — Create and claim works perfectly
- **One-time semantics** — Secrets properly deleted after claim
- **Unicode/emoji support** — Full UTF-8 works great
- **Binary files** — Raw binary round-trips correctly
- **Passphrase protection** — From env var, file, or prompt all work
- **TTL formats** — `5m`, `2h`, `1d` all parse correctly
- **Trim flag** — Properly strips whitespace
- **Pipe/stdin support** — Works as expected
- **File input** — `--file` works for any file type
- **Error messages** — Generally clear about what went wrong
- **Exit codes** — Proper non-zero for errors
- **JSON output** — Works for create (has all fields)
- **Shell completions** — bash/zsh/fish all generate properly
- **Config system** — init, path, show all work
- **Help text** — Clear, well-organized, good examples
- **Unknown command handling** — Helpful error with suggestions

---

## 📋 Suggestions

### Documentation
1. Document the payload size limit
2. Add troubleshooting section for common errors
3. Note that wrong passphrase = lost secret

### CLI Enhancements
1. Add `--verbose` flag for debugging (show request size, timing, etc.)
2. Add `--dry-run` for create (show what would be sent without sending)
3. Consider `--output` flag for claim to write directly to file
4. Add `--confirm` prompt option for create (show secret before uploading)

### Error Messages
1. De-duplicate nested error messages
2. Add context to server errors (404 = already claimed/expired)
3. Warn when passphrase decryption fails that the secret is now gone

### Passphrase Retry Feature → Already Implemented! ✅
**Commit:** b5fbf3b

The CLI already supports:
- Auto-prompting on TTY for passphrase-protected secrets
- Unlimited retries (envelope stays in memory after claim)
- Helpful error message for non-TTY with flag suggestions

**Future enhancement idea:** Add `decrypt_passphrase` to config so teams with shared passphrases can auto-decrypt without prompting. Would try config passphrase first, then fall back to interactive prompt on failure.

### JSON Mode
1. Fix claim --json to include plaintext
2. Consider `{"plaintext": "...", "expires_at": "...", "claimed_at": "..."}`

---

## Test Matrix

| Feature | Status | Notes |
|---------|--------|-------|
| Create from stdin | ✅ | |
| Create from --text | ✅ | |
| Create from --file | ✅ | |
| Create with TTL | ✅ | 5m, 2h, 1d all work |
| Create with passphrase (env) | ✅ | |
| Create with passphrase (file) | ✅ | |
| Create --json | ✅ | |
| Create --silent | ✅ | |
| Create --trim | ✅ | |
| Create large payload (~135KB) | ✅ | |
| Create huge payload (~175KB+) | ❌ | Server 400 |
| Create empty input | ✅ | Proper error |
| Create binary file | ✅ | |
| Claim basic | ✅ | |
| Claim with passphrase | ✅ | |
| Claim wrong passphrase | ✅ | TTY: retries allowed. Non-TTY: clear error |
| Claim --json | ❌ | Missing plaintext |
| Claim --silent | ✅ | |
| Claim expired/claimed | ✅ | 404 error |
| Claim malformed URL | ✅ | Proper error |
| Burn without API key | ✅ | Proper error |
| Burn with bad API key | ✅ | 401 error |
| Config show | ✅ | |
| Config init | ✅ | |
| Config init --force | ✅ | |
| Config path | ✅ | |
| Config --help | ❌ | Treated as subcommand |
| Version | ✅ | Shows "dev" |
| Help | ✅ | |
| Completions (bash/zsh/fish) | ✅ | |
| Unknown command | ✅ | Helpful error |
| Unicode/emoji | ✅ | |

---

## Environment

- **OS:** Linux (OpenClaw container on Unraid)
- **Rust:** 1.93.0
- **Server:** https://secrt.ca (production)
