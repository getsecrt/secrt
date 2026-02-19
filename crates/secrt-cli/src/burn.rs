use std::io::Write;

use crate::cli::{parse_flags, print_burn_help, resolve_globals, CliError, Deps};
use crate::client::SecretApi;
use crate::color::{color_func, SUCCESS};
use crate::envelope;
use crate::passphrase::write_error;

/// Strip a trailing ellipsis character (U+2026 `…`) and anything after it.
/// This handles the common case of copying a truncated ID from `secrt list`.
fn strip_ellipsis(id: &str) -> &str {
    match id.find('\u{2026}') {
        Some(pos) => &id[..pos],
        None => id,
    }
}

/// Resolve a possibly-partial secret ID to a full ID using the list endpoint.
/// Returns `Ok(full_id)` on unique match, or an error message otherwise.
fn resolve_prefix(client: &dyn SecretApi, prefix: &str) -> Result<String, String> {
    // Fetch all secrets (up to a generous limit)
    let resp = client.list(Some(20_000), None)?;

    let matches: Vec<&str> = resp
        .secrets
        .iter()
        .filter(|s| s.id.starts_with(prefix))
        .map(|s| s.id.as_str())
        .collect();

    match matches.len() {
        0 => Err(format!("no secret matching prefix '{}'", prefix)),
        1 => Ok(matches[0].to_string()),
        n => Err(format!(
            "prefix '{}' is ambiguous ({} matches); use more characters",
            prefix, n
        )),
    }
}

pub fn run_burn(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_burn_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    if pa.args.is_empty() {
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            "secret ID prefix or share URL is required",
        );
        return 2;
    }

    if pa.api_key.is_empty() {
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            "--api-key is required for burn",
        );
        return 2;
    }

    // Extract ID: might be a share URL or bare ID
    let id_or_url = &pa.args[0];
    let mut secret_id = strip_ellipsis(id_or_url).to_string();
    let mut base_url = pa.base_url.clone();

    if id_or_url.contains('/') || id_or_url.contains('#') {
        match envelope::parse_share_url(id_or_url) {
            Ok((id, _)) => {
                secret_id = id;
                // Derive base URL from share URL if not explicitly set via flag/env
                if !pa.base_url_from_flag
                    && (deps.getenv)("SECRET_BASE_URL").is_none()
                    && id_or_url.contains("://")
                {
                    if let Some(scheme_end) = id_or_url.find("://") {
                        let after_scheme = &id_or_url[scheme_end + 3..];
                        if let Some(path_start) = after_scheme.find('/') {
                            base_url = id_or_url[..scheme_end + 3 + path_start].to_string();
                        }
                    }
                }
            }
            Err(e) => {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    (deps.is_tty)(),
                    &format!("invalid URL: {}", e),
                );
                return 2;
            }
        }
    }

    let client = (deps.make_api)(&base_url, &pa.api_key);

    // Try exact ID first; on 404, attempt prefix resolution
    match client.burn(&secret_id) {
        Ok(()) => {}
        Err(e) if e.contains("404") => {
            // Might be a prefix — resolve via list
            match resolve_prefix(client.as_ref(), &secret_id) {
                Ok(full_id) => {
                    if let Err(e2) = client.burn(&full_id) {
                        write_error(
                            &mut deps.stderr,
                            pa.json,
                            (deps.is_tty)(),
                            &format!("burn failed: {}", e2),
                        );
                        return 1;
                    }
                }
                Err(resolve_err) => {
                    write_error(
                        &mut deps.stderr,
                        pa.json,
                        (deps.is_tty)(),
                        &format!("burn failed: {}", resolve_err),
                    );
                    return 1;
                }
            }
        }
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("burn failed: {}", e),
            );
            return 1;
        }
    }

    if pa.json {
        let _ = writeln!(
            deps.stdout,
            "{}",
            serde_json::to_string(&serde_json::json!({"ok": true})).unwrap()
        );
    } else if (deps.is_tty)() && !pa.silent {
        let c = color_func(true);
        let _ = writeln!(deps.stderr, "{} Secret burned.", c(SUCCESS, "\u{2713}"));
    } else if !pa.silent {
        let _ = writeln!(deps.stderr, "Secret burned.");
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{
        ClaimResponse, CreateRequest, CreateResponse, InfoResponse, ListSecretsResponse,
        SecretMetadataItem,
    };

    #[test]
    fn strip_ellipsis_no_ellipsis() {
        assert_eq!(strip_ellipsis("abc123"), "abc123");
    }

    #[test]
    fn strip_ellipsis_trailing() {
        assert_eq!(strip_ellipsis("abc123\u{2026}"), "abc123");
    }

    #[test]
    fn strip_ellipsis_with_trailing_text() {
        assert_eq!(strip_ellipsis("abc123\u{2026}  extra"), "abc123");
    }

    #[test]
    fn strip_ellipsis_empty() {
        assert_eq!(strip_ellipsis(""), "");
    }

    /// Minimal mock that only implements `list` for testing `resolve_prefix`.
    struct ListOnlyApi {
        secrets: Vec<SecretMetadataItem>,
    }

    impl SecretApi for ListOnlyApi {
        fn create(&self, _: CreateRequest) -> Result<CreateResponse, String> {
            unimplemented!()
        }
        fn claim(&self, _: &str, _: &[u8]) -> Result<ClaimResponse, String> {
            unimplemented!()
        }
        fn burn(&self, _: &str) -> Result<(), String> {
            unimplemented!()
        }
        fn info(&self) -> Result<InfoResponse, String> {
            unimplemented!()
        }
        fn list(&self, _: Option<i64>, _: Option<i64>) -> Result<ListSecretsResponse, String> {
            Ok(ListSecretsResponse {
                secrets: self.secrets.clone(),
                total: self.secrets.len() as i64,
                limit: 50,
                offset: 0,
            })
        }
    }

    fn item(id: &str) -> SecretMetadataItem {
        SecretMetadataItem {
            id: id.into(),
            share_url: format!("https://x/s/{id}"),
            expires_at: "2099-12-31T23:59:59Z".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            ciphertext_size: 100,
            passphrase_protected: false,
            enc_meta: None,
        }
    }

    #[test]
    fn resolve_prefix_unique_match() {
        let api = ListOnlyApi {
            secrets: vec![item("abcdef123456"), item("xyz789000000")],
        };
        assert_eq!(resolve_prefix(&api, "abc").unwrap(), "abcdef123456");
    }

    #[test]
    fn resolve_prefix_no_match() {
        let api = ListOnlyApi {
            secrets: vec![item("abcdef123456")],
        };
        let err = resolve_prefix(&api, "zzz").unwrap_err();
        assert!(err.contains("no secret matching"), "{}", err);
    }

    #[test]
    fn resolve_prefix_ambiguous() {
        let api = ListOnlyApi {
            secrets: vec![item("abc111"), item("abc222")],
        };
        let err = resolve_prefix(&api, "abc").unwrap_err();
        assert!(err.contains("ambiguous"), "{}", err);
        assert!(err.contains("2 matches"), "{}", err);
    }

    #[test]
    fn resolve_prefix_exact_match_among_similar() {
        let api = ListOnlyApi {
            secrets: vec![item("abc"), item("abcdef")],
        };
        // "abc" is a prefix of both, so it's ambiguous
        let err = resolve_prefix(&api, "abc").unwrap_err();
        assert!(err.contains("ambiguous"), "{}", err);
        // But "abcd" uniquely matches "abcdef"
        assert_eq!(resolve_prefix(&api, "abcd").unwrap(), "abcdef");
    }
}
