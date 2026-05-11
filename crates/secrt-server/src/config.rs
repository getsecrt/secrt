use std::env;

use thiserror::Error;

/// Default for `PUBLIC_BASE_URL` when the env var is unset. Exposed so the
/// runtime bootstrap can distinguish "user supplied the default explicitly"
/// from "we fell back silently" and surface a dev-mode hint if the latter
/// would lead to a confusing WebAuthn `OriginMismatch`.
pub const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:8080";

#[derive(Clone, Debug)]
pub struct Config {
    pub env: String,
    pub listen_addr: String,
    /// Canonical origin (`scheme://host[:port]`). Always normalized in
    /// `Config::load`: default port elided, trailing slash removed, no
    /// path / query / fragment / userinfo. Use directly as the WebAuthn
    /// expected origin and as a base for share URLs.
    pub public_base_url: String,
    /// WebAuthn Relying Party ID — the host component of
    /// `public_base_url`, no scheme, no port. Pinned alongside
    /// `public_base_url` so the verifier and any logger see the same
    /// canonical bytes.
    pub rp_id: String,
    pub log_level: String,

    pub database_url: String,
    pub db_host: String,
    pub db_port: u16,
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
    pub db_sslmode: String,
    pub db_sslrootcert: String,

    pub api_key_pepper: String,
    pub session_token_pepper: String,

    pub public_max_envelope_bytes: i64,
    pub authed_max_envelope_bytes: i64,
    pub public_max_secrets: i64,
    pub public_max_total_bytes: i64,
    pub authed_max_secrets: i64,
    pub authed_max_total_bytes: i64,

    pub public_create_rate: f64,
    pub public_create_burst: usize,
    pub claim_rate: f64,
    pub claim_burst: usize,
    pub authed_create_rate: f64,
    pub authed_create_burst: usize,
    pub apikey_register_rate: f64,
    pub apikey_register_burst: usize,
    pub apikey_register_account_max_per_hour: i64,
    pub apikey_register_account_max_per_day: i64,
    pub apikey_register_ip_max_per_hour: i64,
    pub apikey_register_ip_max_per_day: i64,

    /// Per-IP rate limit for the unauthenticated passkey ceremony /start
    /// endpoints (`/auth/passkeys/register/start`, `/auth/passkeys/login/start`).
    /// Each call inserts a row into `webauthn_challenges` with a 10-minute
    /// TTL — without a limiter, an attacker can spam-fill that table.
    pub passkey_ceremony_rate: f64,
    pub passkey_ceremony_burst: usize,

    /// Per-IP rate limit shared across the six `/auth/pair/*` endpoints
    /// (start, poll, claim, challenge, approve, cancel). Tuned to absorb a
    /// realistic browser-to-browser pair UX — `/poll` alone is called every
    /// few seconds while a slot is open — without becoming a slot-flooding
    /// vector. Burst should comfortably cover one full pair round trip
    /// (~15 ops); sustained rate should cover continuous polling.
    pub web_pair_rate: f64,
    pub web_pair_burst: usize,

    /// Feature flags
    pub encrypted_notes_enabled: bool,

    /// GitHub Releases poll cadence, in seconds. `0` disables polling entirely
    /// (the task is not spawned and `/api/v1/info` returns the version fields
    /// as absent). Air-gapped self-hosters should set this to `0`.
    pub github_poll_interval_seconds: u64,
    /// `owner/repo` pair to poll for CLI release tags.
    pub github_repo: String,
    /// Optional GitHub token, used to lift the unauthenticated rate limit.
    pub github_token: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid DB_PORT '{0}'")]
    InvalidDbPort(String),
    #[error("PUBLIC_BASE_URL is required")]
    MissingPublicBaseUrl,
    #[error("invalid PUBLIC_BASE_URL")]
    InvalidPublicBaseUrl,
    #[error("PUBLIC_BASE_URL must be an origin only (scheme://host[:port]); got {component} component which is not allowed")]
    PublicBaseUrlNotOrigin { component: &'static str },
    #[error("PUBLIC_BASE_URL scheme must be http or https; got '{0}'")]
    PublicBaseUrlBadScheme(String),
    #[error("API_KEY_PEPPER is required in production")]
    MissingApiKeyPepper,
    #[error("SESSION_TOKEN_PEPPER is required in production")]
    MissingSessionTokenPepper,
    #[error("missing env vars: {0}")]
    MissingEnvVars(String),
}

/// Result of canonicalizing a raw `PUBLIC_BASE_URL` to the
/// `scheme://host[:port]` form WebAuthn expects.
struct CanonicalBaseUrl {
    /// `scheme://host[:port]` with default ports elided (`:443` for
    /// https, `:80` for http), no trailing slash, no path, no userinfo,
    /// no query, no fragment.
    pub origin: String,
    /// Host component only (`host_str()`), used as the WebAuthn RP ID.
    pub host: String,
}

/// Parse and canonicalize a `PUBLIC_BASE_URL` value. Rejects anything
/// outside the `scheme://host[:port]` form with a specific error so
/// operators can fix the misconfiguration immediately instead of
/// debugging a downstream `OriginMismatch` or RP-ID-hash mismatch.
fn canonicalize_public_base_url(raw: &str) -> Result<CanonicalBaseUrl, ConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::MissingPublicBaseUrl);
    }

    let parsed = url::Url::parse(trimmed).map_err(|_| ConfigError::InvalidPublicBaseUrl)?;

    // WebAuthn ceremonies and the share-URL generator both assume
    // origin-only inputs. Reject any extra structure explicitly so the
    // operator gets an actionable error rather than a runtime symptom.
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ConfigError::PublicBaseUrlBadScheme(scheme.to_string()));
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(ConfigError::PublicBaseUrlNotOrigin { component: "path" });
    }
    if parsed.query().is_some() {
        return Err(ConfigError::PublicBaseUrlNotOrigin { component: "query" });
    }
    if parsed.fragment().is_some() {
        return Err(ConfigError::PublicBaseUrlNotOrigin {
            component: "fragment",
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::PublicBaseUrlNotOrigin {
            component: "userinfo",
        });
    }
    let host = parsed
        .host_str()
        .ok_or(ConfigError::InvalidPublicBaseUrl)?
        .to_string();

    // Rebuild canonical form. `url::Url::origin().ascii_serialization()`
    // gives us the WHATWG-canonical tuple origin, which is exactly what
    // browsers put in `clientDataJSON.origin` — default ports elided,
    // no trailing slash, case-folded scheme/host.
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return Err(ConfigError::InvalidPublicBaseUrl);
    }

    Ok(CanonicalBaseUrl { origin, host })
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let env_name = getenv_default("ENV", "development");

        let db_port_raw = getenv_default("DB_PORT", "5432");
        let db_port = db_port_raw
            .trim()
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidDbPort(db_port_raw.clone()))?;
        if db_port == 0 {
            return Err(ConfigError::InvalidDbPort(db_port_raw));
        }

        let raw_public_base_url = getenv_default("PUBLIC_BASE_URL", DEFAULT_PUBLIC_BASE_URL);
        let canonical = canonicalize_public_base_url(&raw_public_base_url)?;
        let public_base_url = canonical.origin;
        let rp_id = canonical.host;

        let api_key_pepper = env::var("API_KEY_PEPPER")
            .unwrap_or_default()
            .trim()
            .to_string();
        if env_name == "production" && api_key_pepper.is_empty() {
            return Err(ConfigError::MissingApiKeyPepper);
        }
        let session_token_pepper = env::var("SESSION_TOKEN_PEPPER")
            .unwrap_or_default()
            .trim()
            .to_string();
        if env_name == "production" && session_token_pepper.is_empty() {
            return Err(ConfigError::MissingSessionTokenPepper);
        }

        Ok(Self {
            env: env_name,
            listen_addr: getenv_default("LISTEN_ADDR", ":8080"),
            public_base_url,
            rp_id,
            log_level: getenv_default("LOG_LEVEL", "info"),

            database_url: env::var("DATABASE_URL")
                .unwrap_or_default()
                .trim()
                .to_string(),
            db_host: getenv_default("DB_HOST", "127.0.0.1"),
            db_port,
            db_name: getenv_default("DB_NAME", "secrt"),
            db_user: getenv_default("DB_USER", "secrt_app"),
            db_password: env::var("DB_PASSWORD").unwrap_or_default(),
            db_sslmode: getenv_default("DB_SSLMODE", "disable"),
            db_sslrootcert: env::var("DB_SSLROOTCERT")
                .unwrap_or_default()
                .trim()
                .to_string(),

            api_key_pepper,
            session_token_pepper,

            public_max_envelope_bytes: getenv_i64_default("PUBLIC_MAX_ENVELOPE_BYTES", 256 * 1024),
            authed_max_envelope_bytes: getenv_i64_default("AUTHED_MAX_ENVELOPE_BYTES", 1024 * 1024),
            public_max_secrets: getenv_i64_default("PUBLIC_MAX_SECRETS", 10),
            public_max_total_bytes: getenv_i64_default("PUBLIC_MAX_TOTAL_BYTES", 2 * 1024 * 1024),
            authed_max_secrets: getenv_i64_default("AUTHED_MAX_SECRETS", 1000),
            authed_max_total_bytes: getenv_i64_default("AUTHED_MAX_TOTAL_BYTES", 20 * 1024 * 1024),

            public_create_rate: getenv_f64_default("PUBLIC_CREATE_RATE", 0.5),
            public_create_burst: getenv_usize_default("PUBLIC_CREATE_BURST", 6),
            claim_rate: getenv_f64_default("CLAIM_RATE", 1.0),
            claim_burst: getenv_usize_default("CLAIM_BURST", 10),
            authed_create_rate: getenv_f64_default("AUTHED_CREATE_RATE", 2.0),
            authed_create_burst: getenv_usize_default("AUTHED_CREATE_BURST", 20),
            apikey_register_rate: getenv_f64_default("APIKEY_REGISTER_RATE", 0.5),
            apikey_register_burst: getenv_usize_default("APIKEY_REGISTER_BURST", 6),
            apikey_register_account_max_per_hour: getenv_i64_default(
                "APIKEY_REGISTER_ACCOUNT_MAX_PER_HOUR",
                5,
            ),
            apikey_register_account_max_per_day: getenv_i64_default(
                "APIKEY_REGISTER_ACCOUNT_MAX_PER_DAY",
                20,
            ),
            apikey_register_ip_max_per_hour: getenv_i64_default(
                "APIKEY_REGISTER_IP_MAX_PER_HOUR",
                5,
            ),
            apikey_register_ip_max_per_day: getenv_i64_default(
                "APIKEY_REGISTER_IP_MAX_PER_DAY",
                20,
            ),

            // 0.5 rps with burst 6 → ~30/min sustained per IP, plenty for a
            // legitimate user fumbling the picker, tight enough to make the
            // challenges-table fill attack uneconomical.
            passkey_ceremony_rate: getenv_f64_default("PASSKEY_CEREMONY_RATE", 0.5),
            passkey_ceremony_burst: getenv_usize_default("PASSKEY_CEREMONY_BURST", 6),

            // Pair endpoints are session-authenticated and rely on /poll
            // every few seconds while a slot is open. 2 rps + burst 30
            // accommodates one round trip (~15 ops in a tight cluster) and
            // continuous polling at ~500ms cadence indefinitely, while
            // still bounding slot-creation abuse.
            web_pair_rate: getenv_f64_default("WEB_PAIR_RATE", 2.0),
            web_pair_burst: getenv_usize_default("WEB_PAIR_BURST", 30),

            encrypted_notes_enabled: getenv_bool_default("ENCRYPTED_NOTES_ENABLED", true),

            github_poll_interval_seconds: getenv_u64_default("GITHUB_POLL_INTERVAL_SECONDS", 3600),
            github_repo: getenv_default("GITHUB_REPO", "getsecrt/secrt"),
            github_token: env::var("GITHUB_TOKEN")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        })
    }

    pub fn postgres_url(&self) -> Result<String, ConfigError> {
        if !self.database_url.is_empty() {
            return Ok(self.database_url.clone());
        }

        let mut missing = Vec::new();
        if self.db_host.is_empty() {
            missing.push("DB_HOST");
        }
        if self.db_name.is_empty() {
            missing.push("DB_NAME");
        }
        if self.db_user.is_empty() {
            missing.push("DB_USER");
        }
        if self.db_sslmode.is_empty() {
            missing.push("DB_SSLMODE");
        }
        if !missing.is_empty() {
            return Err(ConfigError::MissingEnvVars(missing.join(", ")));
        }

        let mut url = format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            urlencoding::encode(&self.db_user),
            urlencoding::encode(&self.db_password),
            self.db_host,
            self.db_port,
            self.db_name,
            self.db_sslmode
        );
        if !self.db_sslrootcert.is_empty() {
            url.push_str("&sslrootcert=");
            url.push_str(&urlencoding::encode(&self.db_sslrootcert));
        }
        Ok(url)
    }
}

fn getenv_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn getenv_i64_default(key: &str, default: i64) -> i64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

fn getenv_f64_default(key: &str, default: f64) -> f64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(default)
}

fn getenv_usize_default(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn getenv_u64_default(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn getenv_bool_default(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let old = env::var(key).ok();
            env::set_var(key, value);
            Self { key, old }
        }

        fn clear(key: &'static str) -> Self {
            let old = env::var(key).ok();
            env::remove_var(key);
            Self { key, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.old {
                env::set_var(self.key, v);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    fn clear_all() -> Vec<EnvGuard> {
        vec![
            EnvGuard::clear("ENV"),
            EnvGuard::clear("LISTEN_ADDR"),
            EnvGuard::clear("PUBLIC_BASE_URL"),
            EnvGuard::clear("LOG_LEVEL"),
            EnvGuard::clear("DATABASE_URL"),
            EnvGuard::clear("DB_HOST"),
            EnvGuard::clear("DB_PORT"),
            EnvGuard::clear("DB_NAME"),
            EnvGuard::clear("DB_USER"),
            EnvGuard::clear("DB_PASSWORD"),
            EnvGuard::clear("DB_SSLMODE"),
            EnvGuard::clear("DB_SSLROOTCERT"),
            EnvGuard::clear("API_KEY_PEPPER"),
            EnvGuard::clear("SESSION_TOKEN_PEPPER"),
        ]
    }

    #[test]
    fn default_and_postgres_url() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = clear_all();
        let cfg = Config::load().unwrap();
        let u = cfg.postgres_url().unwrap();
        assert!(u.starts_with("postgres://") || !cfg.database_url.is_empty());
    }

    #[test]
    fn invalid_db_port() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [EnvGuard::set("DB_PORT", "nope")];
        assert!(matches!(Config::load(), Err(ConfigError::InvalidDbPort(_))));
    }

    #[test]
    fn invalid_db_port_zero() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [EnvGuard::set("DB_PORT", "0")];
        assert!(matches!(Config::load(), Err(ConfigError::InvalidDbPort(_))));
    }

    #[test]
    fn invalid_public_base_url() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [EnvGuard::set("PUBLIC_BASE_URL", "://bad-url")];
        assert!(matches!(
            Config::load(),
            Err(ConfigError::InvalidPublicBaseUrl)
        ));
    }

    #[test]
    fn public_base_url_canonicalized_to_origin_form() {
        // `Url::origin().ascii_serialization()` matches what browsers put
        // in clientDataJSON.origin — default ports elided, no trailing
        // slash, lowercase scheme/host.
        for (raw, expected_origin, expected_rp_id) in [
            (
                "http://localhost:5173",
                "http://localhost:5173",
                "localhost",
            ),
            ("https://secrt.is", "https://secrt.is", "secrt.is"),
            // Trailing slash gets stripped.
            ("https://secrt.is/", "https://secrt.is", "secrt.is"),
            // Default ports elided.
            ("https://secrt.is:443", "https://secrt.is", "secrt.is"),
            ("http://localhost:80", "http://localhost", "localhost"),
            // Case-folded scheme/host.
            ("HTTPS://SECRT.IS", "https://secrt.is", "secrt.is"),
        ] {
            let _lock = ENV_LOCK.lock().expect("env lock");
            let _guards = [EnvGuard::set("PUBLIC_BASE_URL", raw)];
            let cfg = Config::load().unwrap_or_else(|err| panic!("expected {raw} to load: {err}"));
            assert_eq!(cfg.public_base_url, expected_origin, "raw={raw}");
            assert_eq!(cfg.rp_id, expected_rp_id, "raw={raw}");
        }
    }

    #[test]
    fn public_base_url_rejects_non_origin_components() {
        for (raw, reason) in [
            ("https://secrt.is/some/path", "path"),
            ("https://secrt.is?x=1", "query"),
            ("https://secrt.is#frag", "fragment"),
            ("https://user:pass@secrt.is", "userinfo"),
        ] {
            let _lock = ENV_LOCK.lock().expect("env lock");
            let _guards = [EnvGuard::set("PUBLIC_BASE_URL", raw)];
            match Config::load() {
                Err(ConfigError::PublicBaseUrlNotOrigin { component }) => {
                    assert_eq!(component, reason, "raw={raw}");
                }
                other => panic!("expected NotOrigin({reason}) for {raw}, got {other:?}"),
            }
        }
    }

    #[test]
    fn public_base_url_rejects_non_http_scheme() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [EnvGuard::set("PUBLIC_BASE_URL", "ftp://secrt.is")];
        match Config::load() {
            Err(ConfigError::PublicBaseUrlBadScheme(s)) => assert_eq!(s, "ftp"),
            other => panic!("expected BadScheme, got {other:?}"),
        }
    }

    #[test]
    fn missing_public_base_url() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [EnvGuard::set("PUBLIC_BASE_URL", "")];
        assert!(matches!(
            Config::load(),
            Err(ConfigError::MissingPublicBaseUrl)
        ));
    }

    #[test]
    fn production_requires_pepper() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [
            EnvGuard::set("ENV", "production"),
            EnvGuard::clear("API_KEY_PEPPER"),
            EnvGuard::set("SESSION_TOKEN_PEPPER", "ok"),
        ];
        assert!(matches!(
            Config::load(),
            Err(ConfigError::MissingApiKeyPepper)
        ));
    }

    #[test]
    fn production_requires_session_pepper() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [
            EnvGuard::set("ENV", "production"),
            EnvGuard::set("API_KEY_PEPPER", "ok"),
            EnvGuard::clear("SESSION_TOKEN_PEPPER"),
        ];
        assert!(matches!(
            Config::load(),
            Err(ConfigError::MissingSessionTokenPepper)
        ));
    }

    #[test]
    fn postgres_url_prefers_database_url() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [EnvGuard::set("DATABASE_URL", "postgres://localhost/custom")];
        let cfg = Config::load().expect("load config");
        assert_eq!(
            cfg.postgres_url().expect("postgres url"),
            "postgres://localhost/custom"
        );
    }

    #[test]
    fn postgres_url_missing_parts_errors() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [
            EnvGuard::clear("DATABASE_URL"),
            EnvGuard::set("DB_HOST", ""),
            EnvGuard::set("DB_NAME", ""),
            EnvGuard::set("DB_USER", ""),
            EnvGuard::set("DB_SSLMODE", ""),
        ];
        let cfg = Config::load().expect("load config");
        assert!(matches!(
            cfg.postgres_url(),
            Err(ConfigError::MissingEnvVars(_))
        ));
    }

    #[test]
    fn postgres_url_includes_sslrootcert_when_set() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _guards = [
            EnvGuard::clear("DATABASE_URL"),
            EnvGuard::set("DB_HOST", "localhost"),
            EnvGuard::set("DB_NAME", "secrt"),
            EnvGuard::set("DB_USER", "secrt"),
            EnvGuard::set("DB_SSLMODE", "verify-full"),
            EnvGuard::set("DB_SSLROOTCERT", "/tmp/ca.pem"),
        ];
        let cfg = Config::load().expect("load config");
        let url = cfg.postgres_url().expect("postgres url");
        assert!(url.contains("sslrootcert="));
    }

    #[test]
    fn env_guard_restores_previous_value() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        env::set_var("SECRT_TEMP_RESTORE", "before");
        {
            let _guard = EnvGuard::set("SECRT_TEMP_RESTORE", "during");
            assert_eq!(
                env::var("SECRT_TEMP_RESTORE").ok().as_deref(),
                Some("during")
            );
        }
        assert_eq!(
            env::var("SECRT_TEMP_RESTORE").ok().as_deref(),
            Some("before")
        );
        env::remove_var("SECRT_TEMP_RESTORE");
    }
}
