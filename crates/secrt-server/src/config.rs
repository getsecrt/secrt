use std::env;

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub env: String,
    pub listen_addr: String,
    pub public_base_url: String,
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

    /// Feature flags
    pub encrypted_notes_enabled: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid DB_PORT '{0}'")]
    InvalidDbPort(String),
    #[error("PUBLIC_BASE_URL is required")]
    MissingPublicBaseUrl,
    #[error("invalid PUBLIC_BASE_URL")]
    InvalidPublicBaseUrl,
    #[error("API_KEY_PEPPER is required in production")]
    MissingApiKeyPepper,
    #[error("SESSION_TOKEN_PEPPER is required in production")]
    MissingSessionTokenPepper,
    #[error("missing env vars: {0}")]
    MissingEnvVars(String),
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

        let public_base_url = getenv_default("PUBLIC_BASE_URL", "http://localhost:8080")
            .trim_end_matches('/')
            .to_string();
        if public_base_url.is_empty() {
            return Err(ConfigError::MissingPublicBaseUrl);
        }
        if url::Url::parse(&public_base_url).is_err() {
            return Err(ConfigError::InvalidPublicBaseUrl);
        }

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

            encrypted_notes_enabled: getenv_bool_default("ENCRYPTED_NOTES_ENABLED", false),
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
