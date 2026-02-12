use std::process::ExitCode;
use std::sync::Arc;

use chrono::Utc;
use secrt_server::config::Config;
use secrt_server::domain::auth::generate_api_key;
use secrt_server::runtime::load_dotenv_if_present;
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use secrt_server::storage::{ApiKeyRecord, ApiKeysStore};

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::var("ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
        let _ = load_dotenv_if_present(".env");
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "apikey" {
        usage();
        return ExitCode::from(2);
    }

    let cfg = match Config::load() {
        Ok(v) => v,
        Err(err) => {
            eprintln!("config error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let db_url = match cfg.postgres_url() {
        Ok(v) => v,
        Err(err) => {
            eprintln!("db url error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let store = match PgStore::from_database_url(&db_url).await {
        Ok(v) => Arc::new(v),
        Err(err) => {
            eprintln!("db connection error: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = migrate(store.pool()).await {
        eprintln!("migration error: {err}");
        return ExitCode::FAILURE;
    }

    match args[2].as_str() {
        "create" => {
            let scopes = if args.len() >= 4 {
                args[3].trim().to_string()
            } else {
                String::new()
            };

            if cfg.api_key_pepper.is_empty() {
                eprintln!("API_KEY_PEPPER is required to create API keys");
                return ExitCode::FAILURE;
            }

            let (api_key, prefix, hash) = match generate_api_key(&cfg.api_key_pepper) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("generate api key: {err}");
                    return ExitCode::FAILURE;
                }
            };

            let rec = ApiKeyRecord {
                id: 0,
                prefix,
                hash,
                scopes,
                created_at: Utc::now(),
                revoked_at: None,
            };

            if let Err(err) = store.insert(rec).await {
                eprintln!("insert api key: {err}");
                return ExitCode::FAILURE;
            }

            println!("{api_key}");
            ExitCode::SUCCESS
        }
        "revoke" => {
            if args.len() < 4 {
                usage();
                return ExitCode::from(2);
            }
            let prefix = args[3].trim();
            match store.revoke_by_prefix(prefix).await {
                Ok(true) => {
                    println!("revoked");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("not found or already revoked");
                    ExitCode::FAILURE
                }
                Err(err) => {
                    eprintln!("revoke api key: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  secrt-admin apikey create [scopes]");
    eprintln!("  secrt-admin apikey revoke <prefix>");
}
