use std::process::ExitCode;
use std::sync::Arc;

use secrt_server::config::Config;
use secrt_server::runtime::load_dotenv_if_present;
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use secrt_server::storage::ApiKeysStore;

enum Action {
    Revoke { prefix: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::var("ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
        let _ = load_dotenv_if_present(".env");
    }

    let args: Vec<String> = std::env::args().collect();

    // Validate all args before doing any I/O.
    let action = match parse_action(&args) {
        Some(a) => a,
        None => {
            usage();
            return ExitCode::from(2);
        }
    };

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

    match action {
        Action::Revoke { prefix } => match store.revoke_by_prefix(&prefix).await {
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
        },
    }
}

fn parse_action(args: &[String]) -> Option<Action> {
    if args.len() < 3 || args[1] != "apikey" {
        return None;
    }
    match args[2].as_str() {
        "revoke" => {
            if args.len() < 4 {
                return None;
            }
            Some(Action::Revoke {
                prefix: args[3].trim().to_string(),
            })
        }
        _ => None,
    }
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  secrt-admin apikey revoke <prefix>");
}
