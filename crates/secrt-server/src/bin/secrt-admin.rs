use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;

use chrono::Utc;

use secrt_server::config::Config;
use secrt_server::runtime::load_dotenv_if_present;
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use secrt_server::storage::{AdminStore, ApiKeysStore, UserId};

/// Default path for the server's environment file (systemd `EnvironmentFile=`).
const DEFAULT_ENV_FILE: &str = "/etc/secrt-server/env";

// ── Action types ─────────────────────────────────────────────────────

enum Action {
    ApikeyRevoke { prefix: String },
    Stats,
    SecretStats,
    UsersList { limit: i64 },
    UsersShow { user_id: String },
    ApikeysList { user_id: Option<String>, limit: i64 },
    TopUsers { by: TopUsersBy, limit: i64 },
}

#[derive(Clone, Copy)]
enum TopUsersBy {
    Secrets,
    Bytes,
    Keys,
}

// ── Arg parsing ──────────────────────────────────────────────────────

fn parse_flag_i64(args: &[String], flag: &str, default: i64) -> i64 {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == flag {
            if let Ok(v) = args[i + 1].parse::<i64>() {
                return v;
            }
        }
    }
    default
}

fn parse_flag_str<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == flag {
            return Some(&args[i + 1]);
        }
    }
    None
}

fn parse_action(args: &[String]) -> Option<Action> {
    if args.len() < 2 {
        return None;
    }

    match args[1].as_str() {
        "stats" => Some(Action::Stats),
        "secrets" => {
            if args.len() >= 3 && args[2] == "stats" {
                Some(Action::SecretStats)
            } else {
                None
            }
        }
        "users" => {
            if args.len() < 3 {
                return None;
            }
            match args[2].as_str() {
                "list" => Some(Action::UsersList {
                    limit: parse_flag_i64(args, "--limit", 50),
                }),
                "show" => {
                    if args.len() < 4 {
                        return None;
                    }
                    Some(Action::UsersShow {
                        user_id: args[3].clone(),
                    })
                }
                _ => None,
            }
        }
        "apikey" | "apikeys" => {
            if args.len() < 3 {
                return None;
            }
            match args[2].as_str() {
                "revoke" => {
                    if args.len() < 4 {
                        return None;
                    }
                    Some(Action::ApikeyRevoke {
                        prefix: args[3].trim().to_string(),
                    })
                }
                "list" => Some(Action::ApikeysList {
                    user_id: parse_flag_str(args, "--user").map(String::from),
                    limit: parse_flag_i64(args, "--limit", 50),
                }),
                _ => None,
            }
        }
        "top-users" => {
            let by = match parse_flag_str(args, "--by") {
                Some("bytes") => TopUsersBy::Bytes,
                Some("keys") => TopUsersBy::Keys,
                _ => TopUsersBy::Secrets,
            };
            Some(Action::TopUsers {
                by,
                limit: parse_flag_i64(args, "--limit", 10),
            })
        }
        _ => None,
    }
}

// ── Formatting helpers ───────────────────────────────────────────────

fn human_bytes(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

struct Color {
    bold: &'static str,
    dim: &'static str,
    green: &'static str,
    yellow: &'static str,
    red: &'static str,
    cyan: &'static str,
    reset: &'static str,
}

const COLOR_ON: Color = Color {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    red: "\x1b[31m",
    cyan: "\x1b[36m",
    reset: "\x1b[0m",
};

const COLOR_OFF: Color = Color {
    bold: "",
    dim: "",
    green: "",
    yellow: "",
    red: "",
    cyan: "",
    reset: "",
};

fn colors() -> &'static Color {
    if std::io::stdout().is_terminal() {
        &COLOR_ON
    } else {
        &COLOR_OFF
    }
}

/// Remove `--env-file <path>` from the argument list so it doesn't
/// interfere with subcommand parsing.
fn strip_env_file_flag(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--env-file" {
            skip_next = true;
            continue;
        }
        out.push(arg.clone());
    }
    out
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().collect();

    // 1. Explicit --env-file (always loaded, even in production)
    if let Some(path) = parse_flag_str(&raw_args, "--env-file") {
        if let Err(err) = load_dotenv_if_present(path) {
            eprintln!("warning: could not read env file {path}: {err}");
        }
    }

    // 2. Standard deployment path (always tried)
    let _ = load_dotenv_if_present(DEFAULT_ENV_FILE);

    // 3. Local .env (dev only)
    if std::env::var("ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
        let _ = load_dotenv_if_present(".env");
    }

    let args = strip_env_file_flag(&raw_args);

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
        Action::ApikeyRevoke { prefix } => cmd_apikey_revoke(&store, &prefix).await,
        Action::Stats => cmd_stats(&store).await,
        Action::SecretStats => cmd_secret_stats(&store).await,
        Action::UsersList { limit } => cmd_users_list(&store, limit).await,
        Action::UsersShow { user_id } => cmd_users_show(&store, &user_id).await,
        Action::ApikeysList { user_id, limit } => {
            cmd_apikeys_list(&store, user_id.as_deref(), limit).await
        }
        Action::TopUsers { by, limit } => cmd_top_users(&store, by, limit).await,
    }
}

// ── Command handlers ─────────────────────────────────────────────────

async fn cmd_apikey_revoke(store: &Arc<PgStore>, prefix: &str) -> ExitCode {
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

async fn cmd_stats(store: &Arc<PgStore>) -> ExitCode {
    let now = Utc::now();
    let stats = match store.dashboard_stats(now).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("stats error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let c = colors();
    println!("{}secrt dashboard{}", c.bold, c.reset);
    println!("{}────────────────────────────────{}", c.dim, c.reset);
    println!();
    println!("{}Secrets{}", c.bold, c.reset);
    println!(
        "  Active:          {}{}{}",
        c.cyan, stats.active_secrets, c.reset
    );
    println!(
        "  Storage:         {}{}{}",
        c.cyan,
        human_bytes(stats.total_secret_bytes),
        c.reset
    );
    println!("  Created (24h):   {}", stats.secrets_24h);
    println!("  Created (7d):    {}", stats.secrets_7d);
    println!("  Created (30d):   {}", stats.secrets_30d);
    println!();
    println!("{}Users{}", c.bold, c.reset);
    println!(
        "  Total:           {}{}{}",
        c.cyan, stats.total_users, c.reset
    );
    println!("  Active (30d):    {}", stats.users_active_30d);
    println!("  Active (90d):    {}", stats.users_active_90d);
    println!();
    println!("{}API Keys{}", c.bold, c.reset);
    println!(
        "  Active:          {}{}{}",
        c.green, stats.active_api_keys, c.reset
    );
    println!(
        "  Revoked:         {}{}{}",
        c.dim, stats.revoked_api_keys, c.reset
    );
    println!();
    println!("{}Sessions{}", c.bold, c.reset);
    println!("  Active:          {}", stats.active_sessions);

    ExitCode::SUCCESS
}

async fn cmd_secret_stats(store: &Arc<PgStore>) -> ExitCode {
    let now = Utc::now();
    let b = match store.secret_breakdown(now).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("secret stats error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let c = colors();
    println!("{}secret breakdown{}", c.bold, c.reset);
    println!("{}────────────────────────────────{}", c.dim, c.reset);
    println!();
    println!("{}Expiry{}", c.bold, c.reset);
    println!("  < 1 hour:        {}{}{}", c.red, b.expiring_1h, c.reset);
    println!(
        "  1h – 24h:        {}{}{}",
        c.yellow, b.expiring_24h, c.reset
    );
    println!("  1d – 7d:         {}", b.expiring_7d);
    println!("  > 7 days:        {}", b.expiring_beyond_7d);
    println!();
    println!("{}Ownership{}", c.bold, c.reset);
    println!("  Anonymous:       {}", b.anonymous_count);
    println!("  Authenticated:   {}", b.authenticated_count);
    println!();
    println!("{}Passphrase{}", c.bold, c.reset);
    println!(
        "  Protected:       {}{}{}",
        c.green, b.passphrase_protected, c.reset
    );
    println!("  Not protected:   {}", b.not_passphrase_protected);
    println!();
    println!("{}Size{}", c.bold, c.reset);
    println!("  Average:         {}", human_bytes(b.avg_ciphertext_bytes));
    println!(
        "  Median:          {}",
        human_bytes(b.median_ciphertext_bytes)
    );

    ExitCode::SUCCESS
}

async fn cmd_users_list(store: &Arc<PgStore>, limit: i64) -> ExitCode {
    let now = Utc::now();
    let users = match store.list_users(now, limit, 0).await {
        Ok(u) => u,
        Err(err) => {
            eprintln!("list users error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let c = colors();
    println!(
        "{}  {:<36}  {:<20}  {:>12}  {:>5}  {:>7}  {:>7}{}",
        c.bold, "ID", "NAME", "LAST ACTIVE", "KEYS", "SECRETS", "PASSKEYS", c.reset
    );

    for u in &users {
        println!(
            "  {:<36}  {:<20}  {:>12}  {:>5}  {:>7}  {:>7}",
            u.id,
            truncate(&u.display_name, 20),
            u.last_active_at.format("%Y-%m-%d"),
            u.active_api_keys,
            u.active_secrets,
            u.passkey_count,
        );
    }

    if users.is_empty() {
        println!("{}  (no users){}", c.dim, c.reset);
    }

    ExitCode::SUCCESS
}

async fn cmd_users_show(store: &Arc<PgStore>, user_id_str: &str) -> ExitCode {
    let user_id: UserId = match user_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            eprintln!("invalid user ID: {user_id_str}");
            return ExitCode::FAILURE;
        }
    };

    let now = Utc::now();
    let detail = match store.user_detail(user_id, now).await {
        Ok(d) => d,
        Err(err) => {
            eprintln!("user detail error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let c = colors();
    println!("{}user {}{}", c.bold, detail.user.id, c.reset);
    println!("{}────────────────────────────────{}", c.dim, c.reset);
    println!("  Display name:    {}", detail.user.display_name);
    println!(
        "  Created:         {}",
        detail.user.created_at.format("%Y-%m-%d %H:%M UTC")
    );
    println!(
        "  Last active:     {}",
        detail.user.last_active_at.format("%Y-%m-%d")
    );
    println!();
    println!("  Secrets:         {}", detail.secret_count);
    println!(
        "  Secret storage:  {}",
        human_bytes(detail.total_secret_bytes)
    );
    println!("  Passkeys:        {}", detail.passkey_count);
    println!(
        "  Notes Key (AMK): {}",
        if detail.has_amk {
            format!("{}yes{}", c.green, c.reset)
        } else {
            "no".to_string()
        }
    );
    println!();

    if detail.api_keys.is_empty() {
        println!("  {}API Keys: (none){}", c.dim, c.reset);
    } else {
        println!("  {}API Keys:{}", c.bold, c.reset);
        for k in &detail.api_keys {
            let status = if k.revoked_at.is_some() {
                format!("{}revoked{}", c.red, c.reset)
            } else {
                format!("{}active{}", c.green, c.reset)
            };
            println!(
                "    {}  {}  created {}",
                k.prefix,
                status,
                k.created_at.format("%Y-%m-%d"),
            );
        }
    }

    ExitCode::SUCCESS
}

async fn cmd_apikeys_list(store: &Arc<PgStore>, user_id_str: Option<&str>, limit: i64) -> ExitCode {
    let user_id: Option<UserId> = match user_id_str {
        Some(s) => match s.parse() {
            Ok(id) => Some(id),
            Err(_) => {
                eprintln!("invalid user ID: {s}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let keys = match store.list_all_api_keys(user_id, limit).await {
        Ok(k) => k,
        Err(err) => {
            eprintln!("list api keys error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let c = colors();
    println!(
        "{}  {:<14}  {:>7}  {:<20}  {:<12}  SCOPES{}",
        c.bold, "PREFIX", "STATUS", "USER", "CREATED", c.reset
    );

    for k in &keys {
        let status = if k.revoked_at.is_some() {
            format!("{}revoked{}", c.red, c.reset)
        } else {
            format!("{}active{}", c.green, c.reset)
        };
        let user_display =
            k.display_name.as_deref().unwrap_or_else(
                || {
                    if k.user_id.is_some() {
                        "?"
                    } else {
                        "-"
                    }
                },
            );
        println!(
            "  {:<14}  {:>7}  {:<20}  {:<12}  {}",
            k.prefix,
            status,
            truncate(user_display, 20),
            k.created_at.format("%Y-%m-%d"),
            if k.scopes.is_empty() {
                "(all)"
            } else {
                &k.scopes
            },
        );
    }

    if keys.is_empty() {
        println!("{}  (no api keys){}", c.dim, c.reset);
    }

    ExitCode::SUCCESS
}

async fn cmd_top_users(store: &Arc<PgStore>, by: TopUsersBy, limit: i64) -> ExitCode {
    let now = Utc::now();

    let (label, results) = match by {
        TopUsersBy::Secrets => ("secrets", store.top_users_by_secrets(now, limit).await),
        TopUsersBy::Bytes => ("bytes", store.top_users_by_bytes(now, limit).await),
        TopUsersBy::Keys => ("keys", store.top_users_by_keys(limit).await),
    };

    let users = match results {
        Ok(u) => u,
        Err(err) => {
            eprintln!("top users error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let c = colors();
    println!("{}top users by {}{}", c.bold, label, c.reset);
    println!("{}────────────────────────────────{}", c.dim, c.reset);

    for (i, u) in users.iter().enumerate() {
        let value_str = if matches!(by, TopUsersBy::Bytes) {
            human_bytes(u.value)
        } else {
            u.value.to_string()
        };
        println!(
            "  {:>3}.  {:<36}  {:<20}  {}{}{}",
            i + 1,
            u.id,
            truncate(&u.display_name, 20),
            c.cyan,
            value_str,
            c.reset,
        );
    }

    if users.is_empty() {
        println!("{}  (no users){}", c.dim, c.reset);
    }

    ExitCode::SUCCESS
}

// ── Utility ──────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn usage() {
    eprintln!("Usage: secrt-admin [options] <command>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --env-file <path>   Load environment from file (default: {DEFAULT_ENV_FILE})");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  stats                              Dashboard overview");
    eprintln!("  secrets stats                      Detailed secret analytics");
    eprintln!("  users list [--limit N]             List users (default: 50)");
    eprintln!("  users show <user-id>               User detail view");
    eprintln!("  apikeys list [--user ID] [--limit N]  List API keys");
    eprintln!("  apikey revoke <prefix>             Revoke an API key");
    eprintln!("  top-users [--by secrets|bytes|keys] [--limit N]");
}
