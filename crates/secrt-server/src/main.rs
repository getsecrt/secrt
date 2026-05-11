const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("Usage:");
    println!("  secrt-server");
    println!("  secrt-server [--help|-h|help]");
    println!("  secrt-server [--version|-v|version]");
    println!();
    println!("Options:");
    println!("  -h, --help     Show this help and exit");
    println!("  -v, --version  Show version and exit");
}

fn main() {
    // Argument parsing runs synchronously before anything else.
    match std::env::args().nth(1).as_deref() {
        Some("--version") | Some("-v") | Some("version") => {
            println!("secrt-server {}", VERSION);
            return;
        }
        Some("--help") | Some("-h") | Some("help") => {
            print_help();
            return;
        }
        _ => {}
    }

    // Load `.env` into the process environment BEFORE the Tokio runtime is
    // built. `std::env::set_var` is unsound from a multi-threaded context,
    // and Tokio's multi-threaded runtime spawns its worker pool eagerly,
    // so the dotenv loader has to run while this thread is still the only
    // one in the process. See `runtime::prepare_env` for the contract.
    let dotenv_outcome = secrt_server::runtime::prepare_env();

    // Build the Tokio runtime explicitly (rather than via `#[tokio::main]`)
    // so the sync dotenv-load above sees a single-threaded process.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("failed to build tokio runtime: {err}");
            std::process::exit(1);
        }
    };

    let result = rt.block_on(secrt_server::runtime::run_server(dotenv_outcome));

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
