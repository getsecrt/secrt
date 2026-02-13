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

#[tokio::main]
async fn main() {
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

    if let Err(err) = secrt_server::runtime::run_server().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
