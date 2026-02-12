#[tokio::main]
async fn main() {
    if let Err(err) = secrt_server::runtime::run_server().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
