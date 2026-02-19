use std::io::{self, Write};

use secrt_cli::cli;
use secrt_cli::client::ApiClient;
use secrt_cli::envelope;

fn main() {
    let mut deps = cli::Deps {
        stdin: Box::new(io::stdin()),
        stdout: Box::new(io::stdout()),
        stderr: Box::new(io::stderr()),
        is_tty: Box::new(|| is_terminal::is_terminal(io::stdin())),
        is_stdout_tty: Box::new(|| is_terminal::is_terminal(io::stdout())),
        getenv: Box::new(|key: &str| std::env::var(key).ok()),
        rand_bytes: Box::new(|buf: &mut [u8]| {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            rng.fill(buf)
                .map_err(|_| envelope::EnvelopeError::RngError("SystemRandom failed".into()))
        }),
        make_api: Box::new(|base_url: &str, api_key: &str| {
            Box::new(ApiClient {
                base_url: base_url.to_string(),
                api_key: api_key.to_string(),
            })
        }),
        read_pass: Box::new(|prompt: &str, w: &mut dyn Write| {
            w.write_all(prompt.as_bytes())?;
            w.flush()?;
            rpassword::read_password()
        }),
        get_keychain_secret: Box::new(secrt_cli::keychain::get_secret),
        set_keychain_secret: Box::new(secrt_cli::keychain::set_secret),
        delete_keychain_secret: Box::new(secrt_cli::keychain::delete_secret),
        get_keychain_secret_list: Box::new(secrt_cli::keychain::get_secret_list),
        open_browser: Box::new(|url: &str| {
            #[cfg(target_os = "macos")]
            {
                std::process::Command::new("open")
                    .arg(url)
                    .spawn()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            #[cfg(target_os = "linux")]
            {
                std::process::Command::new("xdg-open")
                    .arg(url)
                    .spawn()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            #[cfg(target_os = "windows")]
            {
                std::process::Command::new("cmd")
                    .args(["/c", "start", url])
                    .spawn()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                let _ = url;
                Err("unsupported platform".into())
            }
        }),
        sleep: Box::new(|d: std::time::Duration| std::thread::sleep(d)),
    };

    let args: Vec<String> = std::env::args().collect();
    let code = cli::run(&args, &mut deps);
    std::process::exit(code);
}
