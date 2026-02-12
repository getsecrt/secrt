use std::io::{self, Write};

use secrt::cli;
use secrt::client::ApiClient;
use secrt::envelope;

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
        get_keychain_secret: Box::new(secrt::keychain::get_secret),
        get_keychain_secret_list: Box::new(secrt::keychain::get_secret_list),
    };

    let args: Vec<String> = std::env::args().collect();
    let code = cli::run(&args, &mut deps);
    std::process::exit(code);
}
