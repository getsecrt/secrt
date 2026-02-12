#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};

use secrt_cli::cli::Deps;
use secrt_cli::client::{
    ApiClient, ClaimResponse, CreateRequest, CreateResponse, InfoResponse, SecretApi,
};
use secrt_cli::envelope::EnvelopeError;

/// A shared buffer that implements Write for capturing output.
#[derive(Clone)]
pub struct SharedBuf(pub Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn new() -> Self {
        SharedBuf(Arc::new(Mutex::new(Vec::new())))
    }

    pub fn to_string(&self) -> String {
        let buf = self.0.lock().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Canned responses for MockApi.
#[derive(Clone)]
pub struct MockApiResponses {
    pub create: Option<Result<CreateResponse, String>>,
    pub claim: Option<Result<ClaimResponse, String>>,
    pub burn: Option<Result<(), String>>,
    pub info: Option<Result<InfoResponse, String>>,
}

impl Default for MockApiResponses {
    fn default() -> Self {
        MockApiResponses {
            create: None,
            claim: None,
            burn: None,
            info: None,
        }
    }
}

/// A mock API client for testing.
pub struct MockApi {
    responses: MockApiResponses,
}

impl MockApi {
    pub fn new(responses: MockApiResponses) -> Self {
        MockApi { responses }
    }
}

impl SecretApi for MockApi {
    fn create(&self, _req: CreateRequest) -> Result<CreateResponse, String> {
        match &self.responses.create {
            Some(Ok(r)) => Ok(CreateResponse {
                id: r.id.clone(),
                share_url: r.share_url.clone(),
                expires_at: r.expires_at.clone(),
            }),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: create not configured".into()),
        }
    }

    fn claim(&self, _secret_id: &str, _claim_token: &[u8]) -> Result<ClaimResponse, String> {
        match &self.responses.claim {
            Some(Ok(r)) => Ok(ClaimResponse {
                envelope: r.envelope.clone(),
                expires_at: r.expires_at.clone(),
            }),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: claim not configured".into()),
        }
    }

    fn burn(&self, _secret_id: &str) -> Result<(), String> {
        match &self.responses.burn {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: burn not configured".into()),
        }
    }

    fn info(&self) -> Result<InfoResponse, String> {
        match &self.responses.info {
            Some(Ok(r)) => Ok(r.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: info not configured".into()),
        }
    }
}

/// Build test Deps with configurable options.
pub struct TestDepsBuilder {
    stdin_data: Vec<u8>,
    is_tty: bool,
    is_stdout_tty: bool,
    env: HashMap<String, String>,
    read_pass_responses: Vec<String>,
    read_pass_error: Option<String>,
    mock_responses: Option<MockApiResponses>,
    keychain_secrets: HashMap<String, String>,
    keychain_secret_lists: HashMap<String, Vec<String>>,
}

impl TestDepsBuilder {
    pub fn new() -> Self {
        TestDepsBuilder {
            stdin_data: Vec::new(),
            is_tty: false,
            is_stdout_tty: false,
            env: HashMap::new(),
            read_pass_responses: Vec::new(),
            read_pass_error: None,
            mock_responses: None,
            keychain_secrets: HashMap::new(),
            keychain_secret_lists: HashMap::new(),
        }
    }

    pub fn stdin(mut self, data: &[u8]) -> Self {
        self.stdin_data = data.to_vec();
        self
    }

    pub fn is_tty(mut self, v: bool) -> Self {
        self.is_tty = v;
        self
    }

    #[allow(dead_code)]
    pub fn is_stdout_tty(mut self, v: bool) -> Self {
        self.is_stdout_tty = v;
        self
    }

    pub fn env(mut self, key: &str, val: &str) -> Self {
        self.env.insert(key.to_string(), val.to_string());
        self
    }

    pub fn read_pass(mut self, responses: &[&str]) -> Self {
        self.read_pass_responses = responses.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn read_pass_error(mut self, msg: &str) -> Self {
        self.read_pass_error = Some(msg.to_string());
        self
    }

    pub fn mock_create(mut self, resp: Result<CreateResponse, String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .create = Some(resp);
        self
    }

    pub fn mock_claim(mut self, resp: Result<ClaimResponse, String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .claim = Some(resp);
        self
    }

    pub fn mock_burn(mut self, resp: Result<(), String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .burn = Some(resp);
        self
    }

    pub fn mock_info(mut self, resp: Result<InfoResponse, String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .info = Some(resp);
        self
    }

    pub fn keychain_secret(mut self, key: &str, val: &str) -> Self {
        self.keychain_secrets
            .insert(key.to_string(), val.to_string());
        self
    }

    pub fn keychain_secret_list(mut self, key: &str, vals: &[&str]) -> Self {
        self.keychain_secret_lists.insert(
            key.to_string(),
            vals.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    pub fn build(self) -> (Deps, SharedBuf, SharedBuf) {
        let stdout = SharedBuf::new();
        let stderr = SharedBuf::new();
        let stdout_clone = stdout.clone();
        let stderr_clone = stderr.clone();

        let is_tty = self.is_tty;
        let is_stdout_tty = self.is_stdout_tty;
        let env = self.env;

        let read_pass_responses = Arc::new(Mutex::new(self.read_pass_responses));
        let read_pass_error = self.read_pass_error;

        let deps = Deps {
            stdin: Box::new(Cursor::new(self.stdin_data)),
            stdout: Box::new(stdout_clone),
            stderr: Box::new(stderr_clone),
            is_tty: Box::new(move || is_tty),
            is_stdout_tty: Box::new(move || is_stdout_tty),
            getenv: Box::new(move |key: &str| env.get(key).cloned()),
            rand_bytes: Box::new(|buf: &mut [u8]| {
                use ring::rand::{SecureRandom, SystemRandom};
                let rng = SystemRandom::new();
                rng.fill(buf)
                    .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
            }),
            read_pass: Box::new(move |prompt: &str, w: &mut dyn Write| {
                let _ = w.write_all(prompt.as_bytes());
                let _ = w.flush();
                if let Some(ref msg) = read_pass_error {
                    return Err(io::Error::new(io::ErrorKind::Other, msg.clone()));
                }
                let mut responses = read_pass_responses.lock().unwrap();
                if responses.is_empty() {
                    Err(io::Error::new(io::ErrorKind::Other, "no password input"))
                } else {
                    Ok(responses.remove(0))
                }
            }),
            get_keychain_secret: {
                let kc = self.keychain_secrets;
                Box::new(move |key: &str| kc.get(key).cloned())
            },
            get_keychain_secret_list: {
                let kcl = self.keychain_secret_lists;
                Box::new(move |key: &str| kcl.get(key).cloned().unwrap_or_default())
            },
            make_api: if let Some(mock_responses) = self.mock_responses {
                Box::new(move |_base_url: &str, _api_key: &str| {
                    Box::new(MockApi::new(mock_responses.clone())) as Box<dyn SecretApi>
                })
            } else {
                Box::new(|base_url: &str, api_key: &str| {
                    Box::new(ApiClient {
                        base_url: base_url.to_string(),
                        api_key: api_key.to_string(),
                    }) as Box<dyn SecretApi>
                })
            },
        };

        (deps, stdout, stderr)
    }
}

/// Helper to build args vec from a slice of &str.
pub fn args(strs: &[&str]) -> Vec<String> {
    strs.iter().map(|s| s.to_string()).collect()
}
