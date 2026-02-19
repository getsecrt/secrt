#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};

use secrt_cli::cli::Deps;
use secrt_cli::client::{
    AmkWrapperResponse, ApiClient, ClaimResponse, CreateRequest, CreateResponse, EncMetaV1,
    InfoResponse, ListSecretsResponse, SecretApi, SecretMetadataItem,
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
    pub list: Option<Result<ListSecretsResponse, String>>,
    pub get_secret_metadata: Option<Result<SecretMetadataItem, String>>,
    pub get_amk_wrapper: Option<Result<Option<AmkWrapperResponse>, String>>,
    pub upsert_amk_wrapper: Option<Result<(), String>>,
    pub update_secret_meta: Option<Result<(), String>>,
}

impl Default for MockApiResponses {
    fn default() -> Self {
        MockApiResponses {
            create: None,
            claim: None,
            burn: None,
            info: None,
            list: None,
            get_secret_metadata: None,
            get_amk_wrapper: None,
            upsert_amk_wrapper: None,
            update_secret_meta: None,
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

    fn list(
        &self,
        _limit: Option<i64>,
        _offset: Option<i64>,
    ) -> Result<ListSecretsResponse, String> {
        match &self.responses.list {
            Some(Ok(r)) => Ok(r.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: list not configured".into()),
        }
    }

    fn get_secret_metadata(&self, _id: &str) -> Result<SecretMetadataItem, String> {
        match &self.responses.get_secret_metadata {
            Some(Ok(r)) => Ok(r.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: get_secret_metadata not configured".into()),
        }
    }

    fn get_amk_wrapper(&self) -> Result<Option<AmkWrapperResponse>, String> {
        match &self.responses.get_amk_wrapper {
            Some(Ok(r)) => Ok(r.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: get_amk_wrapper not configured".into()),
        }
    }

    fn upsert_amk_wrapper(
        &self,
        _key_prefix: &str,
        _wrapped_amk: &str,
        _nonce: &str,
        _amk_commit: &str,
        _version: i16,
    ) -> Result<(), String> {
        match &self.responses.upsert_amk_wrapper {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: upsert_amk_wrapper not configured".into()),
        }
    }

    fn update_secret_meta(
        &self,
        _secret_id: &str,
        _enc_meta: &EncMetaV1,
        _meta_key_version: i16,
    ) -> Result<(), String> {
        match &self.responses.update_secret_meta {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("mock: update_secret_meta not configured".into()),
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
        // Default XDG_CONFIG_HOME to a unique temp dir so tests never pick up the
        // real user config. Tests that need a specific config call `.env("XDG_CONFIG_HOME", ...)`
        // which will override this default.
        let iso_dir = std::env::temp_dir().join(format!(
            "secrt_test_iso_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut env = HashMap::new();
        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            iso_dir.to_string_lossy().to_string(),
        );
        TestDepsBuilder {
            stdin_data: Vec::new(),
            is_tty: false,
            is_stdout_tty: false,
            env,
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

    pub fn mock_list(mut self, resp: Result<ListSecretsResponse, String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .list = Some(resp);
        self
    }

    pub fn mock_get_secret_metadata(mut self, resp: Result<SecretMetadataItem, String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .get_secret_metadata = Some(resp);
        self
    }

    pub fn mock_get_amk_wrapper(
        mut self,
        resp: Result<Option<AmkWrapperResponse>, String>,
    ) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .get_amk_wrapper = Some(resp);
        self
    }

    pub fn mock_upsert_amk_wrapper(mut self, resp: Result<(), String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .upsert_amk_wrapper = Some(resp);
        self
    }

    pub fn mock_update_secret_meta(mut self, resp: Result<(), String>) -> Self {
        self.mock_responses
            .get_or_insert_with(MockApiResponses::default)
            .update_secret_meta = Some(resp);
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
            set_keychain_secret: Box::new(|_: &str, _: &str| Ok(())),
            delete_keychain_secret: Box::new(|_: &str| Ok(())),
            get_keychain_secret_list: {
                let kcl = self.keychain_secret_lists;
                Box::new(move |key: &str| kcl.get(key).cloned().unwrap_or_default())
            },
            open_browser: Box::new(|_: &str| Ok(())),
            sleep: Box::new(|_: std::time::Duration| {}),
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
