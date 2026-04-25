pub mod assets;
pub mod config;
pub mod domain;
pub mod http;
pub mod reaper;
pub mod release_poller;
pub mod runtime;
pub mod storage;

/// Hard floor: CLI versions older than this are advisory-warned by the server
/// (via `min_supported_cli_version` on `/api/v1/info` and the
/// `X-Secrt-Min-Cli-Version` advisory header). The server itself does NOT
/// refuse old clients — that would break zero-knowledge bearer claim flows for
/// users who got a share link before they upgraded. The CLI uses this value
/// to inform the user that an upgrade is required.
///
/// Bump this when a server release contains a wire-format change that breaks
/// older CLIs. The v0.15.0 AAD format break is the canonical example. See the
/// release process in `secrt/AGENTS.md`.
pub const MIN_SUPPORTED_CLI_VERSION: &str = "0.15.0";
