//! Instance trust policy.
//!
//! Conforming clients use [`classify_origin`] to decide whether a base URL
//! belongs to an official secrt deployment, a user-trusted custom server,
//! a development loopback, or an unknown host. The verdict drives loud
//! warnings and credential-leak hard-blocks on the CLI.
//!
//! The official-instance list is a normative spec contract — see
//! `spec/v1/instances.md` and `spec/v1/instances.json`. Tests pin
//! [`KNOWN_INSTANCES`] to the JSON apex list and fail on drift.

use url::{Host, Url};

/// Apex hostnames of official secrt instances. Wildcard subdomains
/// (e.g. `my.secrt.is`, `team.secrt.ca`) collapse to their apex.
///
/// MUST stay in sync with `spec/v1/instances.json`. The drift test in
/// `crates/secrt-core/tests/instance.rs` asserts equality.
pub const KNOWN_INSTANCES: &[&str] = &["secrt.ca", "secrt.is"];

/// Typed verdict on whether a base URL is trustworthy. Encodes the
/// distinction between "official", "user opted in", "dev-local exempt",
/// and "we have no idea who runs this".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// URL's normalized origin matches an official apex (or a wildcard
    /// subdomain of one), with `https` scheme and default port.
    Official { apex: &'static str },
    /// Host appears in the user's local trust list (e.g. CLI
    /// `trusted_servers` config). Self-hosters use this verdict to
    /// silence the off-list warning for their own deployments.
    TrustedCustom,
    /// Host is `localhost`, `127.0.0.0/8`, an IPv6 loopback, or `*.local`.
    /// Used for development and integration testing; no warning emitted.
    DevLocal,
    /// None of the above. Conforming clients warn before any operation
    /// against this host, and refuse to send credentials to it when it
    /// was URL-derived rather than explicitly configured.
    Untrusted,
}

/// Compute the trust verdict for a base URL against the official list
/// and a caller-provided list of user-trusted hosts.
///
/// Rules:
///   - Returns `Untrusted` if the URL fails to parse, lacks a host, or
///     uses anything other than http/https.
///   - `Official` requires `https`, default port (443), and a host that
///     equals one of [`KNOWN_INSTANCES`] or is a strict subdomain of one.
///     A non-default port (`https://secrt.ca:8443`) is *not* Official —
///     operators on a non-default port are self-hosters and must opt in
///     via `trusted_custom`.
///   - `DevLocal` covers `localhost`, IPv4 `127.0.0.0/8`, IPv6 loopback
///     `::1`, and any host ending in `.local`. The scheme MAY be `http`.
///   - `TrustedCustom` matches when the host (lowercased) equals an
///     entry in `trusted_custom`. Plain hostnames in the list are
///     matched as-is — callers should normalize before storing.
pub fn classify_origin(base_url: &str, trusted_custom: &[String]) -> TrustDecision {
    let parsed = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return TrustDecision::Untrusted,
    };

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return TrustDecision::Untrusted;
    }

    let host = match parsed.host() {
        Some(h) => h,
        None => return TrustDecision::Untrusted,
    };

    if is_dev_local(&host) {
        return TrustDecision::DevLocal;
    }

    let host_str = match &host {
        Host::Domain(d) => d.to_ascii_lowercase(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    };

    if scheme == "https" && parsed.port().is_none() {
        for known in KNOWN_INSTANCES {
            if host_str == *known || host_str.ends_with(&format!(".{known}")) {
                return TrustDecision::Official { apex: known };
            }
        }
    }

    for trusted in trusted_custom {
        if host_str == trusted.to_ascii_lowercase() {
            return TrustDecision::TrustedCustom;
        }
    }

    TrustDecision::Untrusted
}

/// Extract the host portion of a URL — lowercased domain or stringified
/// IP — without scheme, port, or path. IPv6 hosts are returned with
/// brackets (`[::1]`). Returns `None` for unparseable URLs.
///
/// Useful for diagnostic output ("pointing at `evil.tld`") that doesn't
/// want the full origin and doesn't want to display the user's port.
pub fn host_of(base_url: &str) -> Option<String> {
    let parsed = Url::parse(base_url).ok()?;
    let host = parsed.host()?;
    Some(match &host {
        Host::Domain(d) => d.to_ascii_lowercase(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    })
}

/// Normalize a URL to its origin string (`scheme://host[:port]`). Returns
/// `None` if parsing fails or the URL has no host. Preserves IPv6
/// brackets correctly (the `url` crate does the right thing here, unlike
/// hand-rolled `indexOf(':')` approaches).
pub fn normalize_origin(base_url: &str) -> Option<String> {
    let parsed = Url::parse(base_url).ok()?;
    let scheme = parsed.scheme();
    let host = parsed.host()?;
    let host_str = match &host {
        Host::Domain(d) => d.to_ascii_lowercase(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    };
    Some(match parsed.port() {
        Some(p) => format!("{scheme}://{host_str}:{p}"),
        None => format!("{scheme}://{host_str}"),
    })
}

fn is_dev_local(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => {
            let lower = d.to_ascii_lowercase();
            lower == "localhost" || lower.ends_with(".local")
        }
        Host::Ipv4(ip) => ip.octets()[0] == 127,
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}
