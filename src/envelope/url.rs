use crate::envelope::crypto::{b64_decode, b64_encode};
use crate::envelope::types::{EnvelopeError, URL_KEY_LEN};

/// Parse a share URL to extract ID and url_key.
/// Accepts formats:
///   - https://host/s/<id>#v1.<url_key_b64>
///   - <id>#v1.<url_key_b64> (bare ID with fragment)
pub fn parse_share_url(raw_url: &str) -> Result<(String, Vec<u8>), EnvelopeError> {
    let (id, fragment) = if raw_url.contains("://") {
        // Full URL
        // Split off fragment manually since url crate would percent-decode
        let (base, frag) = match raw_url.find('#') {
            Some(idx) => (&raw_url[..idx], &raw_url[idx + 1..]),
            None => {
                return Err(EnvelopeError::InvalidFragment("missing fragment".into()));
            }
        };

        // Parse the base URL to extract the path
        // Find the path after the host
        let path = if let Some(scheme_end) = base.find("://") {
            let after_scheme = &base[scheme_end + 3..];
            match after_scheme.find('/') {
                Some(idx) => &after_scheme[idx..],
                None => "",
            }
        } else {
            ""
        };

        let id = path
            .strip_prefix("/s/")
            .ok_or_else(|| EnvelopeError::InvalidFragment("expected /s/<id> path".into()))?;

        if id.is_empty() {
            return Err(EnvelopeError::InvalidFragment(
                "expected /s/<id> path".into(),
            ));
        }

        (id.to_string(), frag.to_string())
    } else {
        // Bare format: id#fragment
        let parts: Vec<&str> = raw_url.splitn(2, '#').collect();
        if parts.len() != 2 || parts[0].is_empty() {
            return Err(EnvelopeError::InvalidFragment("missing fragment".into()));
        }
        (parts[0].to_string(), parts[1].to_string())
    };

    // Parse fragment
    if !fragment.starts_with("v1.") {
        return Err(EnvelopeError::InvalidFragment(
            "fragment must start with v1.".into(),
        ));
    }

    let key_b64 = &fragment[3..];
    let url_key = b64_decode(key_b64)
        .map_err(|_| EnvelopeError::InvalidFragment("invalid url_key encoding".into()))?;

    if url_key.len() != URL_KEY_LEN {
        return Err(EnvelopeError::InvalidFragment(format!(
            "url_key must be {} bytes, got {}",
            URL_KEY_LEN,
            url_key.len()
        )));
    }

    Ok((id, url_key))
}

/// Build a share URL with fragment.
pub fn format_share_link(share_url: &str, url_key: &[u8]) -> String {
    format!("{}#v1.{}", share_url, b64_encode(url_key))
}
