use crate::envelope::crypto::{b64_decode, b64_encode};
use crate::envelope::types::{EnvelopeError, URL_KEY_LEN};

/// Parse a share URL to extract ID and url_key.
/// Accepts formats:
///   - https://host/s/<id>#<url_key_b64>
///   - <id>#<url_key_b64> (bare ID with fragment)
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

    let key_b64 = &fragment;
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
    format!("{}#{}", share_url, b64_encode(url_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> Vec<u8> {
        vec![42u8; URL_KEY_LEN]
    }

    fn make_key_b64() -> String {
        b64_encode(&make_key())
    }

    #[test]
    fn parse_full_url() {
        let key = make_key();
        let key_b64 = make_key_b64();
        let url = format!("https://secrt.ca/s/abc123#{}", key_b64);
        let (id, url_key) = parse_share_url(&url).unwrap();
        assert_eq!(id, "abc123");
        assert_eq!(url_key, key);
    }

    #[test]
    fn parse_bare_id() {
        let key = make_key();
        let key_b64 = make_key_b64();
        let url = format!("abc123#{}", key_b64);
        let (id, url_key) = parse_share_url(&url).unwrap();
        assert_eq!(id, "abc123");
        assert_eq!(url_key, key);
    }

    #[test]
    fn parse_url_with_port() {
        let key = make_key();
        let key_b64 = make_key_b64();
        let url = format!("https://localhost:8443/s/testid#{}", key_b64);
        let (id, url_key) = parse_share_url(&url).unwrap();
        assert_eq!(id, "testid");
        assert_eq!(url_key, key);
    }

    #[test]
    fn parse_missing_fragment() {
        let err = parse_share_url("https://secrt.ca/s/abc123");
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn parse_no_s_path() {
        let key_b64 = make_key_b64();
        let url = format!("https://secrt.ca/x/abc#{}", key_b64);
        let err = parse_share_url(&url);
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn parse_fragment_wrong_length() {
        let short_frag = b64_encode(&[0u8; 5]);
        let url = format!("https://secrt.ca/s/abc#{}", short_frag);
        let err = parse_share_url(&url);
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn parse_invalid_base64() {
        let err = parse_share_url("https://secrt.ca/s/abc#!!!invalid!!!");
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn parse_wrong_key_length() {
        // 16 bytes instead of 32
        let short_key = b64_encode(&[0u8; 16]);
        let url = format!("https://secrt.ca/s/abc#{}", short_key);
        let err = parse_share_url(&url);
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn parse_bare_no_hash() {
        let err = parse_share_url("abc123");
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn format_roundtrip() {
        let key = make_key();
        let share_url = "https://secrt.ca/s/abc123";
        let link = format_share_link(share_url, &key);
        let (id, url_key) = parse_share_url(&link).unwrap();
        assert_eq!(id, "abc123");
        assert_eq!(url_key, key);
    }

    #[test]
    fn parse_url_no_path_after_host() {
        let key_b64 = make_key_b64();
        let url = format!("https://example.com#{}", key_b64);
        let err = parse_share_url(&url);
        // No /s/<id> path → error
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }

    #[test]
    fn parse_empty_id_in_path() {
        let key_b64 = make_key_b64();
        let url = format!("https://secrt.ca/s/#{}", key_b64);
        let err = parse_share_url(&url);
        assert!(matches!(err, Err(EnvelopeError::InvalidFragment(_))));
    }
}
