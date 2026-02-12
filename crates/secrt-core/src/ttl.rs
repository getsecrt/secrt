use crate::types::EnvelopeError;

/// Maximum allowed TTL (1 year in seconds).
pub const MAX_TTL_SECONDS: i64 = 31_536_000;

/// Parse a CLI TTL string to seconds.
/// Grammar: <positive-integer>[s|m|h|d|w]
/// No unit defaults to seconds. Result must be 1..31536000.
pub fn parse_ttl(s: &str) -> Result<i64, EnvelopeError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(EnvelopeError::InvalidTtl(String::new()));
    }

    let (num_str, unit) = if let Some(last) = s.bytes().last() {
        if last.is_ascii_digit() {
            (s, b's')
        } else {
            if s.len() < 2 {
                return Err(EnvelopeError::InvalidTtl(format!("{:?}", s)));
            }
            let unit_char = s.as_bytes()[s.len() - 1];
            let num_part = &s[..s.len() - 1];
            match unit_char {
                b's' | b'm' | b'h' | b'd' | b'w' => (num_part, unit_char),
                _ => {
                    return Err(EnvelopeError::InvalidTtl(format!(
                        "unknown unit in {:?}",
                        s
                    )))
                }
            }
        }
    } else {
        return Err(EnvelopeError::InvalidTtl(String::new()));
    };

    // Reject decimals, spaces, signs in the numeric part
    if num_str.contains('.')
        || num_str.contains(' ')
        || num_str.contains('-')
        || num_str.contains('+')
    {
        return Err(EnvelopeError::InvalidTtl(format!("{:?}", s)));
    }

    let n: i64 = num_str
        .parse()
        .map_err(|_| EnvelopeError::InvalidTtl(format!("{:?}", s)))?;

    if n <= 0 {
        return Err(EnvelopeError::InvalidTtl("value must be positive".into()));
    }

    let multiplier: i64 = match unit {
        b's' => 1,
        b'm' => 60,
        b'h' => 3600,
        b'd' => 86400,
        b'w' => 604800,
        _ => unreachable!(),
    };

    let result = n * multiplier;
    if result > MAX_TTL_SECONDS {
        return Err(EnvelopeError::InvalidTtl(format!(
            "exceeds maximum ({} seconds)",
            MAX_TTL_SECONDS
        )));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_char_invalid() {
        let err = parse_ttl("x");
        assert!(matches!(err, Err(EnvelopeError::InvalidTtl(_))));
    }
}
