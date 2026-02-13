use std::path::{Path, PathBuf};

use crate::envelope::{PayloadMeta, PayloadType};
use crate::mime::mime_from_extension;

/// Metadata extracted from decrypted payload metadata with `type: "file"`.
pub struct FileHint {
    pub filename: String,
    pub mime: String,
}

/// Build encrypted payload metadata for a file path (used during `send --file`).
/// Returns `None` if the path has no usable basename.
pub fn build_file_metadata(path: &str) -> Option<PayloadMeta> {
    let basename = Path::new(path).file_name()?.to_str()?.to_string();

    if basename.is_empty() {
        return None;
    }

    let ext = Path::new(&basename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let mime = mime_from_extension(ext).to_string();

    Some(PayloadMeta::file(basename, mime))
}

/// Sanitize a filename received from decrypted metadata.
///
/// Strips path separators, null bytes, control characters, and leading dots.
/// Replaces forbidden characters with `_`. Limits to 255 bytes.
/// Returns `None` if the result is empty.
pub fn sanitize_filename(raw: &str) -> Option<String> {
    // Strip any path components — keep only the final segment
    let name = raw.rsplit(['/', '\\']).next().unwrap_or(raw);

    // Remove null bytes and control chars, replace forbidden chars
    let sanitized: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .map(|c| {
            if matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();

    // Strip leading dots (prevents hidden files / path traversal)
    let sanitized = sanitized.trim_start_matches('.');

    if sanitized.is_empty() {
        return None;
    }

    // Truncate to 255 bytes (filesystem limit)
    let truncated = if sanitized.len() > 255 {
        // Find a valid UTF-8 boundary
        let mut end = 255;
        while !sanitized.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        &sanitized[..end]
    } else {
        sanitized
    };

    if truncated.is_empty() {
        None
    } else {
        Some(truncated.to_string())
    }
}

/// Resolve a non-colliding output path in the current directory.
///
/// If `./filename` doesn't exist, returns it. Otherwise tries
/// `filename (1).ext`, `filename (2).ext`, etc., up to 999 attempts.
pub fn resolve_output_path(filename: &str) -> Result<PathBuf, String> {
    let base = PathBuf::from(filename);
    if !base.exists() {
        return Ok(base);
    }

    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let ext = base.extension().and_then(|e| e.to_str());

    for i in 1..=999 {
        let candidate = match ext {
            Some(e) => PathBuf::from(format!("{} ({}).{}", stem, i, e)),
            None => PathBuf::from(format!("{} ({})", stem, i)),
        };
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "could not find a non-colliding filename for {:?} after 999 attempts",
        filename
    ))
}

/// Extract a `FileHint` from decrypted payload metadata.
///
/// Returns `Some(FileHint)` only when `metadata.type == "file"` and the
/// filename passes sanitization.
pub fn extract_file_hint(metadata: &PayloadMeta) -> Option<FileHint> {
    if metadata.payload_type != PayloadType::File {
        return None;
    }

    let raw_filename = metadata.filename.as_deref()?;
    let filename = sanitize_filename(raw_filename)?;

    let mime = metadata
        .mime
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Some(FileHint { filename, mime })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- build_file_metadata ---

    #[test]
    fn build_hint_simple() {
        let hint = build_file_metadata("./claw.png").unwrap();
        assert_eq!(hint.payload_type, PayloadType::File);
        assert_eq!(hint.filename.as_deref(), Some("claw.png"));
        assert_eq!(hint.mime.as_deref(), Some("image/png"));
    }

    #[test]
    fn build_hint_nested_path() {
        let hint = build_file_metadata("/home/user/docs/report.pdf").unwrap();
        assert_eq!(hint.filename.as_deref(), Some("report.pdf"));
        assert_eq!(hint.mime.as_deref(), Some("application/pdf"));
    }

    #[test]
    fn build_hint_no_extension() {
        let hint = build_file_metadata("Makefile").unwrap();
        assert_eq!(hint.filename.as_deref(), Some("Makefile"));
        assert_eq!(hint.mime.as_deref(), Some("application/octet-stream"));
    }

    #[test]
    fn build_hint_empty_path() {
        assert!(build_file_metadata("").is_none());
    }

    // --- sanitize_filename ---

    #[test]
    fn sanitize_simple() {
        assert_eq!(sanitize_filename("hello.txt").unwrap(), "hello.txt");
    }

    #[test]
    fn sanitize_strips_path() {
        assert_eq!(sanitize_filename("/etc/passwd").unwrap(), "passwd");
        assert_eq!(
            sanitize_filename("..\\..\\windows\\system32\\foo.dll").unwrap(),
            "foo.dll"
        );
    }

    #[test]
    fn sanitize_strips_leading_dots() {
        assert_eq!(sanitize_filename(".hidden").unwrap(), "hidden");
        assert_eq!(sanitize_filename("...dots").unwrap(), "dots");
    }

    #[test]
    fn sanitize_replaces_forbidden() {
        assert_eq!(sanitize_filename("a:b*c?.txt").unwrap(), "a_b_c_.txt");
    }

    #[test]
    fn sanitize_empty_after_strip() {
        assert!(sanitize_filename("...").is_none());
        assert!(sanitize_filename("").is_none());
    }

    #[test]
    fn sanitize_control_chars() {
        assert_eq!(sanitize_filename("a\x00b\x01c.txt").unwrap(), "abc.txt");
    }

    #[test]
    fn sanitize_long_name() {
        let long = "a".repeat(300);
        let result = sanitize_filename(&long).unwrap();
        assert!(result.len() <= 255);
        assert_eq!(result.len(), 255);
    }

    // --- resolve_output_path ---

    #[test]
    fn resolve_nonexistent_file() {
        // A file that almost certainly doesn't exist
        let path = resolve_output_path("__secrt_test_nonexistent_file_12345.png").unwrap();
        assert_eq!(
            path,
            PathBuf::from("__secrt_test_nonexistent_file_12345.png")
        );
    }

    // --- extract_file_hint ---

    #[test]
    fn extract_hint_valid() {
        let meta = PayloadMeta::file("photo.jpg".into(), "image/jpeg".into());
        let fh = extract_file_hint(&meta).unwrap();
        assert_eq!(fh.filename, "photo.jpg");
        assert_eq!(fh.mime, "image/jpeg");
    }

    #[test]
    fn extract_hint_no_hint() {
        let meta = PayloadMeta::text();
        assert!(extract_file_hint(&meta).is_none());
    }

    #[test]
    fn extract_hint_wrong_type() {
        let mut meta = PayloadMeta::text();
        meta.filename = Some("notes.txt".into());
        assert!(extract_file_hint(&meta).is_none());
    }

    #[test]
    fn extract_hint_sanitizes_filename() {
        let meta = PayloadMeta::file("../../../etc/passwd".into(), "text/plain".into());
        let fh = extract_file_hint(&meta).unwrap();
        assert_eq!(fh.filename, "passwd");
    }

    #[test]
    fn extract_hint_bad_filename_returns_none() {
        let meta = PayloadMeta::file("...".into(), "text/plain".into());
        assert!(extract_file_hint(&meta).is_none());
    }

    #[test]
    fn extract_hint_default_mime() {
        let mut meta = PayloadMeta::file("data.bin".into(), "application/octet-stream".into());
        meta.mime = None;
        let fh = extract_file_hint(&meta).unwrap();
        assert_eq!(fh.mime, "application/octet-stream");
    }

    #[test]
    fn sanitize_multibyte_truncation() {
        // é = 2 bytes in UTF-8. 254 + 2 = 256, over the 255-byte limit.
        let s = "a".repeat(254) + "é";
        assert_eq!(s.len(), 256);
        let result = sanitize_filename(&s).unwrap();
        assert!(result.len() <= 255);
        // Should truncate at the char boundary: 254 (can't include the 2-byte char)
        assert_eq!(result.len(), 254);
    }

    #[test]
    fn sanitize_multibyte_exact_fit() {
        // 253 + 2 = 255 bytes, fits exactly at the boundary
        let s = "a".repeat(253) + "é";
        assert_eq!(s.len(), 255);
        let result = sanitize_filename(&s).unwrap();
        assert_eq!(result.len(), 255);
    }

    #[test]
    fn sanitize_multibyte_3byte_truncation() {
        // 日 = 3 bytes in UTF-8. 254 + 3 = 257, over limit.
        let s = "a".repeat(254) + "日";
        assert_eq!(s.len(), 257);
        let result = sanitize_filename(&s).unwrap();
        assert!(result.len() <= 255);
        assert_eq!(result.len(), 254);
    }

    // NOTE: resolve_output_path collision tests are in tests/cli_get.rs as integration
    // tests because they depend on CWD manipulation, which races with parallel unit tests.

    #[test]
    fn extract_hint_missing_filename() {
        let mut meta = PayloadMeta::file("test.txt".into(), "text/plain".into());
        meta.filename = None;
        assert!(extract_file_hint(&meta).is_none());
    }

    #[test]
    fn extract_hint_missing_type() {
        let mut meta = PayloadMeta::text();
        meta.filename = Some("test.txt".into());
        meta.mime = Some("text/plain".into());
        assert!(extract_file_hint(&meta).is_none());
    }

    #[test]
    fn build_hint_root_path() {
        // Path "/" has no file_name component
        assert!(build_file_metadata("/").is_none());
    }
}
