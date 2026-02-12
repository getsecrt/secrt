/// Return a MIME type for a file extension (case-insensitive).
/// Falls back to `application/octet-stream` for unknown extensions.
pub fn mime_from_extension(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        // Text
        "txt" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "xml" => "text/xml",
        "md" => "text/markdown",
        "yaml" | "yml" => "text/yaml",

        // Images
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",

        // Application
        "json" => "application/json",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "wasm" => "application/wasm",
        "toml" => "application/toml",
        "sql" => "application/sql",

        // Crypto / keys
        "pem" => "application/x-pem-file",
        "key" => "application/x-pem-file",
        "crt" | "cer" => "application/x-x509-ca-cert",
        "p12" | "pfx" => "application/x-pkcs12",
        "asc" => "application/pgp-keys",

        // Archives
        "7z" => "application/x-7z-compressed",
        "rar" => "application/x-rar-compressed",

        // Other
        "env" => "text/plain",
        "sh" | "bash" => "text/x-shellscript",
        "rs" => "text/x-rust",
        "go" => "text/x-go",
        "py" => "text/x-python",
        "rb" => "text/x-ruby",
        "ts" => "text/typescript",
        "tsx" | "jsx" => "text/javascript",

        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_extensions() {
        assert_eq!(mime_from_extension("png"), "image/png");
        assert_eq!(mime_from_extension("jpg"), "image/jpeg");
        assert_eq!(mime_from_extension("jpeg"), "image/jpeg");
        assert_eq!(mime_from_extension("pdf"), "application/pdf");
        assert_eq!(mime_from_extension("json"), "application/json");
        assert_eq!(mime_from_extension("txt"), "text/plain");
        assert_eq!(mime_from_extension("pem"), "application/x-pem-file");
        assert_eq!(mime_from_extension("key"), "application/x-pem-file");
        assert_eq!(mime_from_extension("zip"), "application/zip");
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(mime_from_extension("PNG"), "image/png");
        assert_eq!(mime_from_extension("Pdf"), "application/pdf");
        assert_eq!(mime_from_extension("JSON"), "application/json");
    }

    #[test]
    fn unknown_extension() {
        assert_eq!(mime_from_extension("xyz"), "application/octet-stream");
        assert_eq!(mime_from_extension(""), "application/octet-stream");
    }
}
