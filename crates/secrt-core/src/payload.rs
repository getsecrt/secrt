use crate::types::*;

const FRAME_HEADER_LEN: usize = 16;

const CODEC_NONE: u8 = 0;
const CODEC_ZSTD: u8 = 1;

fn codec_id(codec: PayloadCodec) -> u8 {
    match codec {
        PayloadCodec::None => CODEC_NONE,
        PayloadCodec::Zstd => CODEC_ZSTD,
    }
}

fn parse_codec(id: u8) -> Result<PayloadCodec, EnvelopeError> {
    match id {
        CODEC_NONE => Ok(PayloadCodec::None),
        CODEC_ZSTD => Ok(PayloadCodec::Zstd),
        v => Err(EnvelopeError::UnsupportedCodec(v)),
    }
}

fn has_magic_prefix(data: &[u8], magic: &[u8]) -> bool {
    data.len() >= magic.len() && &data[..magic.len()] == magic
}

fn looks_precompressed(data: &[u8]) -> bool {
    // png
    if has_magic_prefix(data, b"\x89PNG\r\n\x1A\n") {
        return true;
    }
    // jpg/jpeg
    if has_magic_prefix(data, b"\xFF\xD8\xFF") {
        return true;
    }
    // gif
    if has_magic_prefix(data, b"GIF87a") || has_magic_prefix(data, b"GIF89a") {
        return true;
    }
    // webp (RIFF....WEBP)
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return true;
    }
    // zip
    if has_magic_prefix(data, b"PK\x03\x04")
        || has_magic_prefix(data, b"PK\x05\x06")
        || has_magic_prefix(data, b"PK\x07\x08")
    {
        return true;
    }
    // gzip
    if has_magic_prefix(data, b"\x1F\x8B") {
        return true;
    }
    // bzip2
    if has_magic_prefix(data, b"BZh") {
        return true;
    }
    // xz
    if has_magic_prefix(data, b"\xFD7zXZ\x00") {
        return true;
    }
    // zstd
    if has_magic_prefix(data, b"\x28\xB5\x2F\xFD") {
        return true;
    }
    // 7z
    if has_magic_prefix(data, b"7z\xBC\xAF\x27\x1C") {
        return true;
    }
    // pdf
    if has_magic_prefix(data, b"%PDF-") {
        return true;
    }
    // mp4 (ftyp box)
    if data.len() >= 8 && &data[4..8] == b"ftyp" {
        return true;
    }
    // mp3
    if has_magic_prefix(data, b"ID3")
        || (data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0)
    {
        return true;
    }
    false
}

fn build_frame(
    content: &[u8],
    metadata: &PayloadMeta,
    codec: PayloadCodec,
    body: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let meta_bytes = serde_json::to_vec(metadata)
        .map_err(|e| EnvelopeError::InvalidFrame(format!("serialize metadata: {}", e)))?;

    let meta_len = u32::try_from(meta_bytes.len())
        .map_err(|_| EnvelopeError::InvalidFrame("metadata too large".into()))?;
    let raw_len = u32::try_from(content.len())
        .map_err(|_| EnvelopeError::InvalidFrame("content too large".into()))?;

    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + meta_bytes.len() + body.len());
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.push(PAYLOAD_FRAME_VERSION);
    out.push(codec_id(codec));
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&meta_len.to_be_bytes());
    out.extend_from_slice(&raw_len.to_be_bytes());
    out.extend_from_slice(&meta_bytes);
    out.extend_from_slice(body);

    Ok(out)
}

pub fn encode_payload(
    content: &[u8],
    metadata: &PayloadMeta,
    policy: CompressionPolicy,
) -> Result<(Vec<u8>, PayloadCodec), EnvelopeError> {
    let mut codec = PayloadCodec::None;
    let mut body = content.to_vec();

    if content.len() >= policy.threshold_bytes && !looks_precompressed(content) {
        let compressed = zstd::bulk::compress(content, policy.zstd_level)
            .map_err(|e| EnvelopeError::CompressionFailed(e.to_string()))?;

        if compressed.len() < content.len() {
            let savings = content.len() - compressed.len();
            let ratio = savings as f64 / content.len() as f64;
            if savings >= policy.min_savings_bytes && ratio >= policy.min_savings_ratio {
                codec = PayloadCodec::Zstd;
                body = compressed;
            }
        }
    }

    let frame = build_frame(content, metadata, codec, &body)?;
    Ok((frame, codec))
}

pub fn decode_payload(
    frame: &[u8],
    max_decompressed_bytes: usize,
) -> Result<OpenResult, EnvelopeError> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(EnvelopeError::InvalidFrame("frame too short".into()));
    }
    if &frame[0..4] != PAYLOAD_MAGIC {
        return Err(EnvelopeError::InvalidFrame("invalid magic".into()));
    }
    if frame[4] != PAYLOAD_FRAME_VERSION {
        return Err(EnvelopeError::InvalidFrame(format!(
            "unsupported frame version {}",
            frame[4]
        )));
    }

    let codec = parse_codec(frame[5])?;
    let reserved = u16::from_be_bytes([frame[6], frame[7]]);
    if reserved != 0 {
        return Err(EnvelopeError::InvalidFrame(
            "reserved field must be zero".into(),
        ));
    }

    let meta_len = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
    let raw_len = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]) as usize;

    if raw_len > max_decompressed_bytes {
        return Err(EnvelopeError::DecompressedTooLarge {
            max: max_decompressed_bytes,
            requested: raw_len,
        });
    }

    let meta_end = FRAME_HEADER_LEN
        .checked_add(meta_len)
        .ok_or_else(|| EnvelopeError::InvalidFrame("metadata length overflow".into()))?;
    if meta_end > frame.len() {
        return Err(EnvelopeError::InvalidFrame(
            "metadata length exceeds frame size".into(),
        ));
    }

    let metadata: PayloadMeta = serde_json::from_slice(&frame[FRAME_HEADER_LEN..meta_end])
        .map_err(|e| EnvelopeError::InvalidFrame(format!("invalid metadata json: {}", e)))?;

    let body = &frame[meta_end..];
    let content = match codec {
        PayloadCodec::None => {
            if body.len() != raw_len {
                return Err(EnvelopeError::FrameLengthMismatch(format!(
                    "codec=none body bytes {} != raw_len {}",
                    body.len(),
                    raw_len
                )));
            }
            body.to_vec()
        }
        PayloadCodec::Zstd => {
            let decompressed = zstd::bulk::decompress(body, raw_len)
                .map_err(|e| EnvelopeError::DecompressionFailed(e.to_string()))?;
            if decompressed.len() != raw_len {
                return Err(EnvelopeError::FrameLengthMismatch(format!(
                    "codec=zstd decompressed bytes {} != raw_len {}",
                    decompressed.len(),
                    raw_len
                )));
            }
            decompressed
        }
    };

    Ok(OpenResult {
        content,
        metadata,
        codec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_none_codec() {
        let policy = CompressionPolicy {
            threshold_bytes: 4096,
            ..CompressionPolicy::default()
        };
        let meta = PayloadMeta::text();
        let content = b"small text secret".to_vec();

        let (frame, codec) = encode_payload(&content, &meta, policy).expect("encode");
        assert_eq!(codec, PayloadCodec::None);

        let decoded = decode_payload(&frame, MAX_DECOMPRESSED_BYTES_DEFAULT).expect("decode");
        assert_eq!(decoded.codec, PayloadCodec::None);
        assert_eq!(decoded.content, content);
        assert_eq!(decoded.metadata, meta);
    }

    #[test]
    fn roundtrip_zstd_codec() {
        let mut content = Vec::new();
        for _ in 0..400 {
            content.extend_from_slice(b"secrt payload compression sample line\n");
        }
        let meta = PayloadMeta::text();

        let (frame, codec) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        assert_eq!(codec, PayloadCodec::Zstd);

        let decoded = decode_payload(&frame, MAX_DECOMPRESSED_BYTES_DEFAULT).expect("decode");
        assert_eq!(decoded.codec, PayloadCodec::Zstd);
        assert_eq!(decoded.content, content);
        assert_eq!(decoded.metadata, meta);
    }

    #[test]
    fn threshold_2047_stays_uncompressed() {
        let content = vec![b'a'; 2047];
        let meta = PayloadMeta::text();
        let (frame, codec) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        assert_eq!(codec, PayloadCodec::None);
        let decoded = decode_payload(&frame, MAX_DECOMPRESSED_BYTES_DEFAULT).expect("decode");
        assert_eq!(decoded.codec, PayloadCodec::None);
    }

    #[test]
    fn threshold_2048_allows_compression_when_beneficial() {
        let content = vec![b'a'; 2048];
        let meta = PayloadMeta::text();
        let (_, codec) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        assert_eq!(codec, PayloadCodec::Zstd);
    }

    #[test]
    fn min_savings_bytes_gate_blocks_compression() {
        let content = vec![b'a'; 2048];
        let meta = PayloadMeta::text();
        let policy = CompressionPolicy {
            min_savings_bytes: usize::MAX / 2,
            ..CompressionPolicy::default()
        };
        let (_, codec) = encode_payload(&content, &meta, policy).expect("encode");
        assert_eq!(codec, PayloadCodec::None);
    }

    #[test]
    fn min_savings_ratio_gate_blocks_compression() {
        let content = vec![b'a'; 2048];
        let meta = PayloadMeta::text();
        let policy = CompressionPolicy {
            min_savings_ratio: 1.0,
            ..CompressionPolicy::default()
        };
        let (_, codec) = encode_payload(&content, &meta, policy).expect("encode");
        assert_eq!(codec, PayloadCodec::None);
    }

    #[test]
    fn already_compressed_signature_skips_attempt() {
        let mut content = b"\x89PNG\r\n\x1A\n".to_vec();
        content.extend(vec![b'a'; 8192]);
        let meta = PayloadMeta::binary();
        let (_, codec) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        assert_eq!(codec, PayloadCodec::None);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let err = decode_payload(b"BAD!", MAX_DECOMPRESSED_BYTES_DEFAULT).expect_err("bad magic");
        assert!(matches!(err, EnvelopeError::InvalidFrame(_)));
    }

    #[test]
    fn decode_rejects_unknown_codec() {
        let content = b"hello world".to_vec();
        let meta = PayloadMeta::text();
        let (mut frame, _) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        frame[5] = 9;
        let err = decode_payload(&frame, MAX_DECOMPRESSED_BYTES_DEFAULT).expect_err("codec");
        assert!(matches!(err, EnvelopeError::UnsupportedCodec(9)));
    }

    #[test]
    fn decode_rejects_truncated_frame() {
        let content = b"hello world".to_vec();
        let meta = PayloadMeta::text();
        let (frame, _) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        let err = decode_payload(&frame[..8], MAX_DECOMPRESSED_BYTES_DEFAULT).expect_err("short");
        assert!(matches!(err, EnvelopeError::InvalidFrame(_)));
    }

    #[test]
    fn decode_rejects_raw_len_over_cap() {
        let content = b"hello world".to_vec();
        let meta = PayloadMeta::text();
        let (frame, _) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        let err = decode_payload(&frame, 8).expect_err("over cap");
        assert!(matches!(err, EnvelopeError::DecompressedTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_length_mismatch_none_codec() {
        let content = b"hello world".to_vec();
        let meta = PayloadMeta::text();
        let (mut frame, _) =
            encode_payload(&content, &meta, CompressionPolicy::default()).expect("encode");
        let bad = (content.len() as u32 + 1).to_be_bytes();
        frame[12..16].copy_from_slice(&bad);
        let err = decode_payload(&frame, MAX_DECOMPRESSED_BYTES_DEFAULT).expect_err("mismatch");
        assert!(matches!(err, EnvelopeError::FrameLengthMismatch(_)));
    }
}
