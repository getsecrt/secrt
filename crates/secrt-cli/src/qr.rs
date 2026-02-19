/// Render a QR code compactly using Unicode half-block characters.
///
/// Each terminal character encodes two vertical QR modules using ▀/▄/█/space,
/// halving the height. Combined with 1 char per module width (terminal chars
/// are ~2:1 height:width), modules render roughly square at ~1/4 the area of
/// the standard char renderer.
pub fn render_qr_compact(code: &qrcode::QrCode) -> String {
    use qrcode::types::Color;

    let w = code.width();
    let modules = code.to_colors();
    let quiet = 1usize;
    let total = w + 2 * quiet;

    let is_dark = |r: usize, c: usize| -> bool {
        if r < quiet || r >= quiet + w || c < quiet || c >= quiet + w {
            false
        } else {
            modules[(r - quiet) * w + (c - quiet)] == Color::Dark
        }
    };

    let mut out = String::new();
    let mut row = 0;
    while row < total {
        let has_bot = row + 1 < total;
        for col in 0..total {
            let top = is_dark(row, col);
            let bot = has_bot && is_dark(row + 1, col);
            out.push(match (top, bot) {
                (true, true) => '\u{2588}',  // █ full block
                (true, false) => '\u{2580}', // ▀ upper half
                (false, true) => '\u{2584}', // ▄ lower half
                (false, false) => ' ',
            });
        }
        out.push('\n');
        row += 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_produces_nonempty_output() {
        let code = qrcode::QrCode::new(b"https://secrt.ca/s/test#key123").unwrap();
        let rendered = render_qr_compact(&code);
        assert!(!rendered.is_empty());
        assert!(rendered.contains('\n'));
        // Should contain at least some block characters
        assert!(
            rendered.contains('\u{2588}')
                || rendered.contains('\u{2580}')
                || rendered.contains('\u{2584}')
        );
    }

    #[test]
    fn render_is_deterministic() {
        let code = qrcode::QrCode::new(b"test").unwrap();
        let a = render_qr_compact(&code);
        let b = render_qr_compact(&code);
        assert_eq!(a, b);
    }
}
