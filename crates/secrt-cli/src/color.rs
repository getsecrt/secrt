// Semantic color tokens
pub const CMD: &str = "36"; // cyan — command names
pub const OPT: &str = "33"; // yellow — flags/options
pub const ARG: &str = "2"; // dim — argument placeholders
pub const HEADING: &str = "1"; // bold — section headings
pub const SUCCESS: &str = "32"; // green — success indicators
pub const ERROR: &str = "31"; // red — error prefix
pub const URL: &str = "1;36"; // bold cyan — share URLs
pub const LABEL: &str = "37"; // white — prompt labels (Secret:, Passphrase:)
pub const DIM: &str = "2"; // dim — status messages, hints, secondary text
pub const WARN: &str = "33"; // yellow — warnings, in-progress

pub type ColorFn = Box<dyn Fn(&str, &str) -> String>;

/// Returns a function that wraps text in ANSI escape codes if is_tty is true.
pub fn color_func(is_tty: bool) -> ColorFn {
    if is_tty {
        Box::new(|code: &str, text: &str| format!("\x1b[{}m{}\x1b[0m", code, text))
    } else {
        Box::new(|_code: &str, text: &str| text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_wraps_ansi() {
        let c = color_func(true);
        assert_eq!(c("36", "text"), "\x1b[36mtext\x1b[0m");
    }

    #[test]
    fn non_tty_plain() {
        let c = color_func(false);
        assert_eq!(c("36", "text"), "text");
    }
}
