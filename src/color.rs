pub type ColorFn = Box<dyn Fn(&str, &str) -> String>;

/// Returns a function that wraps text in ANSI escape codes if is_tty is true.
pub fn color_func(is_tty: bool) -> ColorFn {
    if is_tty {
        Box::new(|code: &str, text: &str| format!("\x1b[{}m{}\x1b[0m", code, text))
    } else {
        Box::new(|_code: &str, text: &str| text.to_string())
    }
}
