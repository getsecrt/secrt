use std::io::Write;

use crate::cli::{parse_flags, print_gen_help, CliError, Deps, ParsedArgs};
use crate::envelope::EnvelopeError;
use crate::passphrase::write_error;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@*^_+-=?";

pub fn run_gen(args: &[String], deps: &mut Deps) -> i32 {
    let pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_gen_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };

    // Combined mode: `secrt gen send ...` → delegate to run_send
    if pa.args.iter().any(|a| a == "send") {
        let new_args: Vec<String> = args
            .iter()
            .map(|a| {
                if a == "send" {
                    "gen".to_string()
                } else {
                    a.clone()
                }
            })
            .collect();
        return crate::send::run_send(&new_args, deps);
    }

    let count = if pa.gen_count == 0 { 1 } else { pa.gen_count } as usize;

    // Generate passwords
    let mut passwords = Vec::with_capacity(count);
    for _ in 0..count {
        match generate_password_from_args(&pa, &*deps.rand_bytes) {
            Ok(pw) => passwords.push(pw),
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, (deps.is_tty)(), &e);
                return 2;
            }
        }
    }

    // Output
    if pa.json {
        if count == 1 {
            let out = serde_json::json!({ "password": passwords[0] });
            let _ = writeln!(deps.stdout, "{}", serde_json::to_string(&out).unwrap());
        } else {
            let out = serde_json::json!({ "passwords": passwords });
            let _ = writeln!(deps.stdout, "{}", serde_json::to_string(&out).unwrap());
        }
    } else {
        for pw in &passwords {
            let _ = writeln!(deps.stdout, "{}", pw);
        }
    }

    0
}

/// Generate a single password using the gen flags from ParsedArgs.
/// Used by both `run_gen` and `send.rs` in combined mode.
pub fn generate_password_from_args(
    pa: &ParsedArgs,
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<String, String> {
    let length = if pa.gen_length == 0 {
        20
    } else {
        pa.gen_length
    } as usize;

    // Build character classes (lowercase always on)
    let mut classes: Vec<&[u8]> = vec![LOWERCASE];
    if !pa.gen_no_caps {
        classes.push(UPPERCASE);
    }
    if !pa.gen_no_numbers {
        classes.push(DIGITS);
    }
    if !pa.gen_no_symbols {
        classes.push(SYMBOLS);
    }

    let required = classes.len();
    if length < required {
        return Err(format!(
            "length {} is too short; need at least {} for the enabled character classes",
            length, required
        ));
    }

    generate_password(length, &classes, pa.gen_grouped, rand_bytes)
        .map_err(|e| format!("generation failed: {}", e))
}

/// Generate a uniform random number in `[0, range)` using rejection sampling.
fn random_usize(
    range: usize,
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<usize, EnvelopeError> {
    debug_assert!(range > 0);
    if range == 1 {
        return Ok(0);
    }

    if range <= 256 {
        let n = range as u16;
        let limit = 256u16 - (256u16 % n);
        loop {
            let mut buf = [0u8; 1];
            rand_bytes(&mut buf)?;
            if (buf[0] as u16) < limit {
                return Ok((buf[0] as usize) % range);
            }
        }
    } else {
        let n = range as u64;
        let total = 1u64 << 32;
        let limit = total - (total % n);
        loop {
            let mut buf = [0u8; 4];
            rand_bytes(&mut buf)?;
            let val = u32::from_le_bytes(buf) as u64;
            if val < limit {
                return Ok((val % n) as usize);
            }
        }
    }
}

/// Pick a random character from `charset` using unbiased rejection sampling.
fn random_char(
    charset: &[u8],
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<u8, EnvelopeError> {
    Ok(charset[random_usize(charset.len(), rand_bytes)?])
}

/// Fisher-Yates shuffle using crypto RNG.
fn shuffle(
    chars: &mut [u8],
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<(), EnvelopeError> {
    for i in (1..chars.len()).rev() {
        let j = random_usize(i + 1, rand_bytes)?;
        chars.swap(i, j);
    }
    Ok(())
}

fn generate_password(
    length: usize,
    classes: &[&[u8]],
    grouped: bool,
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<String, EnvelopeError> {
    if grouped {
        return generate_grouped(length, classes, rand_bytes);
    }

    // Build combined charset
    let mut charset = Vec::new();
    for class in classes {
        charset.extend_from_slice(class);
    }

    // Guarantee: one char from each enabled class
    let mut chars = Vec::with_capacity(length);
    for class in classes {
        chars.push(random_char(class, rand_bytes)?);
    }

    // Fill remaining from combined charset
    for _ in chars.len()..length {
        chars.push(random_char(&charset, rand_bytes)?);
    }

    // Shuffle all positions
    shuffle(&mut chars, rand_bytes)?;

    Ok(String::from_utf8(chars).unwrap())
}

fn generate_grouped(
    length: usize,
    classes: &[&[u8]],
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<String, EnvelopeError> {
    // Allocate positions: 1 per class guaranteed, distribute remaining randomly
    let mut counts: Vec<usize> = vec![1; classes.len()];
    let remaining = length - classes.len();
    for _ in 0..remaining {
        let idx = random_usize(classes.len(), rand_bytes)?;
        counts[idx] += 1;
    }

    // Generate chars for each class
    let mut groups: Vec<Vec<u8>> = Vec::with_capacity(classes.len());
    for (i, class) in classes.iter().enumerate() {
        let mut group = Vec::with_capacity(counts[i]);
        for _ in 0..counts[i] {
            group.push(random_char(class, rand_bytes)?);
        }
        shuffle(&mut group, rand_bytes)?;
        groups.push(group);
    }

    // Randomize group order
    let n = groups.len();
    for i in (1..n).rev() {
        let j = random_usize(i + 1, rand_bytes)?;
        groups.swap(i, j);
    }

    // Concatenate
    let mut result = Vec::with_capacity(length);
    for group in &groups {
        result.extend_from_slice(group);
    }

    Ok(String::from_utf8(result).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic RNG that cycles through 0..255.
    fn make_counter_rng() -> impl Fn(&mut [u8]) -> Result<(), EnvelopeError> {
        use std::cell::Cell;
        let counter = Cell::new(0u8);
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter.get();
                counter.set(counter.get().wrapping_add(1));
            }
            Ok(())
        }
    }

    #[test]
    fn basic_password_has_correct_length() {
        let rng = make_counter_rng();
        let classes: Vec<&[u8]> = vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS];
        let pw = generate_password(20, &classes, false, &rng).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn password_contains_all_classes() {
        let rng = make_counter_rng();
        let classes: Vec<&[u8]> = vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS];
        let pw = generate_password(20, &classes, false, &rng).unwrap();
        assert!(pw.bytes().any(|b| LOWERCASE.contains(&b)));
        assert!(pw.bytes().any(|b| UPPERCASE.contains(&b)));
        assert!(pw.bytes().any(|b| DIGITS.contains(&b)));
        assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn lowercase_only() {
        let rng = make_counter_rng();
        let classes: Vec<&[u8]> = vec![LOWERCASE];
        let pw = generate_password(16, &classes, false, &rng).unwrap();
        assert_eq!(pw.len(), 16);
        assert!(pw.bytes().all(|b| LOWERCASE.contains(&b)));
    }

    #[test]
    fn grouped_has_correct_length() {
        let rng = make_counter_rng();
        let classes: Vec<&[u8]> = vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS];
        let pw = generate_grouped(20, &classes, &rng).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn grouped_contains_all_classes() {
        let rng = make_counter_rng();
        let classes: Vec<&[u8]> = vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS];
        let pw = generate_grouped(20, &classes, &rng).unwrap();
        assert!(pw.bytes().any(|b| LOWERCASE.contains(&b)));
        assert!(pw.bytes().any(|b| UPPERCASE.contains(&b)));
        assert!(pw.bytes().any(|b| DIGITS.contains(&b)));
        assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn minimum_length_equals_classes() {
        let rng = make_counter_rng();
        let classes: Vec<&[u8]> = vec![LOWERCASE, UPPERCASE, DIGITS, SYMBOLS];
        let pw = generate_password(4, &classes, false, &rng).unwrap();
        assert_eq!(pw.len(), 4);
        // Each class represented exactly once
        assert!(pw.bytes().any(|b| LOWERCASE.contains(&b)));
        assert!(pw.bytes().any(|b| UPPERCASE.contains(&b)));
        assert!(pw.bytes().any(|b| DIGITS.contains(&b)));
        assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn random_usize_single_value() {
        let rng = make_counter_rng();
        assert_eq!(random_usize(1, &rng).unwrap(), 0);
    }

    #[test]
    fn random_usize_within_range() {
        let rng = make_counter_rng();
        for _ in 0..100 {
            let val = random_usize(10, &rng).unwrap();
            assert!(val < 10);
        }
    }
}
