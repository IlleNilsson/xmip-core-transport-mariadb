//! A Stream that is not text, carried the way `MySQL` itself writes
//! binary: the hexadecimal literal, `X'` and two digits a byte.
//!
//! A text column holds UTF-8 without a NUL and nothing else, so a Stream
//! that is anything else is inserted as the `X'…'` literal a BLOB or
//! VARBINARY column stores as the bytes. Coming back over the text
//! protocol a BLOB is its raw bytes, which the row reader takes as text
//! and mangles, so a receive query that carries binary spells it out —
//! `SELECT id, CONCAT('0x', HEX(payload)) FROM inbox` — and a value in
//! either hex form, `X'…'` or `0x…`, is the bytes again on the way back.
//! Text that happens to be in one of those forms is read as bytes; that
//! is the price of one column carrying both, and it is paid on purpose.

use std::fmt::Write as _;

/// True when `bytes` can be one text column: UTF-8 without a NUL.
#[must_use]
pub fn is_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| !text.contains('\0'))
}

/// `bytes` as the hexadecimal literal: `X'` then two lower-case digits a
/// byte, then `'`. Unquoted, as a literal goes into a statement.
#[must_use]
pub fn hex_literal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(3 + bytes.len() * 2);
    out.push_str("X'");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out.push('\'');
    out
}

/// The bytes a value in a hex form names — `X'…'`, `x'…'` or `0x…` —
/// or `None` when `text` is not in one.
#[must_use]
pub fn from_hex_literal(text: &str) -> Option<Vec<u8>> {
    let digits = match text.strip_prefix("X'").or_else(|| text.strip_prefix("x'")) {
        Some(quoted) => quoted.strip_suffix('\'')?,
        None => text.strip_prefix("0x")?,
    };
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(digits.get(at..at + 2)?, 16).ok())
        .collect()
}

/// A column value as the bytes it carries: decoded when in a hex form,
/// the text's bytes otherwise.
#[must_use]
pub fn column_bytes(text: String) -> Vec<u8> {
    from_hex_literal(&text).unwrap_or_else(|| text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_utf8_without_a_nul() {
        assert!(is_text(b"a row"));
        assert!(is_text(b""));
        assert!(!is_text(b"a\0row"));
        assert!(!is_text(&[0xff, 0xfe]));
    }

    #[test]
    fn bytes_round_trip_through_the_hex_form() {
        let bytes: Vec<u8> = (0..=255).collect();
        let literal = hex_literal(&bytes);
        assert!(literal.starts_with("X'000102"));
        assert!(literal.ends_with("feff'"));
        assert_eq!(from_hex_literal(&literal), Some(bytes.clone()));
        assert_eq!(column_bytes(literal), bytes);
        assert_eq!(hex_literal(b""), "X''");
        assert_eq!(from_hex_literal("X''"), Some(Vec::new()));
        assert_eq!(from_hex_literal("0xFFfe"), Some(vec![0xff, 0xfe]));
        assert_eq!(from_hex_literal("x'0a'"), Some(vec![0x0a]));
    }

    #[test]
    fn what_is_not_a_hex_form_is_text() {
        assert_eq!(from_hex_literal("plain"), None);
        assert_eq!(from_hex_literal("X'abc'"), None, "an odd digit count");
        assert_eq!(from_hex_literal("X'zz'"), None, "not hex");
        assert_eq!(from_hex_literal("X'ab"), None, "never closed");
        assert_eq!(from_hex_literal("0x"), Some(Vec::new()));
        assert_eq!(column_bytes("plain".to_string()), b"plain");
    }
}
