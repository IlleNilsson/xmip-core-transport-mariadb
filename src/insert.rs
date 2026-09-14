//! The one statement the far-end [`crate::Session`] reads rather than
//! answers blindly: `INSERT INTO t (c) VALUES (...)`, taken apart so the
//! value a client sent comes back as the Stream it was — the inverse of
//! [`crate::quote_literal`] and of the `X'…'` literal, with the escapes
//! the server would undo undone here. The statement's shape is the
//! capability's (`transport::sql`, ADR-0044); the dialect is here.

use transport::sql;

use crate::hex::from_hex_literal;

/// `INSERT INTO <table> (<column>) VALUES (<literal>)` taken apart: the
/// table, the column and the value — a quoted string with its escapes
/// undone, or the bytes of an `X'…'` literal. Identifiers may be in
/// backticks; anything else is `None`.
#[must_use]
pub fn parse_insert(statement: &str) -> Option<(String, String, Vec<u8>)> {
    sql::parse_insert(statement, identifier, literal)
}

/// One literal — `'…'` with backslash escapes, or `X'…'` — and what
/// follows it.
fn literal(rest: &str) -> Option<(Vec<u8>, &str)> {
    if rest.starts_with("X'") || rest.starts_with("x'") {
        let end = rest[2..].find('\'')? + 3;
        return Some((from_hex_literal(&rest[..end])?, &rest[end..]));
    }
    let mut chars = rest.strip_prefix('\'')?.char_indices().peekable();
    let mut value = String::new();
    loop {
        let (at, c) = chars.next()?;
        match c {
            '\'' if chars.peek().is_some_and(|(_, next)| *next == '\'') => {
                chars.next();
                value.push('\'');
            }
            '\'' => return Some((value.into_bytes(), &rest[at + 2..])),
            '\\' => {
                let escaped = chars.next()?.1;
                let unescaped = match escaped {
                    '0' => '\0',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'b' => '\u{8}',
                    'Z' => '\u{1a}',
                    // A LIKE wildcard keeps its backslash, as the server keeps it.
                    '%' | '_' => {
                        value.push('\\');
                        escaped
                    }
                    other => other,
                };
                value.push(unescaped);
            }
            other => value.push(other),
        }
    }
}

/// One identifier, bare or in backticks, and what follows it.
fn identifier(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if let Some(quoted) = rest.strip_prefix('`') {
        let end = quoted.find('`')?;
        return Some((quoted[..end].to_string(), &quoted[end + 1..]));
    }
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .unwrap_or(rest.len());
    (end > 0).then(|| (rest[..end].to_string(), &rest[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_insert_of_one_column_is_taken_apart() {
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES ('it\\'s here');"),
            Some(("inbox".into(), "payload".into(), b"it's here".to_vec()))
        );
        assert_eq!(
            parse_insert("insert into `In box` ( `Payload` ) values ( '' )"),
            Some(("In box".into(), "Payload".into(), Vec::new()))
        );
        assert_eq!(
            parse_insert("INSERT INTO orders.inbox (payload) VALUES ('a\\nb''c\\\\d\\%e')"),
            Some((
                "orders.inbox".into(),
                "payload".into(),
                b"a\nb'c\\d\\%e".to_vec()
            ))
        );
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES (X'fffe')"),
            Some(("inbox".into(), "payload".into(), vec![0xff, 0xfe]))
        );
        assert!(parse_insert("INSERT INTO inbox (a, b) VALUES ('x', 'y')").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES ('open").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES (X'abc')").is_none());
        assert!(parse_insert("UPDATE inbox SET a = 'x'").is_none());
    }
}
