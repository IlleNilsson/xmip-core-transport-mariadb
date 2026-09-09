//! What a server answers with: the OK packet that completes a statement
//! and closes the login, the ERR packet that refuses either, the EOF
//! packet that bounds the columns and the rows of a result set, and the
//! result set itself — a column count, one definition a column, one text
//! row a row. Written here as well as read, because the far-end
//! [`crate::Session`] writes exactly these.
//!
//! The first byte tells the packets apart: `0x00` opens OK, `0xFF` opens
//! ERR, `0xFE` in a packet under nine bytes is EOF, and anything else is
//! the column count that opens a result set — or, inside one, a row.

use transport::error::{Result, protocol_error};

use crate::wire::{Cursor, lenenc_bytes, lenenc_int};

/// Opens an OK packet.
pub const OK_HEADER: u8 = 0x00;
/// Opens an ERR packet.
pub const ERR_HEADER: u8 = 0xff;
/// Opens an EOF packet, and an authentication switch.
pub const EOF_HEADER: u8 = 0xfe;
/// A NULL in a text row.
pub const NULL_VALUE: u8 = 0xfb;
/// The column type a definition names: `MYSQL_TYPE_VAR_STRING`.
pub const VAR_STRING: u8 = 0xfd;
/// The rest of a definition after its names is twelve bytes.
const FIXED_FIELDS: u64 = 0x0c;

/// What a server sends in answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Ok {
        affected_rows: u64,
        last_insert_id: u64,
        status: u16,
        warnings: u16,
    },
    Err {
        code: u16,
        state: String,
        message: String,
    },
    Eof {
        warnings: u16,
        status: u16,
    },
    /// Neither: a column count, a column definition, a row, or the
    /// plugin's own packet, taken as it came.
    Data(Vec<u8>),
}

/// `reply` as a payload; `Data` is its bytes.
#[must_use]
pub fn encode_reply(reply: &Reply) -> Vec<u8> {
    let mut out = Vec::new();
    match reply {
        Reply::Ok {
            affected_rows,
            last_insert_id,
            status,
            warnings,
        } => {
            out.push(OK_HEADER);
            lenenc_int(&mut out, *affected_rows);
            lenenc_int(&mut out, *last_insert_id);
            out.extend_from_slice(&status.to_le_bytes());
            out.extend_from_slice(&warnings.to_le_bytes());
        }
        Reply::Err {
            code,
            state,
            message,
        } => {
            out.push(ERR_HEADER);
            out.extend_from_slice(&code.to_le_bytes());
            out.push(b'#');
            let mut state = state.clone();
            state.truncate(5);
            while state.len() < 5 {
                state.push('0');
            }
            out.extend_from_slice(state.as_bytes());
            out.extend_from_slice(message.as_bytes());
        }
        Reply::Eof { warnings, status } => {
            out.push(EOF_HEADER);
            out.extend_from_slice(&warnings.to_le_bytes());
            out.extend_from_slice(&status.to_le_bytes());
        }
        Reply::Data(bytes) => out.extend_from_slice(bytes),
    }
    out
}

/// The reply a payload carries.
///
/// # Errors
/// An OK, ERR or EOF packet that breaks off, or an empty payload.
pub fn decode_reply(payload: &[u8]) -> Result<Reply> {
    let mut cursor = Cursor::new(payload);
    match payload.first() {
        None => Err(protocol_error("an empty reply")),
        Some(&OK_HEADER) => {
            cursor.skip(1)?;
            Ok(Reply::Ok {
                affected_rows: cursor.lenenc_int()?,
                last_insert_id: cursor.lenenc_int()?,
                status: cursor.int16()?,
                warnings: cursor.int16()?,
            })
        }
        Some(&ERR_HEADER) => {
            cursor.skip(1)?;
            let code = cursor.int16()?;
            let state = if cursor.peek() == Some(b'#') {
                cursor.skip(1)?;
                String::from_utf8_lossy(cursor.take(5)?).into_owned()
            } else {
                String::new()
            };
            let message = String::from_utf8_lossy(cursor.rest()).into_owned();
            Ok(Reply::Err {
                code,
                state,
                message,
            })
        }
        Some(&EOF_HEADER) if payload.len() < 9 => {
            cursor.skip(1)?;
            Ok(Reply::Eof {
                warnings: cursor.int16()?,
                status: cursor.int16()?,
            })
        }
        Some(_) => Ok(Reply::Data(payload.to_vec())),
    }
}

/// The reply a payload carries inside a result set, where a leading
/// `0x00` is a row whose first value is empty, not an OK packet: without
/// `CLIENT_DEPRECATE_EOF` no OK arrives between the column count and the
/// closing EOF.
///
/// # Errors
/// An ERR or EOF packet that breaks off, or an empty payload.
pub fn decode_in_result_set(payload: &[u8]) -> Result<Reply> {
    match payload.first() {
        Some(&OK_HEADER) => Ok(Reply::Data(payload.to_vec())),
        _ => decode_reply(payload),
    }
}

/// A count of columns, as the packet that opens a result set.
#[must_use]
pub fn encode_column_count(count: usize) -> Vec<u8> {
    let mut out = Vec::new();
    lenenc_int(&mut out, u64::try_from(count).unwrap_or(u64::MAX));
    out
}

/// The count a result set opens with.
///
/// # Errors
/// A payload that is not one length-encoded integer.
pub fn decode_column_count(payload: &[u8]) -> Result<usize> {
    let mut cursor = Cursor::new(payload);
    let count = cursor.lenenc_int()?;
    if !cursor.is_empty() {
        return Err(protocol_error("a column count with something after it"));
    }
    usize::try_from(count).map_err(|_| protocol_error("more columns than memory"))
}

/// A column definition naming `name`, typed as a string with no table
/// behind it — enough for a reader that takes every value as text.
#[must_use]
pub fn encode_column(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    lenenc_bytes(&mut out, b"def");
    lenenc_bytes(&mut out, b"");
    lenenc_bytes(&mut out, b"");
    lenenc_bytes(&mut out, b"");
    lenenc_bytes(&mut out, name.as_bytes());
    lenenc_bytes(&mut out, name.as_bytes());
    lenenc_int(&mut out, FIXED_FIELDS);
    out.extend_from_slice(&45u16.to_le_bytes()); // utf8mb4
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // column length
    out.push(VAR_STRING);
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.push(0); // decimals
    out.extend_from_slice(&[0, 0]);
    out
}

/// The name a column definition carries.
///
/// # Errors
/// A definition that breaks off before its name.
pub fn decode_column(payload: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(payload);
    for _ in 0..4 {
        cursor.lenenc_str()?;
    }
    cursor.lenenc_str()
}

/// One row, each value as text or NULL.
#[must_use]
pub fn encode_row(values: &[Option<String>]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        match value {
            Some(text) => lenenc_bytes(&mut out, text.as_bytes()),
            None => out.push(NULL_VALUE),
        }
    }
    out
}

/// The `count` values a row carries.
///
/// # Errors
/// A row with fewer values than columns, or one that breaks off.
pub fn decode_row(payload: &[u8], count: usize) -> Result<Vec<Option<String>>> {
    let mut cursor = Cursor::new(payload);
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.peek() == Some(NULL_VALUE) {
            cursor.skip(1)?;
            values.push(None);
        } else {
            values.push(Some(cursor.lenenc_str()?));
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reply_round_trips() {
        for reply in [
            Reply::Ok {
                affected_rows: 1,
                last_insert_id: 300,
                status: 2,
                warnings: 0,
            },
            Reply::Err {
                code: 1045,
                state: "28000".into(),
                message: "Access denied for user 'xmip'@'localhost'".into(),
            },
            Reply::Eof {
                warnings: 0,
                status: 2,
            },
            Reply::Data(vec![3]),
            Reply::Data(vec![0xfe, 1, 2, 3, 4, 5, 6, 7, 8]),
        ] {
            let bytes = encode_reply(&reply);
            assert_eq!(decode_reply(&bytes).expect("reply"), reply);
        }
        assert!(decode_reply(&[]).is_err());
        assert!(decode_reply(&[OK_HEADER, 1]).is_err(), "breaks off");
        assert_eq!(
            decode_in_result_set(&[0, 2, b'4', b'1']).expect("a row"),
            Reply::Data(vec![0, 2, b'4', b'1']),
            "an empty first value is not OK"
        );
        assert!(matches!(
            decode_in_result_set(&[EOF_HEADER, 0, 0, 2, 0]).expect("eof"),
            Reply::Eof { .. }
        ));
        assert_eq!(
            decode_reply(&[ERR_HEADER, 0x15, 0x04, b'n', b'o']).expect("no state"),
            Reply::Err {
                code: 1045,
                state: String::new(),
                message: "no".into()
            }
        );
        let short_state = encode_reply(&Reply::Err {
            code: 1,
            state: "HY".into(),
            message: String::new(),
        });
        assert_eq!(&short_state[3..9], b"#HY000");
    }

    #[test]
    fn a_result_set_is_a_count_definitions_and_rows() {
        assert_eq!(
            decode_column_count(&encode_column_count(2)).expect("count"),
            2
        );
        assert!(decode_column_count(&[2, 0]).is_err(), "something after it");
        assert!(decode_column_count(&[NULL_VALUE]).is_err());
        assert_eq!(
            decode_column(&encode_column("payload")).expect("name"),
            "payload"
        );
        assert!(decode_column(&[3, b'd', b'e']).is_err(), "breaks off");
        let row = vec![Some("41".to_string()), None, Some(String::new())];
        let bytes = encode_row(&row);
        assert_eq!(bytes, [2, b'4', b'1', NULL_VALUE, 0]);
        assert_eq!(decode_row(&bytes, 3).expect("row"), row);
        assert!(decode_row(&bytes, 4).is_err(), "fewer values than columns");
        assert!(decode_row(&[5, b'x'], 1).is_err(), "breaks off");
    }
}
