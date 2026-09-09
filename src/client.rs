//! The client's side of one connection to a server: the login, a query
//! and its rows, a statement and its count. The text protocol only, which
//! is what `COM_QUERY` gives.

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, TransportError, classify, protocol_error};
use transport::socket;

use crate::handshake::{
    CAPABILITIES, CLIENT_PROTOCOL_41, HandshakeResponse41, Login, NATIVE_PASSWORD,
    decode_auth_switch, decode_handshake, encode_response, scramble,
};
use crate::result::{
    EOF_HEADER, ERR_HEADER, Reply, decode_column, decode_column_count, decode_in_result_set,
    decode_reply, decode_row,
};
use crate::wire::{Command, encode_command, frame, read_packet};

/// A plugin asking for more than one response.
const AUTH_MORE_DATA: u8 = 0x01;

/// What a query came back with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each row, each column as text or NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// What a statement without rows reported; zero for a result set.
    pub affected_rows: u64,
}

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    server_version: String,
    connection_id: u32,
}

impl Client {
    /// Connect to `server` and log in to `database` as `login`.
    ///
    /// # Errors
    /// Where the server could not be reached, refused the login, or asks
    /// for a plugin other than `mysql_native_password`, which this crate
    /// does not speak.
    pub fn connect(
        server: &str,
        database: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            server_version: String::new(),
            connection_id: 0,
        };
        let (_, payload) = client.read("the greeting")?;
        if payload.first() == Some(&ERR_HEADER) {
            return Err(refused(decode_reply(&payload)?));
        }
        let greeting = decode_handshake(&payload)?;
        if greeting.capabilities & CLIENT_PROTOCOL_41 == 0 {
            return Err(protocol_error("a server without protocol 4.1"));
        }
        client.server_version = greeting.server_version;
        client.connection_id = greeting.connection_id;
        let response = HandshakeResponse41 {
            capabilities: CAPABILITIES,
            user: login.user.clone(),
            auth_response: scramble(&login.password, &greeting.nonce),
            database: database.to_string(),
            plugin: NATIVE_PASSWORD.to_string(),
        };
        let mut sequence = 1;
        client.write(&mut sequence, &encode_response(&response))?;
        loop {
            let (sequence_seen, payload) = client.read("the login's answer")?;
            sequence = sequence_seen.wrapping_add(1);
            match decode_reply(&payload)? {
                Reply::Ok { .. } => return Ok(client),
                error @ Reply::Err { .. } => return Err(refused(error)),
                Reply::Data(bytes) if bytes.first() == Some(&EOF_HEADER) => {
                    let (plugin, nonce) = decode_auth_switch(&bytes)?;
                    if plugin != NATIVE_PASSWORD {
                        return Err(TransportError::permanent(format!(
                            "the server asks for {plugin}, and this crate speaks \
                             mysql_native_password only"
                        )));
                    }
                    client.write(&mut sequence, &scramble(&login.password, &nonce))?;
                }
                Reply::Data(bytes) if bytes.first() == Some(&AUTH_MORE_DATA) => {
                    return Err(TransportError::permanent(
                        "the server asks for more than the native password gives",
                    ));
                }
                Reply::Eof { .. } => {
                    return Err(TransportError::permanent(
                        "the server asks for the pre-4.1 password, which this crate does not speak",
                    ));
                }
                Reply::Data(_) => {
                    return Err(protocol_error("the server answered the login with data"));
                }
            }
        }
    }

    /// What the server said it was, `8.4.0` say.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// The id the server gave this connection.
    #[must_use]
    pub const fn connection_id(&self) -> u32 {
        self.connection_id
    }

    /// Run `sql` and take its rows.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        let mut sequence = 0;
        self.write(
            &mut sequence,
            &encode_command(&Command::Query(sql.to_string())),
        )?;
        let (_, payload) = self.read("the query's answer")?;
        let count = match decode_reply(&payload)? {
            Reply::Ok { affected_rows, .. } => {
                return Ok(QueryResult {
                    affected_rows,
                    ..QueryResult::default()
                });
            }
            error @ Reply::Err { .. } => return Err(refused(error)),
            Reply::Eof { .. } => return Err(protocol_error("EOF where a result set should open")),
            Reply::Data(bytes) => decode_column_count(&bytes)?,
        };
        let mut result = QueryResult::default();
        for _ in 0..count {
            let (_, payload) = self.read("a column definition")?;
            result.columns.push(decode_column(&payload)?);
        }
        let (_, payload) = self.read("the end of the columns")?;
        match decode_in_result_set(&payload)? {
            Reply::Eof { .. } => {}
            error @ Reply::Err { .. } => return Err(refused(error)),
            _ => return Err(protocol_error("no EOF after the column definitions")),
        }
        loop {
            let (_, payload) = self.read("a row")?;
            match decode_in_result_set(&payload)? {
                Reply::Eof { .. } => return Ok(result),
                error @ Reply::Err { .. } => return Err(refused(error)),
                Reply::Data(bytes) => result.rows.push(decode_row(&bytes, count)?),
                Reply::Ok { .. } => return Err(protocol_error("OK in the middle of the rows")),
            }
        }
    }

    /// Run `sql` for its effect; the rows the server said it touched.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn execute(&mut self, sql: &str) -> Result<u64> {
        self.query(sql).map(|result| result.affected_rows)
    }

    /// Say goodbye and hang up.
    ///
    /// # Errors
    /// Where the server had already gone.
    pub fn close(mut self) -> Result<()> {
        self.write(&mut 0, &encode_command(&Command::Quit))
    }

    fn read(&mut self, waiting_for: &str) -> Result<(u8, Vec<u8>)> {
        read_packet(&mut self.reader)?
            .ok_or_else(|| protocol_error(format!("the server closed before {waiting_for}")))
    }

    fn write(&mut self, sequence: &mut u8, payload: &[u8]) -> Result<()> {
        self.writer
            .write_all(&frame(sequence, payload))
            .map_err(|e| classify("writing a packet", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a packet", &e))
    }
}

/// The error an ERR reply carries; anything else is a broken protocol.
fn refused(reply: Reply) -> TransportError {
    match reply {
        Reply::Err {
            code,
            state,
            message,
        } => sql_error(code, &state, &message),
        other => protocol_error(format!("{other:?} where an error was expected")),
    }
}

/// An error the server answered, retryable where the code or the SQLSTATE
/// class says the trouble is the connection, the server's load, a lock or
/// a deadlock — what a later attempt might not meet.
#[must_use]
pub fn sql_error(code: u16, state: &str, message: &str) -> TransportError {
    let text = format!("the server answered {code} ({state}): {message}");
    let transient = matches!(code, 1040 | 1053 | 1077 | 1205 | 1213 | 1317)
        || matches!(state.get(..2), Some("08" | "40"));
    if transient {
        TransportError::retryable(text)
    } else {
        TransportError::permanent(text)
    }
}

/// `text` as a string literal: quoted, with the backslash escapes the
/// server reads unless `NO_BACKSLASH_ESCAPES` is on — a quote, a
/// backslash, a NUL and the line ends each written out.
#[must_use]
pub fn quote_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\0' => out.push_str("\\0"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{1a}' => out.push_str("\\Z"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

/// `name` as an identifier: in backticks, every backtick doubled.
#[must_use]
pub fn quote_identifier(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes_with_a_backslash_and_backticks_double() {
        assert_eq!(quote_literal("it's"), "'it\\'s'");
        assert_eq!(quote_literal("back\\slash"), "'back\\\\slash'");
        assert_eq!(quote_literal("a\nb\r\0\u{1a}"), "'a\\nb\\r\\0\\Z'");
        assert_eq!(quote_literal(""), "''");
        assert_eq!(quote_identifier("in`box"), "`in``box`");
        assert_eq!(quote_identifier("Inbox"), "`Inbox`");
    }

    #[test]
    fn an_error_is_judged_by_its_code_and_class() {
        assert!(sql_error(1040, "08004", "Too many connections").retryable);
        assert!(sql_error(1213, "40001", "Deadlock found").retryable);
        assert!(sql_error(1205, "HY000", "Lock wait timeout exceeded").retryable);
        assert!(sql_error(2013, "08S01", "Lost connection").retryable);
        assert!(!sql_error(1045, "28000", "Access denied").retryable);
        assert!(!sql_error(1146, "42S02", "Table doesn't exist").retryable);
        assert!(!sql_error(0, "", "nothing").retryable);
        assert!(
            refused(Reply::Eof {
                warnings: 0,
                status: 0
            })
            .message
            .contains("expected")
        );
    }
}
