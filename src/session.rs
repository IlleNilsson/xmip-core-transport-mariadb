//! The server's side of one connection: what a test puts at the far end,
//! and what the playground drives.
//!
//! Not a database. One session does the login for one client — a greeting
//! with a fresh nonce, the native password checked against the one login
//! it expects — and answers each query from a closure or from one fixed
//! table: any SELECT gets the table's rows, an INSERT of one column is
//! recorded as a Stream, anything else is completed with OK. Planning,
//! storage and SQL are a database's.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use transport::Arrived;
use transport::error::{Result, TransportError, classify, protocol_error};
use transport::socket;

use crate::handshake::{
    CAPABILITIES, HandshakeV10, Login, NATIVE_PASSWORD, NONCE_LENGTH, decode_response,
    encode_handshake, verify,
};
use crate::insert::parse_insert;
use crate::result::{Reply, encode_column, encode_column_count, encode_reply, encode_row};
use crate::sha1::sha1;
use crate::wire::{Command, decode_command, frame, read_packet};

/// What this far end says it is.
pub const SERVER_VERSION: &str = "8.4.0-xmip";
/// `SERVER_STATUS_AUTOCOMMIT`, the one status a session reports.
const AUTOCOMMIT: u16 = 2;

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here is the Stream.
    Inserted(Arrived),
    /// The client ran something else; here it is.
    Executed(String),
}

/// How a query is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    /// OK, with this many rows affected.
    Complete(u64),
    Error {
        code: u16,
        state: String,
        message: String,
    },
}

type Answering = Box<dyn FnMut(&str) -> Option<Answer> + Send>;

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    user: String,
    database: String,
    columns: Vec<String>,
    rows: Vec<Vec<Option<String>>>,
    answering: Option<Answering>,
}

impl Session {
    /// Accept one client on `listener` and log it in, demanding `login`'s
    /// user and password.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not
    /// answer the greeting with a 4.1 response, or gave another user or
    /// password — which is told to the client as error 1045 before this
    /// returns.
    pub fn accept(
        listener: &TcpListener,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            user: String::new(),
            database: String::new(),
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
        };
        let greeting = HandshakeV10 {
            server_version: SERVER_VERSION.to_string(),
            connection_id: CONNECTIONS.fetch_add(1, Ordering::Relaxed),
            nonce: fresh_nonce(&peer),
            capabilities: CAPABILITIES,
            plugin: NATIVE_PASSWORD.to_string(),
        };
        let mut sequence = 0;
        session.write(&mut sequence, &encode_handshake(&greeting))?;
        let Some((seen, payload)) = read_packet(&mut session.reader)? else {
            return Err(protocol_error(
                "the client closed before answering the greeting",
            ));
        };
        sequence = seen.wrapping_add(1);
        let response = decode_response(&payload)?;
        session.user = response.user;
        session.database = response.database;
        let accepted = session.user == login.user
            && response.plugin == NATIVE_PASSWORD
            && verify(&login.password, &greeting.nonce, &response.auth_response);
        if !accepted {
            let message = format!(
                "Access denied for user '{}'@'{}' (using password: {})",
                session.user,
                peer.ip(),
                if response.auth_response.is_empty() {
                    "NO"
                } else {
                    "YES"
                }
            );
            let reply = Reply::Err {
                code: 1045,
                state: "28000".to_string(),
                message: message.clone(),
            };
            session.write(&mut sequence, &encode_reply(&reply))?;
            return Err(TransportError::permanent(message));
        }
        session.write(&mut sequence, &encode_reply(&ok(0)))?;
        Ok(session)
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The database the client asked for.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        self.columns = columns.iter().map(ToString::to_string).collect();
        self.rows = rows
            .iter()
            .map(|row| row.iter().map(|v| v.map(String::from)).collect())
            .collect();
        self
    }

    /// Answer queries with `answering` first; what it declines falls to the
    /// table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    /// Everything else is answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Arrived>> {
        loop {
            match self.next_event()? {
                Some(Event::Inserted(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// The next query the client ran, answered, or `None` when it quit.
    ///
    /// # Errors
    /// Where the connection broke, nothing arrived before the timeout, or
    /// the client sent a command this crate does not serve.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let Some((seen, payload)) = read_packet(&mut self.reader)? else {
            return Ok(None);
        };
        match decode_command(&payload)? {
            Command::Quit => Ok(None),
            Command::Query(sql) => {
                let (answer, event) = self.answer(&sql);
                let mut sequence = seen.wrapping_add(1);
                self.write_answer(&mut sequence, &answer)?;
                Ok(Some(event))
            }
        }
    }

    /// Serve the client until it quits; everything it did, in order.
    ///
    /// # Errors
    /// Where the connection broke or nothing arrived before the timeout.
    pub fn serve(mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        let verb = sql
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        match verb.as_str() {
            "SELECT" => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            "INSERT" => match parse_insert(sql) {
                Some((table, column, value)) => {
                    let origin =
                        format!("mysql://{}/{}/{table}/{column}", self.peer, self.database);
                    (
                        Answer::Complete(1),
                        Event::Inserted(Arrived::new(origin, value)),
                    )
                }
                None => (
                    Answer::Error {
                        code: 1064,
                        state: "42000".to_string(),
                        message: "only INSERT INTO t (c) VALUES (...) is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => (Answer::Complete(0), Event::Executed(sql.to_string())),
        }
    }

    fn write_answer(&mut self, sequence: &mut u8, answer: &Answer) -> Result<()> {
        match answer {
            Answer::Rows { columns, rows } => {
                let mut out = frame(sequence, &encode_column_count(columns.len()));
                for column in columns {
                    out.extend(frame(sequence, &encode_column(column)));
                }
                out.extend(frame(sequence, &encode_reply(&eof())));
                for row in rows {
                    out.extend(frame(sequence, &encode_row(row)));
                }
                out.extend(frame(sequence, &encode_reply(&eof())));
                self.write_all(&out)
            }
            Answer::Complete(affected) => self.write(sequence, &encode_reply(&ok(*affected))),
            Answer::Error {
                code,
                state,
                message,
            } => self.write(
                sequence,
                &encode_reply(&Reply::Err {
                    code: *code,
                    state: state.clone(),
                    message: message.clone(),
                }),
            ),
        }
    }

    fn write(&mut self, sequence: &mut u8, payload: &[u8]) -> Result<()> {
        self.write_all(&frame(sequence, payload))
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer
            .write_all(bytes)
            .map_err(|e| classify("writing a packet", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a packet", &e))
    }
}

/// Ids handed out, one a connection.
static CONNECTIONS: AtomicU32 = AtomicU32::new(1);

/// Twenty printable bytes no two sessions share: the SHA-1 of the clock,
/// the peer and a counter, each byte folded into `!`..`~` the way a
/// server does so no NUL lands in a field a NUL ends.
fn fresh_nonce(peer: &SocketAddr) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let seed = format!("{nanos}:{peer}:{}", CONNECTIONS.load(Ordering::Relaxed));
    sha1(seed.as_bytes())
        .iter()
        .map(|byte| b'!' + byte % 94)
        .take(NONCE_LENGTH)
        .collect()
}

const fn ok(affected_rows: u64) -> Reply {
    Reply::Ok {
        affected_rows,
        last_insert_id: 0,
        status: AUTOCOMMIT,
        warnings: 0,
    }
}

const fn eof() -> Reply {
    Reply::Eof {
        warnings: 0,
        status: AUTOCOMMIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_printable_and_fresh() {
        let peer: SocketAddr = "127.0.0.1:3306".parse().expect("address");
        let first = fresh_nonce(&peer);
        assert_eq!(first.len(), NONCE_LENGTH);
        assert!(first.iter().all(|b| (b'!'..=b'~').contains(b)));
        CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        assert_ne!(first, fresh_nonce(&peer));
    }
}
