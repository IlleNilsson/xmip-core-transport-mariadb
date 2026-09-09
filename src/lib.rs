#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! `MySQL` and `MariaDB` are the databases the estate's partners already
//! have, and a table in one is the oldest integration surface there is: a
//! producer inserts, an integrator polls. A Receive Location runs its
//! query — `SELECT id, payload FROM inbox ORDER BY id` unless told
//! otherwise — and hands each row up; a Send Location inserts the Stream
//! as one column of one row — as text when the Stream is UTF-8 without a
//! NUL, as an `X'…'` hexadecimal literal otherwise, and a value in a hex
//! form is the bytes again on the way back (`hex.rs`). What is spoken is
//! the client/server protocol as every client since 4.1 speaks it, on
//! port 3306: the greeting, a response with the password scrambled the
//! `mysql_native_password` way (`handshake.rs`, SHA-1 from `sha1.rs`),
//! `COM_QUERY` with rows as text (`result.rs`), `COM_QUIT`.
//! `caching_sha2_password` is not implemented and a server that asks for
//! it is told so; TLS is the transport capability's, per ADR-0033.
//!
//! Rows are artefacts and this transport claims none of them, per ADR-0024:
//! the atomic claim a database has, `SELECT … FOR UPDATE SKIP LOCKED`, only
//! holds inside a transaction, and the flow here opens and closes its
//! connection inside one receive, so there is no transaction to hold it
//! across the Stream's lifetime. Until the claim is written, a Receive
//! Location is one consumer of its query, and the query itself — a status
//! column, a `DELETE … RETURNING` on `MariaDB` — is what keeps a row from
//! arriving twice.
//!
//! The origin URI carries what the row knew: `mysql://server/orders?row=41`.
//! A send target is `mysql://host:3306/<database>/<table>/<column>`,
//! `host:3306/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.

pub mod client;
pub mod handshake;
pub mod hex;
pub mod insert;
pub mod result;
pub mod session;
pub mod sha1;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, QueryResult, quote_identifier, quote_literal};
pub use handshake::Login;
pub use session::{Answer, Event, Session};
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, TransportError};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

pub struct MysqlTransport {
    server: String,
    database: String,
    login: Login,
    query: String,
    timeout: Option<Duration>,
}

impl MysqlTransport {
    /// Speak to the server at `server`, on `database`, as `user` with no
    /// password until one is given.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            database: database.into(),
            login: Login::new(user, ""),
            query: DEFAULT_QUERY.to_string(),
            timeout: None,
        }
    }

    /// The password the login scrambles.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.login.password = password.into();
        self
    }

    /// The query a receive runs: the first column is the row's name, the
    /// last is the Stream.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// Give up on a server that stops mid-packet.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Log in to the server.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.database)
    }

    fn connect_to(&self, server: &str, database: &str) -> Result<Client> {
        Client::connect(server, database, &self.login, self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, demanding this
    /// transport's user and password.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the login failed.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, &self.login, self.timeout)
    }

    /// Where a target names the server, database, table and column, or
    /// some suffix of them on what this transport is configured with.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, &'a str, &'a str, &'a str)> {
        let (server, path) = socket::target("mysql", target)
            .or_else(|| socket::target("mariadb", target))
            .or_else(|| match target.split_once('/') {
                Some((peer, path)) if peer.contains(':') => Some((peer, path)),
                _ => None,
            })
            .unwrap_or((&self.server, target));
        let segments: Vec<&str> = path.split('/').collect();
        match segments.as_slice() {
            [database, table, column] => Ok((server, database, table, column)),
            [table, column] => Ok((server, &self.database, table, column)),
            _ => Err(TransportError::permanent(format!(
                "{target:?} is not database/table/column or table/column"
            ))),
        }
    }
}

impl Transport for MysqlTransport {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Run the query; each row is a Stream.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let result = client.query(&self.query)?;
        client.close()?;
        let mut arrived = Vec::with_capacity(result.rows.len());
        for (index, row) in result.rows.into_iter().enumerate() {
            let name = row
                .first()
                .cloned()
                .flatten()
                .unwrap_or_else(|| index.to_string());
            let value = row.last().cloned().flatten().unwrap_or_default();
            arrived.push(Arrived::new(
                format!("mysql://{}/{}?row={name}", self.server, self.database),
                hex::column_bytes(value),
            ));
        }
        Ok(arrived)
    }

    /// Insert the bytes as one column of one row: text as text, anything
    /// else as a hexadecimal literal.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, database, table, column) = self.resolve(target)?;
        let literal = match std::str::from_utf8(bytes) {
            Ok(text) if hex::is_text(bytes) => quote_literal(text),
            _ => hex::hex_literal(bytes),
        };
        let mut client = self.connect_to(server, database)?;
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_identifier(table),
            quote_identifier(column),
            literal
        );
        client.execute(&sql)?;
        client.close()
    }

    /// Rows are artefacts, and one receive holds no transaction to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{CAPABILITIES, HandshakeV10, NATIVE_PASSWORD, encode_handshake};
    use crate::wire::{cstring, frame};

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end = MysqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            MysqlTransport::new(address, "orders", "xmip")
                .with_password("secret")
                .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                .timing_out_after(secs(2))
                .receive()
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(
                &["id", "kind", "payload"],
                &[
                    &[Some("41"), Some("order"), Some("ISA*00*")],
                    &[Some("42"), None, Some("0xfffe")],
                    &[None, Some(""), None],
                ],
            );
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "orders");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(session.next_event().expect("quit").is_none());
        let arrived = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 3);
        assert_eq!(arrived[0].bytes, b"ISA*00*");
        assert!(arrived[0].origin_uri.ends_with("/orders?row=41"));
        assert_eq!(arrived[1].bytes, [0xff, 0xfe], "a hex form is the bytes");
        assert!(arrived[1].origin_uri.ends_with("?row=42"));
        assert!(arrived[2].bytes.is_empty(), "NULL is an empty Stream");
        assert!(arrived[2].origin_uri.ends_with("?row=2"));
    }

    #[test]
    fn a_send_inserts_the_stream_as_one_column_and_the_login_is_checked() {
        let far_end = MysqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = MysqlTransport::new(address.clone(), "orders", "xmip")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("mysql://{address}/orders/inbox/payload"),
                b"it's \\here",
            )?;
            near.send("outbox/body", b"")?;
            near.send(&format!("{address}/orders/inbox/payload"), &[0xff, 0xfe])?;
            let bad_target = near.send("mariadb://host/only-one", b"x");
            let refused = MysqlTransport::new(address.clone(), "orders", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            let nobody = MysqlTransport::new(address, "orders", "nobody")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            Ok::<_, TransportError>((bad_target, refused, nobody))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's \\here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        assert!(session.next_insert().expect("closed").is_none());
        let mut session = far_end.accept_one(&listener).expect("second");
        let second = session.next_insert().expect("second").expect("one");
        assert!(second.bytes.is_empty());
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
        let session = far_end.accept_one(&listener).expect("third");
        let events = session.serve().expect("served");
        assert!(
            matches!(&events[..], [Event::Inserted(binary)] if binary.bytes == [0xff, 0xfe]),
            "not text, so the hex literal: {events:?}"
        );
        let error = far_end.accept_one(&listener).err().expect("wrong password");
        assert!(error.message.contains("Access denied for user 'xmip'"));
        let error = far_end.accept_one(&listener).err().expect("wrong user");
        assert!(error.message.contains("'nobody'"));
        assert!(error.message.contains("using password: NO"));
        let (bad_target, refused, nobody) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(refused.message.contains("1045"));
        assert!(nobody.expect_err("wrong user").message.contains("28000"));
        assert!(far_end.claims().is_some(), "rows are artefacts");
        assert_eq!(far_end.name(), "mysql");
        assert_eq!(far_end.directions(), Directions::BOTH);
    }

    #[test]
    fn a_query_the_far_end_errors_is_the_error_and_a_statement_is_its_count() {
        let far_end =
            MysqlTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let near = std::thread::spawn(move || {
            let near = MysqlTransport::new(address, "orders", "xmip").timing_out_after(secs(2));
            let failed = near.receive();
            let mut client = near.connect()?;
            let deleted = client.execute("DELETE FROM inbox WHERE id = 41")?;
            let version = client.server_version().to_string();
            client.close()?;
            Ok::<_, TransportError>((failed, deleted, version))
        });
        let session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .answering(|sql| {
                sql.starts_with("SELECT").then(|| Answer::Error {
                    code: 1146,
                    state: "42S02".into(),
                    message: "Table 'orders.inbox' doesn't exist".into(),
                })
            });
        assert_eq!(session.serve().expect("served").len(), 1);
        let session = far_end
            .accept_one(&listener)
            .expect("again")
            .answering(|sql| sql.starts_with("DELETE").then_some(Answer::Complete(3)));
        assert_eq!(
            session.serve().expect("served"),
            [Event::Executed("DELETE FROM inbox WHERE id = 41".into())]
        );
        let (failed, deleted, version) = near.join().expect("thread").expect("near");
        let error = failed.expect_err("the table is missing");
        assert!(!error.retryable);
        assert!(error.message.contains("1146 (42S02)"));
        assert_eq!(deleted, 3);
        assert_eq!(version, session::SERVER_VERSION);
    }

    #[test]
    fn a_server_asking_for_another_plugin_or_speaking_nonsense_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let greeting = frame(
            &mut 0,
            &encode_handshake(&HandshakeV10 {
                server_version: "8.4.0".into(),
                connection_id: 1,
                nonce: vec![b'n'; 20],
                capabilities: CAPABILITIES,
                plugin: "caching_sha2_password".into(),
            }),
        );
        let mut switch = vec![0xfe];
        cstring(&mut switch, "caching_sha2_password");
        switch.extend_from_slice(b"nonce-nonce-nonce-no\0");
        std::thread::spawn(move || {
            for (first, second) in [
                (&greeting[..], &frame(&mut 2, &switch)[..]),
                (b"\x05\x00\x00\x00HTTP/", b""),
            ] {
                let (mut stream, _) = listener.accept().expect("accept");
                std::io::Write::write_all(&mut stream, first).expect("write");
                let mut sink = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut sink);
                std::io::Write::write_all(&mut stream, second).expect("write");
                let _ = std::io::Read::read(&mut stream, &mut sink);
            }
        });
        let near = MysqlTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let error = near.connect().err().expect("caching_sha2_password");
        assert!(!error.retryable);
        assert!(error.message.contains("caching_sha2_password"));
        assert!(error.message.contains(NATIVE_PASSWORD));
        assert!(near.connect().is_err(), "not the protocol");
    }
}
