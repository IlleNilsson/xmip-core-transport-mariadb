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
//! as one column of one row. What the column holds is the Location's to
//! declare, never the bytes' (ADR-0038): `column = "binary"`, the default,
//! inserts every Stream as an `X'…'` hexadecimal literal and reads a value
//! back from a hex form (`hex.rs`); `column = "text"` decodes the Stream
//! strictly in its `encoding` — `utf-8` unless another Unicode form is
//! named — inserts it as a string literal, and encodes a value read back
//! to that form. A Stream that is not its declared form is refused, never
//! repaired; so is a row value that is not UTF-8. What is spoken is
//! the client/server protocol as every client since 4.1 speaks it, on
//! port 3306: the greeting, a response with the password scrambled the
//! `mysql_native_password` way (`handshake.rs`, SHA-1 from codec),
//! `COM_QUERY` with rows as text (`result.rs`), `COM_QUIT`.
//! `caching_sha2_password` is not implemented and a server that asks for
//! it is told so; TLS is `xmip-core-library-tls`'s, per ADR-0033.
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
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, QueryResult, quote_literal};
pub use handshake::Login;
pub use session::{Answer, Event, Session};
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::sql::{COLUMN, Column, ENCODING};
use transport::{Arrived, Configured, Directions, Transport};

use insert::DIALECT;
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What the loopback pair agrees on: one database, one user with no
/// password that the far end demands and the near end gives, one table
/// and column the payload is inserted into.
const LOOPBACK_DATABASE: &str = "probe";
const LOOPBACK_USER: &str = "xmip";
const LOOPBACK_TARGET: &str = "probe/payload";

#[derive(Clone)]
pub struct MysqlTransport {
    server: String,
    database: String,
    login: Login,
    query: String,
    column: Column,
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
            column: Column::Binary,
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

    /// What the payload column holds: bytes unless declared otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
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
            .map(|session| session.holding(self.column))
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
            let bytes = match row.last().cloned().flatten() {
                Some(value) => self.column.bytes(&value, hex::from_hex_literal)?,
                None => Vec::new(),
            };
            arrived.push(Arrived::new(
                format!("mysql://{}/{}?row={name}", self.server, self.database),
                bytes,
            ));
        }
        Ok(arrived)
    }

    /// Insert the bytes as one column of one row: as a hexadecimal
    /// literal, or as text where the column is declared to hold it.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let to = DIALECT.destination(target, &self.server, &self.database)?;
        let literal = self
            .column
            .literal(bytes, quote_literal, hex::hex_literal)?;
        let mut client = self.connect_to(to.server, to.catalog)?;
        client.execute(&DIALECT.insert(to.table, to.column, &literal))?;
        client.close()
    }

    /// Rows are artefacts, and one receive holds no transaction to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Configured for MysqlTransport {
    /// The address is the server's host and port: where a Location connects.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "database",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The database a Location logs in to and reads or inserts into.",
                applies: Applies::Both,
            },
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The user a Location logs in as.",
                applies: Applies::Both,
            },
            Setting {
                name: "query",
                kind: Kind::Text,
                presence: Presence::Default(Fixed::Text(DEFAULT_QUERY)),
                meaning: "The query a receive runs: the first column names the row, the last \
                          is the Stream.",
                applies: Applies::Receive,
            },
            COLUMN,
            ENCODING,
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-packet is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// The password comes through the Location's credentials, never a
    /// setting.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address, settings.text("database"), settings.text("user"));
        if let Some(query) = settings.optional_text("query") {
            transport = transport.with_query(query);
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport.holding(Column::configured(settings)?))
    }
}

impl MysqlTransport {
    /// Both ends on this machine: an ephemeral local port, a login with no
    /// password, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_DATABASE, LOOPBACK_USER)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for MysqlTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Arrived> {
        let mut session = self.accept_one(listener)?;
        let arrived = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        // Read the quit that follows, so the goodbye is taken rather than
        // written into a closed socket.
        session.next_insert()?;
        Ok(arrived)
    }
}

impl Loopback for MysqlTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    /// INSERT the payload as one column of one row, as the column is
    /// declared to hold it, from a fresh near end logging in to
    /// `address` as this transport does.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            server: address.to_string(),
            ..self.clone()
        };
        near.send(LOOPBACK_TARGET, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{CAPABILITIES, HandshakeV10, NATIVE_PASSWORD, encode_handshake};
    use crate::wire::{MysqlWrite, frame};
    use codec::unicode::Form;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn mysql_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(MysqlTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("database", "orders"),
            text("user", "xmip"),
            text("timeout", "2s"),
        ];
        let built = MysqlTransport::open("db:3306", Applies::Receive, &given).expect("built");
        assert_eq!(built.server, "db:3306");
        assert_eq!(built.database, "orders");
        assert_eq!(built.query, DEFAULT_QUERY);
        assert_eq!(built.timeout, Some(secs(2)));
        assert_eq!(built.column, Column::Binary, "bytes unless declared");
        let texts = [
            text("database", "orders"),
            text("user", "xmip"),
            text("column", "text"),
        ];
        let built = MysqlTransport::open("db:3306", Applies::Send, &texts).expect("text");
        assert_eq!(built.column, Column::Text(Form::Utf8), "utf-8 unless named");
        let Err(refused) = MysqlTransport::open("db:3306", Applies::Send, &given[1..]) else {
            panic!("database is required");
        };
        assert!(
            refused.message.contains("\"database\""),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end = MysqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = MysqlTransport::new(address, "orders", "xmip")
                .with_password("secret")
                .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                .timing_out_after(secs(2));
            let bytes = near.receive();
            (bytes, near.holding(Column::Text(Form::Utf8)).receive())
        });
        let rows: [&[Option<&str>]; 3] = [
            &[Some("41"), Some("order"), Some("X'4953412a30302a'")],
            &[Some("42"), None, Some("0xfffe")],
            &[None, Some(""), None],
        ];
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(&["id", "kind", "payload"], &rows);
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "orders");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(session.next_event().expect("quit").is_none());
        let mut session = far_end
            .accept_one(&listener)
            .expect("the text column")
            .with_table(&["id", "payload"], &[&[Some("43"), Some("0xfffe")]]);
        while session.next_event().expect("event").is_some() {}
        let (arrived, text) = receiver.join().expect("thread");
        let text = text.expect("a text column");
        assert_eq!(text[0].bytes, b"0xfffe", "text, never read as a hex form");
        let arrived = arrived.expect("receiving");
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
            "a binary column, so the hex literal: {events:?}"
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
    fn a_text_column_refuses_a_stream_that_is_not_its_encoding() {
        let near =
            MysqlTransport::new("127.0.0.1:1", "orders", "xmip").holding(Column::Text(Form::Utf8));
        let refused = near
            .send("inbox/payload", &[0xff, 0xfe])
            .expect_err("not UTF-8");
        assert!(!refused.retryable);
        assert!(
            refused.message.contains("utf-8 text"),
            "{}",
            refused.message
        );
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
        switch.cstring("caching_sha2_password");
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

    #[test]
    fn the_loopback_inserts_text_and_bytes_through_its_own_session() {
        let pair = MysqlTransport::loopback();
        let arrived = pair.round(b"it's \\here").expect("round");
        assert_eq!(arrived.bytes, b"it's \\here");
        assert!(arrived.origin_uri.starts_with("mysql://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/probe/probe/payload"));
        let binary = pair.round(&[0xff, 0xfe]).expect("the hex literal");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "mysql");
        assert_eq!(pair.ceiling(), None);
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = MysqlTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }
}
