#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! `MariaDB` is a database the estate's Parties already have. A table in
//! one is the oldest integration surface there is: a producer inserts, an
//! integrator polls. A Receive Location runs its
//! query — `SELECT id, payload FROM inbox ORDER BY id` unless told
//! otherwise — and hands each row up; a Send Location inserts the Stream
//! as one column of one row. What the column holds is the Location's to
//! declare, never the bytes' (ADR-0038): `column = "binary"`, the default,
//! inserts every Stream as an `X'…'` hexadecimal literal and reads a value
//! back from a hex form (`MariaDB`'s, `xmip-core-library-sql`);
//! `column = "text"` decodes the Stream
//! strictly in its `encoding` — `utf-8` unless another Unicode form is
//! named — inserts it as a string literal, and encodes a value read back
//! to that form. A Stream that is not its declared form is refused, never
//! repaired; so is a row value that is not UTF-8.
//!
//! **The transport is every SQL technology's**, `transport::sql`'s
//! `SqlTransport` over this crate's [`MariaDb`] wire (2026-11-13): the
//! query and its rows, the `accept` statement after a row's cycle — the
//! row's name bound in place of `?`, written as `MariaDB`'s string literal
//! in the mode the session reads (`mariadb::Client::dialect`: a backslash
//! escaped, or itself where the server's status flags carry
//! `NO_BACKSLASH_ESCAPES`) — the INSERT a send writes, the connections kept
//! per server and database.
//!
//! **The protocol is `xmip-core-library-mariadb`'s**: the client/server
//! protocol as every client since 4.1 speaks it, on port 3306, `COM_QUERY`
//! with rows as text, `COM_QUIT`, and the far end the tests and the
//! System Tests serve. This crate logs in with `MariaDB`'s login, the native
//! password; a server that asks for another plugin is told which this
//! crate speaks. A MySQL server is the MySQL transport's
//! (`xmip-core-transport-mysql`), which speaks MySQL's own logins over the
//! same protocol. `tls = true` upgrades the connection to the estate's TLS
//! before the login (ADR-0033), the server's certificate checked against
//! the operating system's trust store for the address's host or
//! `tls_name`.
//!
//! The origin URI carries what the row knew: `mariadb://server/orders?row=41`.
//! A send target is `mariadb://host:3306/<database>/<table>/<column>`,
//! `host:3306/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.

mod configured;

use std::net::TcpListener;
use std::time::Duration;

use mariadb::{Authentication, Client, Expecting, Insert, Logon, NativePassword, Session};
use sql::Dialect;
use tls::ClientSettings;
use transport::error::{Result, protocol_error};
use transport::pool::alive;
use transport::socket;
use transport::sql::{Probe, Rows, SqlTransport, Wire};
use transport::{Login, Taken};
use xcore::settings::{Read, Settings};

/// The plugins this crate logs in with: `MariaDB`'s.
const PLUGINS: &[&dyn Authentication] = &[&NativePassword];

/// A Location over a `MariaDB` server.
pub type MariaDbTransport = SqlTransport<MariaDb>;

/// `MariaDB`'s wire: `xmip-core-library-mariadb`'s client with the native
/// password, TLS before the login where asked for.
#[derive(Clone, Debug, Default)]
pub struct MariaDb {
    /// TLS before the login, where asked for.
    guard: Option<ClientSettings>,
}

impl MariaDb {
    /// Logging in under TLS, as `guard` says.
    #[must_use]
    pub const fn guarded(guard: ClientSettings) -> Self {
        Self { guard: Some(guard) }
    }

    /// The TLS a login is guarded by, where one is.
    #[must_use]
    pub const fn guard(&self) -> Option<&ClientSettings> {
        self.guard.as_ref()
    }
}

impl Wire for MariaDb {
    type Client = Client;

    const NAME: &'static str = "mariadb";
    const SCHEMES: &'static [&'static str] = &["mariadb"];
    const SETTINGS: &'static Settings = configured::SETTINGS;
    /// A user with no password, which the far end demands and the near end
    /// gives.
    const PROBE: Probe = Probe {
        database: "probe",
        user: "xmip",
        password: "",
        target: "probe/payload",
    };

    fn dialect() -> &'static Dialect {
        &sql::MARIADB
    }

    /// The session's mode: a backslash escaped, or itself where the
    /// server's status flags carry `NO_BACKSLASH_ESCAPES`.
    fn session_dialect(client: &Client) -> Option<&'static Dialect> {
        Some(client.dialect())
    }

    fn configured(self, settings: &Read) -> Result<Self> {
        Ok(Self {
            guard: transport::sql::client_tls(settings),
        })
    }

    fn connect(
        &self,
        server: &str,
        database: &str,
        presented: &Login,
        timeout: Option<Duration>,
    ) -> Result<Client> {
        let logon = Logon {
            user: &presented.user,
            password: &presented.password,
            database,
            plugins: PLUGINS,
            guard: self.guard.as_ref(),
        };
        Ok(Client::connect(server, &logon, timeout)?)
    }

    /// While the server has not closed the connection — its `wait_timeout`
    /// closes an idle one. Each `COM_QUERY` is read to its end, so nothing
    /// of one is left for the next.
    fn usable(client: &mut Client) -> bool {
        alive(client.socket())
    }

    fn query(client: &mut Client, sql: &str) -> Result<Rows<String>> {
        Ok(client.query(sql)?.rows)
    }

    fn execute(client: &mut Client, sql: &str) -> Result<()> {
        client.execute(sql)?;
        Ok(())
    }

    /// The client keeps its connection for the next insert.
    fn take_one(transport: &MariaDbTransport, listener: &TcpListener) -> Result<Taken> {
        let mut session = accept_one(transport, listener)?;
        let insert = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        Ok(taken(transport, &session, insert))
    }
}

/// Accept one client on a listener `transport` bound, demanding its user
/// and password.
///
/// # Errors
/// Where the connection could not be accepted or the login failed.
pub fn accept_one(transport: &MariaDbTransport, listener: &TcpListener) -> Result<Session> {
    let (stream, _) = socket::accept_tcp(listener, transport.timeout())?;
    let login = transport.login();
    let expecting = Expecting::new(&login.user, &login.password, &NativePassword);
    Ok(Session::accept(stream, &expecting)?)
}

/// The Stream `insert` carries, as `transport`'s column holds it, its
/// origin where `session` received it.
#[must_use]
pub fn taken(transport: &MariaDbTransport, session: &Session, insert: Insert) -> Taken {
    MariaDbTransport::inserted(
        session.peer(),
        session.database(),
        &insert.table,
        &insert.column,
        transport.column().stored(insert.literal),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::unicode::Form;
    use mariadb::handshake::{CAPABILITIES, HandshakeV10, encode_auth_switch, encode_handshake};
    use mariadb::session::SERVER_VERSION;
    use mariadb::wire::frame;
    use mariadb::{Answer, Event, NATIVE_PASSWORD};
    use std::assert_matches;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;
    use transport::sql::{Column, DEFAULT_QUERY};
    use transport::{Arrived, Configured, Directions, Loopback, Transport};
    use xcore::settings::Applies;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn mariadb_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(MariaDbTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [text("database", "orders"), text("user", "xmip")];
        let built = MariaDbTransport::open("db:3306", Applies::Receive, &given).expect("built");
        assert_eq!((built.server(), built.database()), ("db:3306", "orders"));
        assert!(
            built.wire().guard().is_none(),
            "the clear unless tls = true"
        );
        let texts = [
            text("database", "orders"),
            text("user", "xmip"),
            text("column", "text"),
            ("tls".to_string(), Given::Boolean(true)),
            text("tls_name", "db.example"),
        ];
        let built = MariaDbTransport::open("db:3306", Applies::Send, &texts).expect("text");
        assert_eq!(
            built.column(),
            Column::Text(Form::Utf8),
            "utf-8 unless named"
        );
        let guard = built.wire().guard().expect("guarded");
        assert_eq!(guard.name(), Some("db.example"));
    }

    /// The first of `arrived` read and refused, the rest taken.
    fn verdicts(arrived: Vec<Arrived>) -> Result<Vec<Taken>> {
        let mut taken = Vec::new();
        for (index, one) in arrived.into_iter().enumerate() {
            assert!(one.defers());
            if index > 0 {
                taken.push(one.taken()?);
                continue;
            }
            let (origin, mut body, acknowledgement) = one.into_parts();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut bytes).expect("reading");
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            taken.push(Taken::new(origin, bytes));
        }
        Ok(taken)
    }

    #[test]
    fn accept_consumes_an_accepted_row_and_a_refused_one_is_left_unreceived() {
        let far_end =
            MariaDbTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = MariaDbTransport::new(address, "orders", "xmip")
                .with_accept("DELETE FROM inbox WHERE id = ?")
                .timing_out_after(secs(2));
            let mut arrived = near.receive()?;
            assert_eq!(arrived.len(), 4);
            arrived.remove(0).taken()?;
            arrived
                .remove(0)
                .refused(transport::Refusal::Unacceptable)?;
            arrived.remove(0).failed()?;
            arrived.remove(0).taken()?;
            let again: Vec<_> = near.receive()?.into_iter().map(|a| a.origin_uri).collect();
            assert_eq!(
                again.len(),
                3,
                "the refused row is not received again: {again:?}"
            );
            assert!(
                again.iter().all(|row| !row.ends_with("?row=it's")),
                "{again:?}"
            );
            Ok::<_, TransportError>(())
        });
        let rows: [&[Option<&str>]; 4] = [
            &[Some("41"), Some("X'61'")],
            &[Some("it's"), Some("X'62'")],
            &[Some("43"), Some("X'63'")],
            &[None, Some("X'64'")],
        ];
        let mut session = accept_one(&far_end, &listener)
            .expect("accepting")
            .with_table(&["id", "payload"], &rows);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        receiver.join().expect("thread").expect("receiving");
        assert_eq!(
            events,
            [
                Event::Selected(DEFAULT_QUERY.into()),
                Event::Executed("DELETE FROM inbox WHERE id = '41'".into()),
                Event::Selected(DEFAULT_QUERY.into()),
            ],
            "the refused, the failed and the unnamed row are left"
        );
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end = MariaDbTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            // Two transports, so two sessions: each keeps its own.
            let near = || {
                MariaDbTransport::new(address.clone(), "orders", "xmip")
                    .with_password("secret")
                    .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                    .timing_out_after(secs(2))
            };
            let bytes = near().receive().and_then(verdicts);
            (
                bytes,
                near()
                    .holding(Column::Text(Form::Utf8))
                    .receive()
                    .and_then(verdicts),
            )
        });
        let rows: [&[Option<&str>]; 3] = [
            &[Some("41"), Some("order"), Some("X'4953412a30302a'")],
            &[Some("42"), None, Some("0xfffe")],
            &[None, Some(""), None],
        ];
        let mut session = accept_one(&far_end, &listener)
            .expect("accepting")
            .with_table(&["id", "kind", "payload"], &rows);
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "orders");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(
            session.next_event().expect("ended").is_none(),
            "a verdict, refused or accepted, says nothing to the database"
        );
        let mut session = accept_one(&far_end, &listener)
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

    /// The next Stream the client on `session` inserts.
    fn next(far_end: &MariaDbTransport, session: &mut Session) -> Taken {
        let insert = session.next_insert().expect("insert").expect("one");
        taken(far_end, session, insert)
    }

    #[test]
    fn a_send_inserts_the_stream_as_one_column_and_the_login_is_checked() {
        let far_end = MariaDbTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = MariaDbTransport::new(address.clone(), "orders", "xmip")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("mariadb://{address}/orders/inbox/payload"),
                b"it's \\here",
            )?;
            near.send("outbox/body", b"")?;
            near.send(&format!("{address}/orders/inbox/payload"), &[0xff, 0xfe])?;
            let bad_target = near.send("mariadb://host/only-one", b"x");
            let refused = MariaDbTransport::new(address.clone(), "orders", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            let nobody = MariaDbTransport::new(address, "orders", "nobody")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            Ok::<_, TransportError>((bad_target, refused, nobody))
        });
        // One server and database, so one login for all three inserts.
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        let first = next(&far_end, &mut session);
        assert_eq!(first.bytes, b"it's \\here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        let second = next(&far_end, &mut session);
        assert_eq!(second.bytes, [] as [u8; 0]);
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
        let binary = next(&far_end, &mut session);
        assert_eq!(
            binary.bytes,
            [0xff, 0xfe],
            "a binary column, so the hex literal"
        );
        let error = accept_one(&far_end, &listener)
            .err()
            .expect("wrong password");
        assert!(error.message.contains("Access denied for user 'xmip'"));
        let error = accept_one(&far_end, &listener).err().expect("wrong user");
        assert!(error.message.contains("'nobody'"));
        assert!(error.message.contains("using password: NO"));
        let (bad_target, refused, nobody) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(refused.message.contains("1045"));
        assert!(nobody.expect_err("wrong user").message.contains("28000"));
        assert!(far_end.claims().is_some(), "rows are artifacts");
        assert_eq!(far_end.name(), "mariadb");
        assert_eq!(far_end.directions(), Directions::BOTH);
    }

    #[test]
    fn a_thousand_inserts_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = MariaDbTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = MariaDbTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            for n in 0..SENDS {
                sending.send("inbox/payload", n.to_string().as_bytes())?;
            }
            sending.send("inbox/payload", b"after the close")
        });
        // One handshake for every insert: one session accepted.
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = next(&far_end, &mut session);
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = accept_one(&far_end, &listener).expect("a new login");
        let last = next(&far_end, &mut again);
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end = MariaDbTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = MariaDbTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let receiving = near.clone();
        let receiver = std::thread::spawn(move || {
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            receiving.receive()
        });
        let accept = || {
            accept_one(&far_end, &listener)
                .expect("a login")
                .with_table(&["id", "payload"], &[&[Some("1"), None]])
        };
        // One login for every query: one session accepted.
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert_matches!(event, Some(Event::Selected(_)), "{event:?}");
        }
        drop(session);
        let mut again = accept();
        assert_matches!(again.next_event(), Ok(Some(Event::Selected(_))));
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.opened(), 2);
    }

    #[test]
    fn a_query_the_far_end_errors_is_the_error_and_a_statement_is_its_count() {
        let far_end =
            MariaDbTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let near = std::thread::spawn(move || {
            let near = MariaDbTransport::new(address, "orders", "xmip").timing_out_after(secs(2));
            let failed = near.receive();
            let mut client = near.connect()?;
            let deleted = client.execute("DELETE FROM inbox WHERE id = 41")?;
            let version = client.server_version().to_string();
            client.close()?;
            Ok::<_, TransportError>((failed, deleted, version))
        });
        let session = accept_one(&far_end, &listener)
            .expect("accepting")
            .answering(|sql| {
                sql.starts_with("SELECT").then(|| Answer::Error {
                    code: 1146,
                    state: "42S02".into(),
                    message: "Table 'orders.inbox' doesn't exist".into(),
                })
            });
        assert_eq!(session.serve().expect("served").len(), 1);
        let session = accept_one(&far_end, &listener)
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
        assert_eq!(version, SERVER_VERSION);
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
                status: 2,
                plugin: "caching_sha2_password".into(),
            }),
        );
        let switch = encode_auth_switch("caching_sha2_password", b"nonce-nonce-nonce-no");
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
        let near = MariaDbTransport::new(address, "orders", "xmip")
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
        let pair = MariaDbTransport::loopback();
        let arrived = pair.round(b"it's \\here").expect("round");
        assert_eq!(arrived.bytes, b"it's \\here");
        assert!(arrived.origin_uri.starts_with("mariadb://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/probe/probe/payload"));
        let binary = pair.round(&[0xff, 0xfe]).expect("the hex literal");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "mariadb");
        assert_eq!(pair.ceiling(), None);
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = MariaDbTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }
}
