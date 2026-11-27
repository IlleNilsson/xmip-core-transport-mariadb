# xmip-core-transport-mariadb

MariaDB transport: one row of a query is one Stream, a send is one
INSERT. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The transport is every SQL technology's, `transport::sql::SqlTransport`, over
this crate's `MariaDb` wire (2026-11-13): its name and scheme, its settings,
the MariaDB dialect in the mode the session reads, the login, and the far end
its loopback serves (`accept_one`, `taken`).

The protocol is
[xmip-core-library-mariadb](https://github.com/IlleNilsson/xmip-core-library-mariadb)'s,
both halves: the client this crate queries and inserts with, and the far end
its tests and the System Tests serve. This crate logs in with MariaDB's login,
the native password. A MySQL server is
[xmip-core-transport-mysql](https://github.com/IlleNilsson/xmip-core-transport-mysql)'s,
which speaks MySQL's own logins over the same protocol.

`tls = true` (boolean, default false) upgrades the connection to the estate's
TLS (`xmip-core-library-tls`, ADR-0033) after the greeting and before the
login, the server's certificate checked against the operating system's trust
store for the address's host, or for `tls_name` where given. A server that
offers no TLS is refused, never spoken to in the clear.

## Acknowledgement

`accept` is every SQL technology's (`transport::sql::accept`): [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport)'s README. On `MariaDB` it is a statement — `DELETE FROM inbox WHERE id = ?`, an `UPDATE` of a status column — with the row's name in place of `?` (the placeholder of a `MariaDB` prepared statement; this client sends the statement as text, `COM_QUERY`), written as `MariaDB`'s string literal; it runs on the connection kept for the server and database, which commits each statement itself (autocommit). A query that consumes as it reads is a `DELETE … RETURNING` on `MariaDB`.

The SQL it writes and its far end reads — backtick identifiers, string
literals with the backslash escapes the server reads, the `X'…'` literal,
the one INSERT with its table and column always quoted identifiers so a
target can name nothing but them, and a statement's verb — is `MariaDB`'s as
`xmip-core-library-sql` writes it, the one SQL in the estate, in the mode
the session reads (`mariadb::Client::dialect`): `sql::MARIADB`, a backslash
escaped, or `sql::MARIADB_NO_BACKSLASH_ESCAPES` where the status flags of the
server's greeting or its last OK carry `NO_BACKSLASH_ESCAPES` (`0x0200`). A
quote is written `''` in both.

Where a send target puts its row — `<scheme>://host:port/<database>/<table>/<column>`,
`host:port/<database>/<table>/<column>` or `<table>/<column>` — is
`xmip-core-transport`'s `sql` module; this crate hands it its scheme,
`mariadb`.

The payload column holds bytes unless the Location declares otherwise (ADR-0038:
a payload is bytes). `column = "binary"`, the default, writes every Stream in
the dialect's binary form (an `X'…'` literal) and reads a value back only from that form;
`column = "text"` decodes the Stream strictly in its `encoding` — `utf-8`
unless `utf-16le`, `utf-16be`, `utf-32le` or `utf-32be` is named — writes it as
a string literal, and encodes a value read back to that form. A Stream or a
value that is not its declared form is refused, never repaired. The two
settings and the rule are `xmip-core-transport`'s `sql` module, shared by every
SQL transport.

Over the text protocol a BLOB comes back as raw bytes, so a binary
column's receive query spells it out: `SELECT id, CONCAT('0x', HEX(payload))
FROM inbox`.

A Send Location inserts on a connection logged in once per server and database and kept (`transport::Pool`); the login is the transport capability's `Login`. Until 2026-09-27 every insert logged in and quit.

A Receive Location runs its query on a connection kept the same way: logged in on its first receive and reused by every receive after, replaced where the server closed it. Until 2026-09-28 every receive logged in and quit.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which its wire hands `transport::sql`'s `Configured` (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `database`, `user`, `query`, `accept`, `column`, `encoding`, `timeout`, `tls` and `tls_name`, each but `tls` what every SQL Location declares (`transport::sql`), and `SCHEMES`, `mariadb`. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on — the protocol, the dialect, and TLS, the capability's with it — are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check a `MariaDB` Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
