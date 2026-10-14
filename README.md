# xmip-core-transport-mariadb

MariaDB transport: one row of a query is one Stream, a send is one
INSERT. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The protocol is
[xmip-core-library-mariadb](https://github.com/IlleNilsson/xmip-core-library-mariadb)'s,
both halves: the client this crate queries and inserts with, and the far end
its tests and the Playground serve. This crate logs in with MariaDB's login,
the native password. A MySQL server is
[xmip-core-transport-mysql](https://github.com/IlleNilsson/xmip-core-transport-mysql)'s,
which speaks MySQL's own logins over the same protocol.

`tls = true` (boolean, default false) upgrades the connection to the estate's
TLS (`xmip-core-library-tls`, ADR-0033) after the greeting and before the
login, the server's certificate checked against the operating system's trust
store for the address's host, or for `tls_name` where given. A server that
offers no TLS is refused, never spoken to in the clear.

## Acknowledgement

The Location's query only reads; what consumes a row is the `accept` statement, run after the row's receive cycle. `accept` (text, receive side, optional) is a statement — `DELETE FROM inbox WHERE id = ?`, an `UPDATE` of a status column — with the row's name, the query's first column as the origin carries it, in place of `?` (the placeholder of a `MariaDB` prepared statement; this client sends the statement as text, `COM_QUERY`), written as `MariaDB`'s string literal (`transport::sql::accept`), so whatever the column holds stays one value. It runs on the connection kept for the server and database, which commits each statement itself (autocommit):

- **Accepted**: `accept` runs; the row is consumed once its Stream is Xmip's.
- **Refused**: nothing runs. A refusal is not a consumption: the row is the only copy, so it is left where it lies, and this Location does not receive it again while its body is unchanged; a row whose body changed is a new arrival. The memory is the node process's (`transport::refused`).
- **Failed**: nothing runs, and the next receive reads the row again.

A row whose first column is NULL has no name to bind, and nothing runs for it. Where `accept` is left out a row's verdict tells the database nothing: every row is read again unless the query keeps it from that, and a query that consumes as it reads — a `DELETE … RETURNING` on `MariaDB`, an `UPDATE` of a status column — consumes before the receive cycle has run: acceptance is then at-most-once. Each row is a whole value of the result, read whole.

The SQL it writes and its far end reads — backtick identifiers, string
literals with the backslash escapes the server reads, the `X'…'` literal,
the one INSERT with its table and column always quoted identifiers so a
target can name nothing but them, and a statement's verb — is `MariaDB`'s as
`xmip-core-library-sql` writes it (`sql::MARIADB`), the one SQL in the
estate.

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

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
