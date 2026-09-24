# xmip-core-transport-mysql

MySQL and MariaDB transport: one row of a query is one Stream, a send is one
INSERT; the client/server protocol with native password authentication. A
technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The backtick identifiers it writes and its far end reads are
`xmip-core-library-codec`'s `sql` module, the one SQL quoting in the estate;
which delimiter is this dialect's own. Its string literal, with the
backslash escapes the server reads, is `MySQL`'s alone and written here.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
