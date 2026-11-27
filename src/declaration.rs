//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`. Its wire
//! hands it to `transport::sql`'s `Configured`. What every SQL Location
//! declares stays `transport::sql`'s. Its login's TLS, declared here, is read
//! by `transport::sql::client_tls`.

use transport::sql::accept::ACCEPT;
use transport::sql::{COLUMN, DATABASE, ENCODING, QUERY, TIMEOUT, TLS, TLS_NAME, USER};
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Every setting a `MariaDB` Location takes beyond its address, the
/// server's host and port.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        DATABASE,
        USER,
        QUERY,
        ACCEPT,
        COLUMN,
        ENCODING,
        TIMEOUT,
        Setting {
            name: TLS,
            kind: Kind::Boolean,
            presence: Presence::Default(Fixed::Boolean(false)),
            meaning: "The connection upgraded to TLS before the login, the server's \
                      certificate checked against the operating system's trust store.",
            applies: Applies::Both,
        },
        TLS_NAME,
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["mariadb"];
