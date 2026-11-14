//! What a Location declares for this technology (ADR-0064, amendment
//! 2026-09-26): what every SQL Location declares (`transport::sql`), and
//! the TLS its login is guarded by, read by `transport::sql::client_tls`.

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
