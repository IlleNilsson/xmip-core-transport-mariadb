//! What a Location declares for this technology, and the transport it builds
//! from it (ADR-0064, amendment 2026-09-26).

use transport::Configured;
use transport::error::Result;
use transport::sql::{COLUMN, Column, ENCODING, accept};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use mariadb::Guard;

use crate::{DEFAULT_QUERY, MariaDbTransport};

impl Configured for MariaDbTransport {
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
            accept::ACCEPT,
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
            Setting {
                name: "tls",
                kind: Kind::Boolean,
                presence: Presence::Default(Fixed::Boolean(false)),
                meaning: "The connection upgraded to TLS before the login, the server's \
                          certificate checked against the operating system's trust store.",
                applies: Applies::Both,
            },
            Setting {
                name: "tls_name",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The name the server's certificate is checked for; the address's \
                          host when left out.",
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
        if let Some(statement) = settings.optional_text(accept::ACCEPT.name) {
            transport = transport.with_accept(statement);
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        if settings.optional_boolean("tls") == Some(true) {
            transport = transport.guarded(Guard {
                trust: None,
                name: settings.optional_text("tls_name").map(ToString::to_string),
            });
        }
        Ok(transport.holding(Column::configured(settings)?))
    }
}
