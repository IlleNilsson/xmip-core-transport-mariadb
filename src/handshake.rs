//! The login: the greeting a server opens with, the response a client
//! answers it with, and the native password that goes in the response.
//! Written and read on both sides, because the far-end [`crate::Session`]
//! speaks the server's half.
//!
//! The greeting is `HandshakeV10`: a version, a connection id, twenty
//! bytes of nonce in two parts, and the capabilities and plugin the server
//! offers. The response is `HandshakeResponse41`, the shape every client
//! since 4.1 sends: the capabilities the client takes up, the user, the
//! password scrambled, the database and the plugin name. This crate takes
//! up four capabilities — protocol 4.1, the secure connection that gives
//! the password a length byte, plugin authentication so both sides can
//! name `mysql_native_password`, and connecting straight to the database —
//! and no more: `CLIENT_DEPRECATE_EOF` is left off so a result set is
//! bounded by the EOF packets `result.rs` reads.
//!
//! `mysql_native_password` is `SHA1(password) XOR SHA1(nonce +
//! SHA1(SHA1(password)))`: the server holds `SHA1(SHA1(password))` and
//! recovers `SHA1(password)` from the response to check it, and a
//! listener on the wire gets neither. `caching_sha2_password`, the default
//! since 8.0, is not implemented; an account that uses it is told so, and
//! the server can be asked for `mysql_native_password` on that account.

use transport::error::{Result, protocol_error};

use crate::sha1::{DIGEST_LENGTH, sha1};
use crate::wire::{Cursor, cstring};

/// The version byte a greeting opens with.
pub const PROTOCOL_VERSION: u8 = 10;
/// The plugin this crate speaks.
pub const NATIVE_PASSWORD: &str = "mysql_native_password";
/// A nonce is twenty bytes: eight in the greeting's first part, twelve in
/// its second.
pub const NONCE_LENGTH: usize = 20;

/// Connect straight to a database.
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
/// The 4.1 shapes of the response and of every result.
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
/// The password behind a length byte rather than a NUL.
pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
/// Both sides name the plugin.
pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
/// The password behind a length-encoded length; read, never sent.
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
/// What this crate takes up.
pub const CAPABILITIES: u32 =
    CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB;
/// utf8mb4, general collation.
pub const UTF8MB4: u8 = 45;

/// Who logs in, and with what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    /// Empty where the account has none.
    pub password: String,
}

impl Login {
    /// `user` with `password`.
    #[must_use]
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }
}

/// What a server opens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeV10 {
    pub server_version: String,
    pub connection_id: u32,
    pub nonce: Vec<u8>,
    pub capabilities: u32,
    pub plugin: String,
}

/// What a client answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponse41 {
    pub capabilities: u32,
    pub user: String,
    /// The password scrambled, or empty where there is none.
    pub auth_response: Vec<u8>,
    pub database: String,
    pub plugin: String,
}

/// `password` scrambled with `nonce` the native way; empty for an empty
/// password, which is what the server expects of an account without one.
#[must_use]
pub fn scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let first = sha1(password.as_bytes());
    let second = sha1(&first);
    let mut salted = Vec::with_capacity(nonce.len() + DIGEST_LENGTH);
    salted.extend_from_slice(nonce);
    salted.extend_from_slice(&second);
    let third = sha1(&salted);
    first.iter().zip(third).map(|(a, b)| a ^ b).collect()
}

/// True when `response` is `password` scrambled with `nonce`.
#[must_use]
pub fn verify(password: &str, nonce: &[u8], response: &[u8]) -> bool {
    scramble(password, nonce) == response
}

/// `greeting` as a payload.
#[must_use]
pub fn encode_handshake(greeting: &HandshakeV10) -> Vec<u8> {
    let mut out = vec![PROTOCOL_VERSION];
    cstring(&mut out, &greeting.server_version);
    out.extend_from_slice(&greeting.connection_id.to_le_bytes());
    let mut nonce = greeting.nonce.clone();
    nonce.resize(NONCE_LENGTH, b'x');
    out.extend_from_slice(&nonce[..8]);
    out.push(0);
    let capabilities = greeting.capabilities.to_le_bytes();
    out.extend_from_slice(&capabilities[..2]);
    out.push(UTF8MB4);
    out.extend_from_slice(&2u16.to_le_bytes()); // SERVER_STATUS_AUTOCOMMIT
    out.extend_from_slice(&capabilities[2..]);
    out.push(u8::try_from(NONCE_LENGTH + 1).unwrap_or(21));
    out.extend_from_slice(&[0u8; 10]);
    out.extend_from_slice(&nonce[8..]);
    out.push(0);
    cstring(&mut out, &greeting.plugin);
    out
}

/// The greeting a payload carries.
///
/// # Errors
/// A version other than 10, or a payload that breaks off.
pub fn decode_handshake(payload: &[u8]) -> Result<HandshakeV10> {
    let mut cursor = Cursor::new(payload);
    let version = cursor.byte()?;
    if version != PROTOCOL_VERSION {
        return Err(protocol_error(format!(
            "handshake version {version} is not 10"
        )));
    }
    let server_version = cursor.cstring()?;
    let connection_id = cursor.int32()?;
    let mut nonce = cursor.take(8)?.to_vec();
    cursor.skip(1)?;
    let lower = cursor.int16()?;
    cursor.skip(3)?;
    let upper = cursor.int16()?;
    let capabilities = u32::from(lower) | (u32::from(upper) << 16);
    let nonce_length = usize::from(cursor.byte()?);
    cursor.skip(10)?;
    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let second = nonce_length.saturating_sub(8).max(13);
        nonce.extend_from_slice(cursor.take(second)?);
        nonce.truncate(NONCE_LENGTH);
    }
    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        cursor.cstring()?
    } else {
        NATIVE_PASSWORD.to_string()
    };
    Ok(HandshakeV10 {
        server_version,
        connection_id,
        nonce,
        capabilities,
        plugin,
    })
}

/// `response` as a payload.
#[must_use]
pub fn encode_response(response: &HandshakeResponse41) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&response.capabilities.to_le_bytes());
    out.extend_from_slice(&0x0100_0000u32.to_le_bytes()); // max packet size
    out.push(UTF8MB4);
    out.extend_from_slice(&[0u8; 23]);
    cstring(&mut out, &response.user);
    out.push(u8::try_from(response.auth_response.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(&response.auth_response);
    if response.capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        cstring(&mut out, &response.database);
    }
    if response.capabilities & CLIENT_PLUGIN_AUTH != 0 {
        cstring(&mut out, &response.plugin);
    }
    out
}

/// The response a payload carries.
///
/// # Errors
/// A client without protocol 4.1, or a payload that breaks off.
pub fn decode_response(payload: &[u8]) -> Result<HandshakeResponse41> {
    let mut cursor = Cursor::new(payload);
    let capabilities = cursor.int32()?;
    if capabilities & CLIENT_PROTOCOL_41 == 0 {
        return Err(protocol_error("a client without protocol 4.1"));
    }
    cursor.skip(4 + 1 + 23)?;
    let user = cursor.cstring()?;
    let auth_response = if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let length = usize::try_from(cursor.lenenc_int()?).unwrap_or(0);
        cursor.take(length)?.to_vec()
    } else if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let length = usize::from(cursor.byte()?);
        cursor.take(length)?.to_vec()
    } else {
        let text = cursor.cstring()?;
        text.into_bytes()
    };
    let database = if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        cursor.cstring()?
    } else {
        String::new()
    };
    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        cursor.cstring()?
    } else {
        NATIVE_PASSWORD.to_string()
    };
    Ok(HandshakeResponse41 {
        capabilities,
        user,
        auth_response,
        database,
        plugin,
    })
}

/// A server's request to switch plugins mid-login: the plugin and its
/// nonce. The payload opens with `0xFE`.
///
/// # Errors
/// A payload that breaks off.
pub fn decode_auth_switch(payload: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut cursor = Cursor::new(payload);
    cursor.skip(1)?;
    let plugin = cursor.cstring()?;
    let mut nonce = cursor.rest().to_vec();
    if nonce.last() == Some(&0) {
        nonce.pop();
    }
    Ok((plugin, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha1::hex;

    #[test]
    fn the_native_password_is_the_documented_scramble() {
        let nonce: Vec<u8> = (1..=20).collect();
        let scrambled = scramble("secret", &nonce);
        assert_eq!(scrambled.len(), DIGEST_LENGTH);
        let mut salted = nonce.clone();
        salted.extend_from_slice(&sha1(&sha1(b"secret")));
        let expected: Vec<u8> = sha1(b"secret")
            .iter()
            .zip(sha1(&salted))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(hex(&scrambled), hex(&expected));
        assert!(verify("secret", &nonce, &scrambled));
        assert!(!verify("wrong", &nonce, &scrambled));
        assert!(!verify("secret", &[0; 20], &scrambled), "another nonce");
        assert!(scramble("", &nonce).is_empty());
        assert!(verify("", &nonce, &[]));
    }

    #[test]
    fn the_greeting_and_the_response_round_trip() {
        let greeting = HandshakeV10 {
            server_version: "8.4.0 (xmip)".into(),
            connection_id: 42,
            nonce: (b'a'..=b't').collect(),
            capabilities: CAPABILITIES,
            plugin: NATIVE_PASSWORD.into(),
        };
        let bytes = encode_handshake(&greeting);
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(decode_handshake(&bytes).expect("greeting"), greeting);
        assert!(decode_handshake(&[9, 0]).is_err(), "version 9");
        assert!(decode_handshake(&bytes[..12]).is_err(), "breaks off");

        let response = HandshakeResponse41 {
            capabilities: CAPABILITIES,
            user: "xmip".into(),
            auth_response: scramble("secret", &greeting.nonce),
            database: "orders".into(),
            plugin: NATIVE_PASSWORD.into(),
        };
        let bytes = encode_response(&response);
        assert_eq!(decode_response(&bytes).expect("response"), response);
        assert!(decode_response(&[0, 0, 0, 0]).is_err(), "not 4.1");
        assert!(decode_response(&bytes[..40]).is_err(), "breaks off");

        let no_database = HandshakeResponse41 {
            capabilities: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION,
            database: String::new(),
            plugin: NATIVE_PASSWORD.into(),
            ..response
        };
        let bytes = encode_response(&no_database);
        assert_eq!(decode_response(&bytes).expect("older client"), no_database);
    }

    #[test]
    fn an_auth_switch_names_its_plugin_and_nonce() {
        let mut payload = vec![0xfe];
        cstring(&mut payload, "caching_sha2_password");
        payload.extend_from_slice(b"nonce-nonce-nonce-no\0");
        let (plugin, nonce) = decode_auth_switch(&payload).expect("switch");
        assert_eq!(plugin, "caching_sha2_password");
        assert_eq!(nonce, b"nonce-nonce-nonce-no");
        assert!(decode_auth_switch(&[0xfe, b'x']).is_err());
    }
}
