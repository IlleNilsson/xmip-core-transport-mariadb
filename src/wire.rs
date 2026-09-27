//! The protocol's framing and primitive fields: a three-byte little-endian
//! payload length, a sequence byte, and a payload of fixed integers,
//! length-encoded integers and strings, and NUL-terminated strings. A
//! payload of 16 MiB less one fills a packet exactly and continues in the
//! next; the sequence byte counts the packets of one exchange from zero and
//! starts over at every command.
//!
//! Fields are read and written through codec's byte cursor and writer;
//! what is `MySQL`'s own — the three-byte length, the length-encoded
//! integer and string, the NUL-terminated string — is [`Mysql`] on the
//! cursor and [`MysqlWrite`] beside the writer. The handshake is in
//! `handshake.rs` and what a query comes back with is in `result.rs`; this
//! file is what both are made of, and the two commands
//! this crate sends, because a command packet is one byte and the text.

use std::io::Read;

use codec::cursor::Cursor;
use codec::unicode::Form;
use codec::writer::ByteWriter;
use net::MAX_BODY;
use transport::ceiling;
use transport::error::{Result, classify, protocol_error};

/// The most one packet carries; a longer payload continues in the next.
pub const MAX_PACKET: usize = 0xff_ffff;

/// The client is done.
pub const COM_QUIT: u8 = 0x01;
/// The client runs a statement as text.
pub const COM_QUERY: u8 = 0x03;

/// What a client sends after the login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Quit,
    Query(String),
}

/// `command` as a payload.
#[must_use]
pub fn encode_command(command: &Command) -> Vec<u8> {
    match command {
        Command::Quit => vec![COM_QUIT],
        Command::Query(sql) => {
            let mut out = Vec::with_capacity(sql.len() + 1);
            out.push(COM_QUERY);
            out.extend_from_slice(sql.as_bytes());
            out
        }
    }
}

/// The command a payload carries.
///
/// # Errors
/// An empty payload, a command this crate does not serve, or a query
/// that is not UTF-8.
pub fn decode_command(payload: &[u8]) -> Result<Command> {
    match payload.split_first() {
        Some((&COM_QUIT, _)) => Ok(Command::Quit),
        Some((&COM_QUERY, sql)) => Ok(Command::Query(Form::Utf8.decode(sql)?)),
        Some((other, _)) => Err(protocol_error(format!(
            "command {other:#04x} is not one this crate serves"
        ))),
        None => Err(protocol_error("an empty command packet")),
    }
}

/// `payload` as one packet or more, `sequence` counting them.
#[must_use]
pub fn frame(sequence: &mut u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    let mut chunks = payload.chunks(MAX_PACKET).peekable();
    let mut last_was_full = payload.is_empty();
    while let Some(chunk) = chunks.next() {
        out.int24(chunk.len()).byte(*sequence).bytes(chunk);
        *sequence = sequence.wrapping_add(1);
        last_was_full = chunk.len() == MAX_PACKET && chunks.peek().is_none();
    }
    if last_was_full {
        out.extend_from_slice(&[0, 0, 0, *sequence]);
        *sequence = sequence.wrapping_add(1);
    }
    out
}

/// One payload, continuation packets joined: its first sequence byte and
/// bytes, or `None` when the peer closed before a header.
///
/// # Errors
/// A read that failed, or a payload over `net::MAX_BODY`.
pub fn read_packet(reader: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut payload = Vec::new();
    let mut first = None;
    loop {
        let mut header = [0u8; 4];
        let read = reader
            .read(&mut header[..1])
            .map_err(|e| classify("reading a packet header", &e))?;
        if read == 0 {
            return match first {
                None => Ok(None),
                Some(_) => Err(protocol_error("the peer closed inside a packet")),
            };
        }
        reader
            .read_exact(&mut header[1..])
            .map_err(|e| classify("reading a packet header", &e))?;
        let length =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        if first.is_none() {
            first = Some(header[3]);
        }
        ceiling::within(
            payload.len() + length,
            MAX_BODY,
            "Xmip reads in one payload",
        )?;
        let start = payload.len();
        payload.resize(start + length, 0);
        reader
            .read_exact(&mut payload[start..])
            .map_err(|e| classify("reading a packet payload", &e))?;
        if length < MAX_PACKET {
            return Ok(first.map(|sequence| (sequence, payload)));
        }
    }
}

/// `MySQL`'s own fields, read off codec's cursor. Fixed integers are codec's,
/// little-endian (`u16_le`, `u32_le`).
pub trait Mysql {
    /// The next length-encoded integer.
    ///
    /// # Errors
    /// Nothing remains, the integer breaks off, or its first byte is the
    /// NULL marker or one the encoding does not use.
    fn lenenc_int(&mut self) -> Result<u64>;

    /// The next length-encoded string, strictly UTF-8.
    ///
    /// # Errors
    /// The length or the string breaks off, or it is not UTF-8.
    fn lenenc_str(&mut self) -> Result<String>;

    /// The next NUL-terminated string, strictly UTF-8.
    ///
    /// # Errors
    /// No NUL before the end, or it is not UTF-8.
    fn cstring(&mut self) -> Result<String>;
}

impl Mysql for Cursor<'_> {
    fn lenenc_int(&mut self) -> Result<u64> {
        let width = match self.byte()? {
            small @ 0..=0xfa => return Ok(u64::from(small)),
            0xfc => 2,
            0xfd => 3,
            0xfe => 8,
            other => {
                return Err(protocol_error(format!(
                    "{other:#04x} does not open a length-encoded integer"
                )));
            }
        };
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(self.take(width)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn lenenc_str(&mut self) -> Result<String> {
        let length = usize::try_from(self.lenenc_int()?)
            .map_err(|_| protocol_error("a string longer than memory"))?;
        Ok(Form::Utf8.decode(self.take(length)?)?)
    }

    fn cstring(&mut self) -> Result<String> {
        Ok(Form::Utf8.decode(self.take_until(0)?)?)
    }
}

/// `MySQL`'s own fields, written beside codec's writer.
pub trait MysqlWrite {
    /// `count` as the packet header's three bytes, little-endian, at most
    /// [`MAX_PACKET`].
    fn int24(&mut self, count: usize) -> &mut Self;

    /// `value` as a length-encoded integer.
    fn lenenc_int(&mut self, value: u64) -> &mut Self;

    /// `bytes` behind its length-encoded length.
    fn lenenc_bytes(&mut self, bytes: &[u8]) -> &mut Self;

    /// `text` followed by the NUL that ends a wire string.
    fn cstring(&mut self, text: &str) -> &mut Self;
}

impl MysqlWrite for Vec<u8> {
    fn int24(&mut self, count: usize) -> &mut Self {
        let bytes = u32::try_from(count.min(MAX_PACKET))
            .unwrap_or(0)
            .to_le_bytes();
        self.bytes(&bytes[..3])
    }

    fn lenenc_int(&mut self, value: u64) -> &mut Self {
        let bytes = value.to_le_bytes();
        match value {
            0..=0xfa => self.byte(bytes[0]),
            0xfb..=0xffff => self.byte(0xfc).bytes(&bytes[..2]),
            0x1_0000..=0xff_ffff => self.byte(0xfd).bytes(&bytes[..3]),
            _ => self.byte(0xfe).bytes(&bytes),
        }
    }

    fn lenenc_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.lenenc_int(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .bytes(bytes)
    }

    fn cstring(&mut self, text: &str) -> &mut Self {
        self.bytes(text.as_bytes()).byte(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_carries_its_length_and_sequence() {
        let mut sequence = 0;
        let framed = frame(&mut sequence, b"\x03SELECT 1");
        assert_eq!(&framed[..4], &[9, 0, 0, 0]);
        assert_eq!(sequence, 1);
        let (seq, payload) = read_packet(&mut framed.as_slice())
            .expect("read")
            .expect("one");
        assert_eq!(seq, 0);
        assert_eq!(
            decode_command(&payload).expect("command"),
            Command::Query("SELECT 1".into())
        );
        assert!(read_packet(&mut &b""[..]).expect("closed").is_none());
        assert!(
            read_packet(&mut &[9, 0, 0, 0, b'x'][..]).is_err(),
            "breaks off"
        );
        assert!(
            read_packet(&mut &[0xff, 0xff, 0xff, 0, 1][..]).is_err(),
            "the continuation never comes"
        );
    }

    #[test]
    fn a_long_payload_is_split_and_joined_again() {
        let payload = vec![0xabu8; MAX_PACKET + 5];
        let mut sequence = 3;
        let framed = frame(&mut sequence, &payload);
        assert_eq!(framed.len(), payload.len() + 8);
        assert_eq!(&framed[..4], &[0xff, 0xff, 0xff, 3]);
        assert_eq!(&framed[MAX_PACKET + 4..MAX_PACKET + 8], &[5, 0, 0, 4]);
        assert_eq!(sequence, 5);
        let (seq, joined) = read_packet(&mut framed.as_slice())
            .expect("read")
            .expect("one");
        assert_eq!((seq, joined.len()), (3, payload.len()));

        let exact = vec![1u8; MAX_PACKET];
        let mut sequence = 0;
        let framed = frame(&mut sequence, &exact);
        assert_eq!(
            &framed[MAX_PACKET + 4..],
            &[0, 0, 0, 1],
            "an empty packet ends it"
        );
        assert_eq!(sequence, 2);
        let (_, joined) = read_packet(&mut framed.as_slice())
            .expect("read")
            .expect("one");
        assert_eq!(joined.len(), MAX_PACKET);
        let empty = frame(&mut 7, b"");
        assert_eq!(empty, [0, 0, 0, 7]);
    }

    #[test]
    fn the_primitive_fields_read_back() {
        let mut out = Vec::new();
        for value in [
            0,
            0xfa,
            0xfb,
            0xffff,
            0x1_0000,
            0xff_ffff,
            0x100_0000,
            u64::MAX,
        ] {
            out.lenenc_int(value);
        }
        out.lenenc_bytes(b"payload")
            .cstring("def")
            .u16_le(7)
            .u32_le(70_000)
            .byte(b'Z');
        let mut cursor = Cursor::new(&out);
        for value in [
            0,
            0xfa,
            0xfb,
            0xffff,
            0x1_0000,
            0xff_ffff,
            0x100_0000,
            u64::MAX,
        ] {
            assert_eq!(cursor.lenenc_int().expect("int"), value);
        }
        assert_eq!(cursor.lenenc_str().expect("str"), "payload");
        assert_eq!(cursor.cstring().expect("cstring"), "def");
        assert_eq!(cursor.u16_le().expect("u16"), 7);
        assert_eq!(cursor.u32_le().expect("u32"), 70_000);
        assert_eq!(cursor.peek(), Some(b'Z'));
        assert_eq!(cursor.take_rest(), b"Z");
        assert!(cursor.is_empty());
        let error = cursor.byte().expect_err("past the end");
        assert!(error.message.contains("runs past"), "{}", error.message);
        assert!(
            Cursor::new(&[0xfb]).lenenc_int().is_err(),
            "NULL is not an integer"
        );
        let error = Cursor::new(&[0xfc, 1])
            .lenenc_int()
            .expect_err("breaks off");
        assert!(error.message.contains("runs past"), "{}", error.message);
        assert!(!error.retryable);
        assert!(Cursor::new(b"no NUL").cstring().is_err());
        assert!(decode_command(&[0x0e]).is_err(), "COM_PING is not served");
        assert!(decode_command(&[]).is_err());
        assert_eq!(encode_command(&Command::Quit), [COM_QUIT]);
    }
}
