//! The protocol's framing and primitive fields: a three-byte little-endian
//! payload length, a sequence byte, and a payload of fixed integers,
//! length-encoded integers and strings, and NUL-terminated strings. A
//! payload of 16 MiB less one fills a packet exactly and continues in the
//! next; the sequence byte counts the packets of one exchange from zero and
//! starts over at every command.
//!
//! The handshake is in `handshake.rs` and what a query comes back with is
//! in `result.rs`; this file is what both are made of, and the two commands
//! this crate sends, because a command packet is one byte and the text.

use std::io::Read;

use transport::error::{Result, classify, protocol_error};

/// The most one packet carries; a longer payload continues in the next.
pub const MAX_PACKET: usize = 0xff_ffff;
/// The most one payload may be, packets joined.
pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

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
/// An empty payload, or a command this crate does not serve.
pub fn decode_command(payload: &[u8]) -> Result<Command> {
    match payload.split_first() {
        Some((&COM_QUIT, _)) => Ok(Command::Quit),
        Some((&COM_QUERY, sql)) => Ok(Command::Query(String::from_utf8_lossy(sql).into_owned())),
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
        out.extend_from_slice(&int24(chunk.len()));
        out.push(*sequence);
        *sequence = sequence.wrapping_add(1);
        out.extend_from_slice(chunk);
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
/// A read that failed, or a payload over [`MAX_PAYLOAD`].
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
        if payload.len() + length > MAX_PAYLOAD {
            return Err(protocol_error("a payload over what Xmip will read"));
        }
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

/// `count` as the header's three bytes, little-endian.
#[must_use]
pub fn int24(count: usize) -> [u8; 3] {
    let bytes = u32::try_from(count.min(MAX_PACKET))
        .unwrap_or(0)
        .to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

/// `value` as a length-encoded integer.
pub fn lenenc_int(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0xfa => out.push(u8::try_from(value).unwrap_or(0)),
        0xfb..=0xffff => {
            out.push(0xfc);
            out.extend_from_slice(&value.to_le_bytes()[..2]);
        }
        0x1_0000..=0xff_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&value.to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// `bytes` behind its length-encoded length.
pub fn lenenc_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    lenenc_int(out, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(bytes);
}

/// `text` followed by the NUL that ends a wire string.
pub fn cstring(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

/// Reads a payload's fields in order.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// True when nothing remains.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// The next `count` bytes.
    ///
    /// # Errors
    /// Fewer than `count` bytes remain.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol_error("a field that runs past the packet"))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// Everything that remains.
    #[must_use]
    pub fn rest(&mut self) -> &'a [u8] {
        let slice = &self.bytes[self.at.min(self.bytes.len())..];
        self.at = self.bytes.len();
        slice
    }

    /// Past the next `count` bytes.
    ///
    /// # Errors
    /// Fewer than `count` bytes remain.
    pub fn skip(&mut self, count: usize) -> Result<()> {
        self.take(count).map(|_| ())
    }

    /// The next byte.
    ///
    /// # Errors
    /// Nothing remains.
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// The next byte without taking it.
    #[must_use]
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// The next little-endian u16.
    ///
    /// # Errors
    /// Fewer than two bytes remain.
    pub fn int16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// The next little-endian u32.
    ///
    /// # Errors
    /// Fewer than four bytes remain.
    pub fn int32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The next length-encoded integer.
    ///
    /// # Errors
    /// Nothing remains, the integer breaks off, or its first byte is the
    /// NULL marker or one the encoding does not use.
    pub fn lenenc_int(&mut self) -> Result<u64> {
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

    /// The next length-encoded string, lossily UTF-8.
    ///
    /// # Errors
    /// The length or the string breaks off.
    pub fn lenenc_str(&mut self) -> Result<String> {
        let length = usize::try_from(self.lenenc_int()?)
            .map_err(|_| protocol_error("a string longer than memory"))?;
        Ok(String::from_utf8_lossy(self.take(length)?).into_owned())
    }

    /// The next NUL-terminated string, lossily UTF-8.
    ///
    /// # Errors
    /// No NUL before the end.
    pub fn cstring(&mut self) -> Result<String> {
        let end = self.bytes[self.at.min(self.bytes.len())..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| protocol_error("a string that never ends"))?;
        let text = String::from_utf8_lossy(self.take(end)?).into_owned();
        self.skip(1)?;
        Ok(text)
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
            lenenc_int(&mut out, value);
        }
        lenenc_bytes(&mut out, b"payload");
        cstring(&mut out, "def");
        out.extend_from_slice(&7u16.to_le_bytes());
        out.extend_from_slice(&70_000u32.to_le_bytes());
        out.push(b'Z');
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
        assert_eq!(cursor.int16().expect("u16"), 7);
        assert_eq!(cursor.int32().expect("u32"), 70_000);
        assert_eq!(cursor.peek(), Some(b'Z'));
        assert_eq!(cursor.rest(), b"Z");
        assert!(cursor.is_empty());
        assert!(cursor.byte().is_err(), "past the end");
        assert!(
            Cursor::new(&[0xfb]).lenenc_int().is_err(),
            "NULL is not an integer"
        );
        assert!(Cursor::new(&[0xfc, 1]).lenenc_int().is_err(), "breaks off");
        assert!(Cursor::new(b"no NUL").cstring().is_err());
        assert!(decode_command(&[0x0e]).is_err(), "COM_PING is not served");
        assert!(decode_command(&[]).is_err());
        assert_eq!(encode_command(&Command::Quit), [COM_QUIT]);
    }
}
