//! SHA-1, as the native password needs it and nothing else does.
//!
//! `mysql_native_password` is SHA-1 three times over a password and a
//! nonce (`handshake.rs`), and SHA-1 has no other use in this crate — it
//! is broken for what a hash is meant for, and the estate's archives and
//! signatures use SHA-256. Eighty rounds over sixteen words is the whole
//! algorithm, so it is written here with the standard library rather than
//! pulling a crate in for one login, and checked against the vectors in
//! FIPS 180-1.

/// A digest as lower-case hex, for a test or a log.
pub use transport::hex::hex;

/// A SHA-1 digest is twenty bytes.
pub const DIGEST_LENGTH: usize = 20;

/// The SHA-1 digest of `message`.
#[must_use]
pub fn sha1(message: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bits = u64::try_from(message.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    padded.extend_from_slice(&bits.to_be_bytes());
    for block in padded.chunks_exact(64) {
        compress(&mut state, block);
    }
    let mut digest = [0u8; DIGEST_LENGTH];
    for (word, out) in state.iter().zip(digest.chunks_exact_mut(4)) {
        out.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// One 64-byte block folded into the state.
// The names are FIPS 180-1's own — a to e, f, k, w — and a reader checking
// this against the specification is better served by them than by longer ones.
#[allow(clippy::many_single_char_names)]
fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (t, word) in w.iter().enumerate() {
        let (f, k) = match t {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fips_vectors_come_out() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha1(&million_a)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn a_message_that_ends_on_a_block_edge_still_pads() {
        let sixty_four = [b'x'; 64];
        let fifty_five = [b'x'; 55];
        assert_ne!(sha1(&sixty_four), sha1(&fifty_five));
        assert_eq!(sha1(&sixty_four).len(), DIGEST_LENGTH);
    }
}
