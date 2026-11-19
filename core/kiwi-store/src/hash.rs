//! Content hashes (BLAKE3, 32 bytes).

use std::fmt;

/// A BLAKE3 content hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash([u8; 32]);

/// Error returned when a hex string is not a valid [`ContentHash`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a content hash is exactly 64 hexadecimal characters")]
pub struct HashParseError;

impl ContentHash {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Wraps raw hash bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Wraps a slice, if it has exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hashes a complete in-memory buffer.
    pub fn of_bytes(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Parses 64 hexadecimal characters (either case).
    pub fn from_hex(hex: &str) -> Result<Self, HashParseError> {
        let raw = hex.as_bytes();
        if raw.len() != 64 {
            return Err(HashParseError);
        }
        let mut out = [0u8; 32];
        for (i, pair) in raw.chunks_exact(2).enumerate() {
            let hi = hex_val(pair[0]).ok_or(HashParseError)?;
            let lo = hex_val(pair[1]).ok_or(HashParseError)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// Lower-case hexadecimal form.
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(DIGITS[(b >> 4) as usize] as char);
            s.push(DIGITS[(b & 0x0f) as usize] as char);
        }
        s
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl From<blake3::Hash> for ContentHash {
    fn from(h: blake3::Hash) -> Self {
        Self(*h.as_bytes())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let h = ContentHash::of_bytes(b"kiwi");
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(ContentHash::from_hex(&hex).unwrap(), h);
        assert_eq!(ContentHash::from_hex(&hex.to_uppercase()).unwrap(), h);
        assert_eq!(format!("{h}"), hex);
    }

    #[test]
    fn known_vector() {
        // BLAKE3 of the empty input (official test vector).
        assert_eq!(
            ContentHash::of_bytes(b"").to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(ContentHash::from_hex("").is_err());
        assert!(ContentHash::from_hex(&"a".repeat(63)).is_err());
        assert!(ContentHash::from_hex(&"a".repeat(65)).is_err());
        assert!(ContentHash::from_hex(&"g".repeat(64)).is_err());
        assert!(ContentHash::from_hex(&"é".repeat(32)).is_err());
        assert!(ContentHash::from_slice(&[0u8; 31]).is_none());
        assert!(ContentHash::from_slice(&[0u8; 32]).is_some());
    }
}
