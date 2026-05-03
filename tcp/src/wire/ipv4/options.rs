use crate::util::FixedBuf;
use crate::{Error, ParseError, Result};

/// IPv4 header options.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Options {
    buf: FixedBuf<{ Ipv4Options::MAX_OPTIONS_LEN }>,
}

impl Ipv4Options {
    /// Maximum length of IPv4 options in bytes.
    pub const MAX_OPTIONS_LEN: usize = 40;

    /// Returns the length of the `Ipv4Options` in bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the `Ipv4Options` contains no bytes.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns an immutable slice to the `Ipv4Options`.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Creates a new empty `Ipv4Options`.
    #[inline]
    #[must_use]
    pub(crate) const fn new() -> Self {
        Ipv4Options {
            buf: FixedBuf::new(),
        }
    }

    /// Creates a new `Ipv4Options` from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes.len() > Ipv4Options::MAX_OPTIONS_LEN`.
    #[inline]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let len = bytes.len();

        if len > Self::MAX_OPTIONS_LEN {
            return Err(Error::Parse(ParseError::InvalidOptionsLength {
                provided: len,
                expected: Self::MAX_OPTIONS_LEN,
            }));
        }

        let mut buf = FixedBuf::<{ Ipv4Options::MAX_OPTIONS_LEN }>::new();
        buf.append(bytes);

        Ok(Ipv4Options { buf })
    }
}
