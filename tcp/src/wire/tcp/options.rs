use crate::wire::FixedBuf;
use crate::{Error, HeaderError, ParseError, Result};

/// TCP header options.
#[derive(Debug, Clone, Copy)]
pub struct TcpOptions {
    buf: FixedBuf<{ TcpOptions::MAX_OPTIONS_LEN }>,
}

impl TcpOptions {
    /// Maximum length of TCP options in bytes.
    pub const MAX_OPTIONS_LEN: usize = 40;

    /// Length of the `MSS` TCP option in bytes.
    pub(crate) const MSS_LEN: usize = 4;

    /// Returns the `Maximum Segment Size` (MSS) option value, or `None` if not
    /// set.
    #[inline]
    pub fn mss(&self) -> Option<u16> {
        let mut i = 0;
        let opts = self.as_slice();

        while i < opts.len() {
            match opts[i].into() {
                OptionKind::EOL => break,
                OptionKind::NOP => {
                    // Length of `NOP`.
                    i += 1;
                }
                OptionKind::MSS => {
                    // RFC 793, Section 3.1:
                    //
                    // ```
                    //                     |-- Length of the TCP option
                    //                     v
                    //        1        2        3         4
                    //        +--------+--------+---------+--------+
                    //        |00000010|00000100|   max seg size   |
                    //        +--------+--------+---------+--------+
                    //            ^              ^^^^^^^^^^^^^^^^^^
                    //            |-- Here        Want these bytes
                    // ```
                    //
                    // Length of `MSS` option must be `0x04` (4 bytes).
                    if *opts.get(i + 1)? != 0x04 {
                        break;
                    }

                    return Some(u16::from_be_bytes([*opts.get(i + 2)?, *opts.get(i + 3)?]));
                }
                OptionKind::Unsupported => {
                    // Length of unsupported TCP option.
                    i += *opts.get(i + 1)? as usize;
                }
            }
        }

        None
    }

    /// Returns the length of the `TcpOptions` in bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the `TcpOptions` contains no bytes.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns an immutable slice to the `TcpOptions`.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Creates a new empty `TcpOptions`.
    #[inline]
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            buf: FixedBuf::new(),
        }
    }

    /// Creates a new`TcpOptions` from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes.len() > TcpOptions::MAX_OPTIONS_LEN`.
    #[inline]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let len = bytes.len();

        if len > Self::MAX_OPTIONS_LEN {
            return Err(Error::Parse(ParseError::InvalidOptionsLength {
                provided: len,
                expected: Self::MAX_OPTIONS_LEN,
            }));
        }

        let mut buf = FixedBuf::<{ TcpOptions::MAX_OPTIONS_LEN }>::new();
        buf.append(bytes);

        Ok(TcpOptions { buf })
    }

    /// Appends `Maximum Segment Size` (MSS) option to `TcpOptions` using the
    /// given value.
    ///
    /// # Errors
    ///
    /// Returns an error if the `TcpOptions` lack sufficient space to append
    /// the `MSS`, or if `mss` is zero.
    #[inline]
    pub(crate) fn set_mss(&mut self, mss: u16) -> Result<()> {
        if mss == 0 {
            return Err(Error::Header(HeaderError::InvalidTcpMssOption));
        }

        let len = self.len();

        if Self::MSS_LEN > self.buf.remaining() {
            return Err(Error::Header(HeaderError::TcpOptionLengthExceeded {
                current: len,
                max: Self::MAX_OPTIONS_LEN,
            }));
        }

        if self.mss().is_none() {
            let mut mss_option = [0u8; Self::MSS_LEN];

            mss_option[0] = OptionKind::MSS as u8;
            mss_option[1] = 0x04;
            mss_option[2..4].copy_from_slice(&mss.to_be_bytes());

            self.buf.append(&mss_option);
        }

        Ok(())
    }
}

/// Different TCP options [(RFC 793, Section 3.1)].
///
/// [(RFC 793, Section 3.1)]: https://www.rfc-editor.org/rfc/rfc793#section-3.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum OptionKind {
    /// End of Option List
    ///
    /// ```text
    ///        +--------+
    ///        |00000000|
    ///        +--------+
    ///          Kind=0
    /// ```
    ///
    /// This option code indicates the end of the option list. This might not
    /// coincide with the end of the TCP header according to the `Data Offset`
    /// field. This is used at the end of all options, not the end of each
    /// option, and need only be used if the end of the options would not
    /// otherwise coincide with the end of the TCP header.
    EOL = 0o00,
    /// No-Operation
    ///
    /// ```text
    ///        +--------+
    ///        |00000001|
    ///        +--------+
    ///          Kind=1
    /// ```
    ///
    /// This option code may be used between options, for example, to align the
    /// beginning of a subsequent option on a word boundary. There is no
    /// guarantee that senders will use this option, so receivers must be
    /// prepared to process options even if they do not begin on a word
    /// boundary.
    NOP = 0o01,
    /// Maximum Segment Size
    ///
    /// ```text
    ///        +--------+--------+---------+--------+
    ///        |00000010|00000100|   max seg size   |
    ///        +--------+--------+---------+--------+
    ///          Kind=2  Length=4
    /// ```
    ///
    /// If this option is present, then it communicates the maximum receive
    /// segment size at the TCP which sends this segment. This field must only
    /// be sent in the initial connection request (i.e., in segments with the
    /// `SYN` flag set).
    MSS = 0o02,

    /// Unsupported TCP Option.
    Unsupported,
}

impl From<u8> for OptionKind {
    fn from(val: u8) -> Self {
        match val {
            0 => OptionKind::EOL,
            1 => OptionKind::NOP,
            2 => OptionKind::MSS,
            _ => OptionKind::Unsupported,
        }
    }
}
