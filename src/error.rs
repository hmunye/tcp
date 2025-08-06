use std::{error, fmt, io, result};

/// Creates a [`crate::Error::Io`] with a custom message prefixed to the current
/// `errno` value.
macro_rules! errno {
    ($($arg:tt)+) => {{
        let errno = ::std::io::Error::last_os_error();
        let prefix = format!($($arg)+);
        let msg = format!("{prefix}: {errno}");
        $crate::Error::Io(::std::io::Error::new(errno.kind(), msg))
    }};
}
pub(crate) use errno;

/// A convenience wrapper around `Result` for [crate::Error].
pub type Result<T> = result::Result<T, Error>;

/// Represents errors that can occur during TCP communication.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error occurred during TCP communication.
    Io(io::Error),
    /// An error occurred during TCP packet parsing.
    Parse(ParseError),
    /// An error occurred constructing or configuring a TCP or IPv4 header.
    Header(HeaderError),
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Error {
        Error::Parse(err)
    }
}

impl From<HeaderError> for Error {
    fn from(err: HeaderError) -> Error {
        Error::Header(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::Parse(ref e) => fmt::Display::fmt(e, f),
            Error::Header(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

/// Represents errors that can occur during TCP packet parsing.
#[derive(Debug)]
pub enum ParseError {
    /// The input buffer is smaller than the minimum header length.
    InvalidBufferLength {
        /// The length of the input buffer provided.
        provided: usize,
        /// The minimum required length for the header.
        minimum: u16,
    },
    /// The Invalid IPv4 version value.
    InvalidVersion {
        /// The version value provided.
        provided: u8,
        /// The expected version value (4).
        expected: u8,
    },
    /// Invalid IPv4 IHL value.
    InvalidIhl {
        /// The IHL value provided.
        provided: u8,
        /// The expected IHL value (5).
        expected: u8,
    },
    /// Invalid IPv4 total length.
    ///
    /// The value provided is less that header length indicated by IHL.
    InvalidTotalLength {
        /// The total length value provided.
        provided: u16,
        /// The actual header length indicated by the IHL.
        actual: u8,
    },
    /// Invalid protocol number (not defined in RFC 1700).
    InvalidProtocol(u8),
    /// Invalid TCP data offset value.
    InvalidDataOffset {
        /// The data offset value provided.
        provided: u16,
        /// The minimum required value for TCP data offset.
        minimum: u16,
    },
    /// The buffer length is less than the TCP header length indicated by the data
    /// offset.
    HeaderLengthMismatch {
        /// The length of the buffer provided.
        provided: usize,
        /// The actual header length indicated by the data offset.
        actual: u16,
    },
    /// The options length is less than the TCP options length indicated by the
    /// data offset.
    OptionsLengthMismatch {
        /// The length of the options provided.
        provided: usize,
        /// The actual options length indicated by the data offset.
        actual: u16,
    },
    /// The options buffer length exceeds the maximum allowed for TCP options.
    InvalidOptionsLength {
        /// The length of the options buffer provided.
        provided: usize,
        /// The maximum allowed length for TCP options.
        maximum: u16,
    },
}

impl error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ParseError::InvalidBufferLength { provided, minimum } => {
                write!(
                    f,
                    "invalid buffer length: {provided} bytes (less than minimum required {minimum} bytes)",
                )
            }
            ParseError::InvalidVersion { provided, expected } => {
                write!(
                    f,
                    "invalid IP version: {provided} (must be {expected}, indicating IPv4)",
                )
            }
            ParseError::InvalidIhl { provided, expected } => {
                write!(
                    f,
                    "invalid IHL: {provided} (expected {expected} since IP options are currently not supported)",
                )
            }
            ParseError::InvalidTotalLength { provided, actual } => {
                write!(
                    f,
                    "invalid total length: {provided} bytes (less than indicated header length {actual} bytes)"
                )
            }
            ParseError::InvalidProtocol(proto) => {
                write!(f, "invalid protocol: {proto} (not defined in RFC 1700)")
            }
            ParseError::InvalidDataOffset { provided, minimum } => {
                write!(
                    f,
                    "invalid data offset: {provided} (less than minimum required {minimum})"
                )
            }
            ParseError::HeaderLengthMismatch { provided, actual } => {
                write!(
                    f,
                    "invalid header length: {provided} bytes (less than indicated header length {actual} bytes)"
                )
            }
            ParseError::OptionsLengthMismatch { provided, actual } => {
                write!(
                    f,
                    "invalid TCP options length: {provided} bytes (less than indicated TCP options length {actual} bytes)"
                )
            }
            ParseError::InvalidOptionsLength { provided, maximum } => {
                write!(
                    f,
                    "invalid TCP options length: {provided} bytes (exceeds maximum allowed {maximum} bytes)"
                )
            }
        }
    }
}

/// Represents errors that can occur when configuring a TCP or IPv4 header.
#[derive(Debug)]
pub enum HeaderError {
    /// Payload length exceeds the maximum allowed for an IPv4 header.
    PayloadTooLarge {
        /// The provided payload length.
        provided: u16,
        /// The maximum allowed IPv4 payload length.
        maximum: u16,
    },
    /// Not enough space to append the TCP option to the current TCP options.
    InsufficientOptionSpace {
        /// The length of the TCP option being appended.
        attempted: usize,
        /// The total length allowed for TCP options.
        maximum: u16,
    },
    /// Invalid MSS option value.
    InvalidMssOption(u16),
}

impl error::Error for HeaderError {}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            HeaderError::PayloadTooLarge { provided, maximum } => {
                write!(
                    f,
                    "failed to set payload length: {provided} bytes (exceeds maximum allowed {maximum} bytes)"
                )
            }
            HeaderError::InsufficientOptionSpace { attempted, maximum } => {
                write!(
                    f,
                    "failed to append option to header: {attempted} bytes (exceeds available space, maximum allowed {maximum} bytes)"
                )
            }
            HeaderError::InvalidMssOption(val) => {
                write!(
                    f,
                    "failed to set MSS option: {val} (must be greater than 0)"
                )
            }
        }
    }
}
