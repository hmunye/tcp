//! Error types for failures in TCP communication.

use std::{error, fmt, io, result};

/// Creates a [crate::Error::Io] with a message prefixed to the `errno` value.
#[macro_export]
macro_rules! errno {
    ($($arg:tt)+) => {{
        let errno = ::std::io::Error::last_os_error();
        let prefix = format!($($arg)+);

        let msg = format!("{prefix}: {errno}");

        $crate::Error::Io(::std::io::Error::new(errno.kind(), msg))
    }};
}

/// A convenience wrapper around `Result` for `tcp::Error`.
pub type Result<T> = result::Result<T, Error>;

/// Errors that can occur during TCP communication.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// I/O error during TCP communication.
    Io(io::Error),
    /// Error occurred while parsing a TCP segment.
    Parse(ParseError),
    /// Error occurred while creating or configuring a TCP or IPv4 header.
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

/// Errors that can occur during TCP segment parsing.
#[derive(Debug)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ParseError {
    /// Input buffer size is outside the range specified by the header.
    InvalidBufferLength { provided: usize, min: u16 },
    /// Invalid IPv4 version.
    InvalidVersion { provided: u8, expected: u8 },
    /// Invalid IPv4 IHL.
    InvalidIhl { provided: u8, expected: u8 },
    /// Invalid IPv4 Total Length.
    ///
    /// The value provided is less than `IHL << 2`.
    InvalidTotalLength { provided: u16, expected: u8 },
    /// Invalid upper-layer protocol (undefined in RFC 1700).
    InvalidProtocol(u8),
    /// Invalid TCP Data Offset.
    InvalidDataOffset { provided: u16, min: u16, max: u16 },
    /// Mismatch between the provided and expected TCP header length.
    ///
    /// The value provided is less than `Data Offset << 2`.
    HeaderLengthMismatch { provided: usize, expected: u16 },
    /// Mismatch between the provided and expected TCP options length.
    ///
    /// The value provided is less than `(Data Offset - MIN_DATA_OFFSET) << 2`.
    OptionsLengthMismatch { provided: usize, expected: u16 },
    /// Invalid TCP Options length.
    InvalidOptionsLength { provided: usize, max: usize },
}

impl error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ParseError::InvalidBufferLength { provided, min } => {
                write!(
                    f,
                    "invalid buffer length: {provided} bytes (must be a least {min} bytes)"
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
            ParseError::InvalidTotalLength { provided, expected } => {
                write!(
                    f,
                    "invalid total length: {provided} bytes (less than indicated by IHL: {expected} bytes)"
                )
            }
            ParseError::InvalidProtocol(proto) => {
                write!(f, "invalid protocol: {proto} (undefined in RFC 1700)")
            }
            ParseError::InvalidDataOffset { provided, min, max } => {
                write!(
                    f,
                    "invalid data offset: {provided} (not within the range {min}..={max})"
                )
            }
            ParseError::HeaderLengthMismatch { provided, expected } => {
                write!(
                    f,
                    "invalid header length: {provided} bytes (less than indicated by data offset: {expected} bytes)"
                )
            }
            ParseError::OptionsLengthMismatch { provided, expected } => {
                write!(
                    f,
                    "invalid TCP options length: {provided} bytes (less than indicated by data offset: {expected} bytes)"
                )
            }
            ParseError::InvalidOptionsLength { provided, max } => {
                write!(
                    f,
                    "invalid TCP options length: {provided} bytes (exceeds maximum allowed {max} bytes)"
                )
            }
        }
    }
}

/// Errors that can occur when creating or configuring a TCP or IPv4 header.
#[derive(Debug)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum HeaderError {
    /// Payload length exceeds the maximum allowed for an IPv4 header.
    PayloadTooLarge { provided: u16, max: u16 },
    /// Not enough space to append the TCP option to the current TCP options.
    InsufficientOptionSpace {
        attempted: usize,
        current: usize,
        max: usize,
    },
    /// Invalid TCP `MSS` option.
    InvalidMssOption(u16),
}

impl error::Error for HeaderError {}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            HeaderError::PayloadTooLarge { provided, max } => {
                write!(
                    f,
                    "failed to set payload length: {provided} bytes (exceeds maximum allowed {max} bytes)"
                )
            }
            HeaderError::InsufficientOptionSpace {
                attempted,
                current,
                max,
            } => {
                write!(
                    f,
                    "failed to append TCP option to header: attempted to append {attempted} bytes (available space: {current} bytes, exceeds maximum allowed {max} bytes)"
                )
            }
            HeaderError::InvalidMssOption(val) => {
                write!(
                    f,
                    "failed to set TCP MSS option: {val} (must be greater than 0)"
                )
            }
        }
    }
}
