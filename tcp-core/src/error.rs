//! Error types for TCP over IPv4, including errors related to both IPv4 headers
//! and TCP segments.

use std::{error, fmt, io, result};

/// A convenience wrapper around `Result` for `tcp_core::Error`.
pub type Result<T> = result::Result<T, Error>;

/// Set of errors that can occur in TCP segment handling.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Error while reading or writing a TCP segment.
    Io(io::Error),
    /// Error parsing a TCP segment.
    Parse(ParseError),
    /// Error creating or manipulating an IPv4 or TCP header.
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
            Error::Io(ref err) => fmt::Display::fmt(err, f),
            Error::Parse(ref err) => fmt::Display::fmt(err, f),
            Error::Header(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

/// Error occurred while trying to parse a TCP over IPv4 segment.
#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ParseError {
    /// Input buffer not within the valid range for an IPv4/TCP header.
    InvalidBufferLength { provided: usize, min: u16, max: u16 },
    /// Invalid IPv4 version.
    InvalidVersion { provided: u8, expected: u8 },
    /// Invalid IPv4 IHL.
    InvalidIhl { provided: u8, expected: u8 },
    /// Invalid IPv4 total length.
    ///
    /// Value provided is less than `IHL << 2`.
    InvalidTotalLength { provided: u16, expected: u8 },
    /// Invalid IPv4 upper-layer protocol (undefined in RFC 1700).
    InvalidProtocol(u8),
    /// Invalid TCP data offset.
    InvalidDataOffset { provided: u16, min: u16, max: u16 },
    /// Mismatch between the provided and expected TCP header length.
    ///
    /// Value provided is less than `data_offset << 2`.
    HeaderLengthMismatch { provided: usize, expected: u16 },
    /// Mismatch between the provided and expected TCP options length.
    ///
    /// Value provided is less than `(data_offset - MIN_DATA_OFFSET) << 2`.
    OptionsLengthMismatch { provided: usize, expected: u16 },
    /// Invalid TCP options length.
    InvalidOptionsLength { provided: usize, max: usize },
}

impl error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ParseError::InvalidBufferLength { provided, min, max } => {
                write!(
                    f,
                    "invalid header length: {provided} bytes (not within the valid range: {min}..={max} bytes)"
                )
            }
            ParseError::InvalidVersion { provided, expected } => {
                write!(
                    f,
                    "invalid IP version: IPv{provided} (must be IPv{expected})"
                )
            }
            ParseError::InvalidIhl { provided, expected } => {
                write!(
                    f,
                    "invalid IPv4 IHL: {provided} (must be {expected}, IPv4 options are currently not supported)"
                )
            }
            ParseError::InvalidTotalLength { provided, expected } => {
                write!(
                    f,
                    "invalid IPv4 total length: {provided} bytes (less than indicated by IHL: {expected} bytes)"
                )
            }
            ParseError::InvalidProtocol(proto) => {
                write!(
                    f,
                    "invalid IPv4 upper-layer protocol: {proto} (undefined in RFC 1700)"
                )
            }
            ParseError::InvalidDataOffset { provided, min, max } => {
                write!(
                    f,
                    "invalid TCP data offset: {provided} (not within the valid range: {min}..={max})"
                )
            }
            ParseError::HeaderLengthMismatch { provided, expected } => {
                write!(
                    f,
                    "invalid TCP header length: {provided} bytes (less than indicated by data offset: {expected} bytes)"
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

/// Error occurred while trying to create or manipulate an IPv4 or TCP header.
#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum HeaderError {
    /// Invalid payload length for an IPv4 header.
    PayloadTooLarge { provided: u16, max: u16 },
    /// Insufficient space to append TCP option.
    InsufficientOptionSpace {
        attempted_len: usize,
        current_len: usize,
        max_len: usize,
    },
    /// Invalid TCP `MSS` option value.
    InvalidMssOption,
}

impl error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HeaderError::PayloadTooLarge { provided, max } => {
                write!(
                    f,
                    "failed to set IPv4 payload length: {provided} bytes (exceeds maximum allowed {max} bytes)"
                )
            }
            HeaderError::InsufficientOptionSpace {
                attempted_len,
                current_len,
                max_len,
            } => {
                write!(
                    f,
                    "failed to append TCP option to header: appending would result in {attempted_len} bytes, but current length is {current_len} (exceeds maximum allowed {max_len} bytes)"
                )
            }
            HeaderError::InvalidMssOption => {
                write!(f, "invalid TCP MSS option: value must be greater than 0")
            }
        }
    }
}
