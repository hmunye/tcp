//! TCP error types.

use std::{fmt, io};

use crate::wire::Protocol;

/// Convenience wrapper around `Result` for `tcp::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while processing TCP segments.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Transport-level and header processing errors.
    Io(io::Error),
    /// Invalid or malformed IPv4/TCP segment.
    Parse(ParseError),
    /// IPv4/TCP header construction or configuration error.
    Header(HeaderError),
}

impl std::error::Error for Error {}

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

/// Errors encountered while parsing IPv4/TCP segments.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// Invalid buffer length for IPv4/TCP header.
    InvalidBufferLength {
        provided: usize,
        min: usize,
        max: usize,
    },
    /// Invalid IP version.
    InvalidVersion { provided: u8, expected: u8 },
    /// Invalid IPv4 `IHL`.
    InvalidIhl { provided: u8, min: u8, max: u8 },
    /// Invalid IPv4 total length.
    InvalidTotalLength { provided: u16, expected: u16 },
    /// Unsupported/unassigned IPv4 protocol.
    InvalidProtocol { protocol: Protocol, value: u8 },
    /// Invalid TCP data offset.
    InvalidDataOffset { provided: u16, min: u8, max: u8 },
    /// Invalid IPv4/TCP header length.
    InvalidHeaderLength { provided: usize, expected: usize },
    /// Invalid IPv4/TCP options length.
    InvalidOptionsLength { provided: usize, expected: usize },
}

impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ParseError::InvalidBufferLength { provided, min, max } => {
                write!(
                    f,
                    "invalid buffer length for IPv4/TCP header: {provided} bytes available, expected: {min}..={max}"
                )
            }
            ParseError::InvalidVersion { provided, expected } => {
                write!(
                    f,
                    "invalid IP version: IPv{provided}, expected: IPv{expected}"
                )
            }
            ParseError::InvalidIhl { provided, min, max } => {
                write!(f, "invalid IPv4 IHL: {provided}, expected: {min}..={max}")
            }
            ParseError::InvalidTotalLength { provided, expected } => {
                write!(
                    f,
                    "invalid IPv4 total length: {provided} bytes available, expected: {expected} bytes"
                )
            }
            ParseError::InvalidProtocol { protocol, value } => {
                write!(f, "invalid IPv4 protocol: {value} ({protocol:?})")
            }
            ParseError::InvalidDataOffset { provided, min, max } => {
                write!(
                    f,
                    "invalid TCP data offset: {provided}, expected: {min}..={max}"
                )
            }
            ParseError::InvalidHeaderLength { provided, expected } => {
                write!(
                    f,
                    "invalid IPv4/TCP header length: {provided} bytes available, expected: {expected} bytes"
                )
            }
            ParseError::InvalidOptionsLength { provided, expected } => {
                write!(
                    f,
                    "invalid IPv4/TCP options length: {provided} bytes available, expected: {expected} bytes"
                )
            }
        }
    }
}

/// Errors encountered while constructing or configuring IPv4/TCP headers.
#[derive(Debug)]
#[non_exhaustive]
pub enum HeaderError {
    /// Invalid IPv4 payload length.
    PayloadTooLarge { provided: u16, max: u16 },
    /// Appending the TCP option will exceed maximum allowed options size.
    TcpOptionLengthExceeded { current: usize, max: usize },
    /// Invalid TCP `MSS` option value.
    InvalidTcpMssOption,
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HeaderError::PayloadTooLarge { provided, max } => {
                write!(
                    f,
                    "invalid IPv4 payload length: {provided} bytes available, expected: 0..={max}"
                )
            }
            HeaderError::TcpOptionLengthExceeded { current, max } => {
                write!(
                    f,
                    "TCP option space exceeded: {current} bytes used, appending would exceed maximum size: {max} bytes"
                )
            }
            HeaderError::InvalidTcpMssOption => {
                write!(f, "invalid TCP MSS option: value must be non-zero")
            }
        }
    }
}
