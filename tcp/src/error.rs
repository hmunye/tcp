//! Transmission Control Protocol (TCP) error types.

use std::{error, fmt, io, result};

/// Convenience wrapper around `Result` for `tcp::Error`.
pub type Result<T> = result::Result<T, Error>;

/// Errors that can occur while processing TCP segments.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Transport-level error (e.g., connection reset).
    Io(io::Error),
    /// Invalid or malformed TCP over IPv4 segment.
    Parse(ParseError),
    /// IPv4/TCP header construction or configuration error.
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

/// Errors encountered while parsing TCP over IPv4 segments.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// Buffer length outside the valid IPv4/TCP header range.
    InvalidBufferLength { provided: usize, min: u16, max: u16 },
    /// Invalid IP version.
    InvalidVersion { provided: u8, expected: u8 },
    /// Invalid IPv4 `IHL`.
    InvalidIhl { provided: u8, expected: u8 },
    /// IPv4 `total_length` less than the minimum implied by `IHL`.
    InvalidTotalLength { provided: u16, expected: u8 },
    /// Unsupported IPv4 `protocol`.
    InvalidProtocol(u8),
    /// Invalid TCP `data_offset`.
    InvalidDataOffset { provided: u16, min: u16, max: u16 },
    /// TCP header length less than the value implied by `data_offset`.
    InvalidHeaderLength { provided: usize, expected: u16 },
    /// TCP options length not equal to the value implied by `data_offset`.
    InvalidOptionsLength { provided: usize, expected: u16 },
    /// TCP options length exceeds the maximum allowed size.
    OptionsLengthTooLarge { provided: usize, max: usize },
}

impl error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ParseError::InvalidBufferLength { provided, min, max } => {
                write!(
                    f,
                    "invalid buffer length: {provided} bytes available (expected range: {min}..={max})"
                )
            }
            ParseError::InvalidVersion { provided, expected } => {
                write!(
                    f,
                    "invalid IP version: IPv{provided} (expected IPv{expected})"
                )
            }
            ParseError::InvalidIhl { provided, expected } => {
                write!(f, "invalid IPv4 IHL: {provided} (expected {expected})")
            }
            ParseError::InvalidTotalLength { provided, expected } => {
                write!(
                    f,
                    "invalid IPv4 total length: {provided} bytes available, need at least {expected} bytes (per IHL)"
                )
            }
            ParseError::InvalidProtocol(proto) => {
                write!(
                    f,
                    "invalid IPv4 protocol: {proto} (unsupported or undefined)"
                )
            }
            ParseError::InvalidDataOffset { provided, min, max } => {
                write!(
                    f,
                    "invalid TCP data offset: {provided} (expected range: {min}..={max})"
                )
            }
            ParseError::InvalidHeaderLength { provided, expected } => {
                write!(
                    f,
                    "invalid TCP header length: {provided} bytes available, need at least {expected} bytes (per data offset)"
                )
            }
            ParseError::InvalidOptionsLength { provided, expected } => {
                write!(
                    f,
                    "invalid TCP options length: {provided} bytes available, expected {expected} bytes (per data offset)"
                )
            }
            ParseError::OptionsLengthTooLarge { provided, max } => {
                write!(
                    f,
                    "invalid TCP options length: {provided} bytes available (expected range: 0..={max})"
                )
            }
        }
    }
}

/// Errors encountered while constructing or configuring IPv4/TCP headers.
#[derive(Debug)]
#[non_exhaustive]
pub enum HeaderError {
    /// IPv4 payload length exceeds the maximum allowed size.
    PayloadTooLarge { provided: u16, max: u16 },
    /// Adding TCP option will exceed maximum allowed size.
    OptionLengthExceeded { current: usize, max: usize },
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
                    "invalid IPv4 payload length: {provided} bytes available (expected range: 0..={max})"
                )
            }
            HeaderError::OptionLengthExceeded { current, max } => {
                write!(
                    f,
                    "TCP option space exceeded: {current} bytes used (appending would exceed maximum size: {max} bytes)"
                )
            }
            HeaderError::InvalidMssOption => {
                write!(f, "invalid TCP MSS option: value must be non-zero")
            }
        }
    }
}
