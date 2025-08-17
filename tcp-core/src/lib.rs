//! A minimal, third-party-free implementation of the Transmission Control Protocol
//! (TCP), based on [RFC 793].
//!
//! This project is experimental and not intended for production use.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod log;

pub mod protocol;

pub mod error;
pub use error::{Error, HeaderError, ParseError, Result};
