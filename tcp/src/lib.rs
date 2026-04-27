//! Implementation of the Transmission Control Protocol (TCP), primarily based
//! on [RFC 793].
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

// TODO: Limitations
//
// Current limitations include, but are not limited to:
//
// - Handling of buffered application data (currently buffered, not drained)
// - No zero-window probing
// - No Initial Send Sequence Number (ISS) randomization
// - No congestion control algorithms (e.g., slow start, fast retransmit)
// - No support for Selective Acknowledgment (SACK)
// - No window scaling
// - TCP Fast Open is not implemented
// - No delayed acknowledgments
// - IPv4 options are not supported (only MSS, others are ignored)

pub mod log;

pub mod protocol;

pub mod error;
pub use error::{Error, HeaderError, ParseError, Result};
