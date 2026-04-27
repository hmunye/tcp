//! User-space implementation of the Transmission Control Protocol (TCP), based
//! primarily on [RFC 793].
//!
//! This crate implements TCP as a protocol engine: a state machine operating
//! over IPv4-based TCP segments that drives connection establishment, data
//! transfer, and connection teardown according to the specification.
//!
//! It is **not** a socket library and does not perform any I/O or interact with
//! the operating system’s networking facilities. Instead, it consumes and
//! produces raw TCP segments while maintaining the full per-connection state
//! required by the protocol.
//!
//! ### Feature Flags
//!
//! This crate uses a set of feature flags to reduce the amount of compiled
//! code, including:
//!
//! - `default`: Enables none of the features listed below.
//! - `full`: Enables all features listed below.
//! - `trace`: Enables internal TCP execution tracing of the state machine
//!   and segment processing for debugging.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

// TODO: Update lints after refactor.
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

// TODO: Fix limitations
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

// Must be defined first!
#[macro_use]
pub(crate) mod macros;

pub mod protocol;

pub mod error;
pub use error::{Error, HeaderError, ParseError, Result};
