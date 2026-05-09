//! User-space implementation of the Transmission Control Protocol (TCP), based
//! primarily on [RFC 793].
//!
//! Implemented as a protocol engine: a state machine operating over IPv4-based
//! TCP segments that manages connection lifecycle, bidirectional data transfer,
//! and termination/reset.
//!
//! This crate is **not a socket library.** It performs no network I/O and
//! shares no state with the host operating system. Instead, it drives a TCP
//! state machine over raw byte slices, generating TCP segments in response to
//! explicit connection operations and incoming packets, and provides types for
//! serializing/deserializing IPv4/TCP headers.
//!
//! ### Unsupported Extensions
//!
//! TODO: Document missing extensions:
//!
//! - No congestion control algorithms (e.g., slow start, fast retransmit)
//! - No support for Selective Acknowledgment (SACK)
//! - No window scaling
//! - TCP Fast Open is not implemented
//! - No delayed acknowledgments
//!
//! ### Feature Flags
//!
//! This crate uses a set of feature flags to reduce the amount of compiled
//! code, including:
//!
//! - `default`: Enables none of the features listed below.
//! - `full`: Enables all features listed below.
//! - `trace`: Enables internal TCP execution tracing of the state machine and
//!   segment processing for debugging purposes.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

// TODO: Update lints after refactor.
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

// TODO: Implement limitations.
//
// - Handling of buffered application data (currently buffered, not drained)
// - No zero-window probing
// - No Initial Send Sequence Number (ISS) randomization

// Must be defined first!
#[macro_use]
pub(crate) mod macros;

pub mod error;
pub use error::{Error, HeaderError, ParseError, Result};

pub mod socket;
pub use socket::{Ipv4AddrParseError, SocketAddrV4, SocketV4};

pub mod protocol;
pub mod wire;
