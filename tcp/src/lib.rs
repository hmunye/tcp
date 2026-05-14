//! User-space implementation of the Transmission Control Protocol (TCP), based
//! primarily on [RFC 793].
//!
//! Implemented as a protocol engine: a state machine operating over IPv4-based
//! TCP segments that manages connection lifecycle, bidirectional data transfer,
//! termination/reset, serialization and deserialization of IPv4 headers, TCP
//! headers, and TCP segments, and zero-window probing.
//!
//! This crate is **not a socket library.** It performs no network I/O and
//! shares no state with the host operating system. Instead, it drives a TCP
//! state machine over raw byte slices, generating TCP segments in response to
//! explicit connection operations and incoming packets, and provides types for
//! serializing/deserializing IPv4/TCP headers.
//!
//! ### Unsupported Extensions
//!
//! #### Congestion Control Algorithms
//!
//! Mechanisms like slow start, congestion avoidance, and fast retransmit were
//! added to prevent network congestion collapse. They dynamically adjust the
//! sending rate based on detected packet loss and network conditions, ensuring
//! stable and efficient traffic flow.
//!
//! #### Selective Acknowledgment (SACK)
//!
//! SACK allows a receiver to acknowledge non-contiguous segments of data. This
//! reduces unnecessary retransmissions when some packets are lost, improving
//! throughput on lossy or high-latency connections.
//!
//! #### Window Scaling
//!
//! The original 16-bit TCP window limits the maximum buffer size to 65,535
//! bytes. Window scaling extends this limit, enabling large receive windows for
//! high-bandwidth, high-latency networks, which improves transfer efficiency.
//!
//! #### TCP Fast Open
//!
//! TCP Fast Open allows sending data during the initial handshake. This reduces
//! latency for repeated connections, particularly for short-lived transactions
//! like HTTP requests.
//!
//! #### Delayed Acknowledgments
//!
//! Delayed ACKs introduce a short wait before sending an acknowledgment. This
//! allows ACKs to be combined with outgoing data, reducing small packets and
//! improving network efficiency.
//!
//! #### TCP Timestamps / PAWS
//!
//! Timestamps provide more accurate round-trip time measurement and allow the
//! PAWS (Protection Against Wrapped Sequence numbers) mechanism to reject old
//! or duplicate segments, improving reliability over long-lived or high-speed
//! connections.
//!
//! #### Explicit Congestion Notification (ECN)
//!
//! ECN allows routers to mark packets instead of dropping them when congestion
//! occurs. TCP endpoints can then reduce sending rates proactively, improving
//! performance and avoiding packet loss under congestion.
//!
//! ### Feature Flags
//!
//! This crate uses a set of feature flags to reduce the amount of compiled
//! code, including:
//!
//! - `default`: Enables none of the features listed below.
//! - `full`: Enables all features listed below.
//! - `trace`: Enables internal TCP execution tracing of the state machine and
//!   segment processing for debugging purposes, printing to `stderr`.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2018_idioms)]
#![warn(missing_debug_implementations)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::use_self)]
#![allow(clippy::redundant_else)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::unused_self)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::single_match_else)]

// Must be defined first!
#[macro_use]
pub(crate) mod macros;

pub mod error;
pub use error::{Error, HeaderError, ParseError, Result};

pub mod socket;
pub use socket::{Ipv4AddrParseError, SocketAddrV4, SocketV4};

pub mod protocol;
pub mod wire;
