//! TCP protocol engine for IPv4, based on [RFC 793].
//!
//! Manages the full connection lifecycle, reliable data transfer, and network
//! constraints unrelated to direct I/O. Coordinates state machine transitions,
//! per-connection transmission control blocks, segment serialization,
//! retransmission scheduling, and receive buffering to deliver an in-order byte
//! stream.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

mod tcb;
pub use tcb::{ConnectionState, TCB};

pub(crate) mod segment_builders;

mod retransmission;
pub(crate) use retransmission::RetransmissionEntry;

/// Maximum segment lifetime (`MSL`) in seconds.
///
/// Defined as the maximum time a segment can exist within the network before
/// being discarded.
pub const MSL: u64 = 120;
