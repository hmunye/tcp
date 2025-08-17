//! Networking primitives for [TCP] over [IPv4].
//!
//! This module implements components for the Transmission Control Protocol over
//! IPv4, including IPv4/TCP header definitions, packet parsing/serialization,
//! TCP segment construction, and the protocol state machine.
//!
//! [TCP]:  https://www.rfc-editor.org/rfc/rfc793
//! [IPv4]: https://www.rfc-editor.org/rfc/rfc791

pub mod fsm;
pub mod headers;

pub mod socket;
pub use socket::{Socket, SocketAddr};

pub mod segment;
pub use segment::TcpSegment;
