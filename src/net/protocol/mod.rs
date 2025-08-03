//! Minimal implementation of the Transmission Control Protocol (TCP).
//!
//! This module defines the logic and state machine for the TCP protocol as
//! described in [RFC 793].
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

mod event_loop;
mod tcp;

pub use event_loop::packet_loop;
pub use tcp::*;
