//! Minimal implementation of the Transmission Control Protocol (TCP).
//!
//! This module defines the event loop and finite state machine needed for the
//! TCP protocol.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

mod event_loop;
mod fsm;

pub use event_loop::packet_loop;
pub use fsm::*;
