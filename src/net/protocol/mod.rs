//! Implementation of the Transmission Control Protocol (TCP) as defined in
//! [RFC 793].
//!
//! This module implements the event loop and finite state machine for managing
//! the TCP protocol.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

pub mod event_loop;
pub mod fsm;
