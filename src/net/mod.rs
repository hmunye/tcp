//! Networking primitives for TCP communication.
//!
//! This module provides networking functionality for the Transmission Control
//! Protocol.

mod headers;
mod protocol;

pub use headers::*;
pub use protocol::*;
