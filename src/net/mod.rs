//! Minimal networking primitives for TCP communication.
//!
//! This module provides networking functionality for the Transmission Control
//! Protocol.

mod headers;
mod proto;

pub use headers::*;
pub use proto::*;
