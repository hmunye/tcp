//! Minimal networking primitives for TCP communication.
//!
//! This module provides networking functionality for the Transmission Control
//! Protocol, as well as types for TCP and IP headers.

mod parse;
mod protocol;

pub use parse::*;
pub use protocol::*;
