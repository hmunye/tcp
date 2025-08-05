//! Networking primitives for TCP communication.
//!
//! This module provides networking functionality for the Transmission Control
//! Protocol over IPv4. It includes core components such as TCP and IPv4 header
//! definitions, protocol state management, and utilities for constructing and
//! parsing TCP packets.

mod headers;
mod protocol;

pub use headers::*;
pub use protocol::*;
