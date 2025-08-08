//! Networking primitives for TCP over IPv4.
//!
//! This module implements core components for the Transmission Control Protocol
//! (TCP) over IPv4, including TCP and IPv4 header definitions, protocol state
//! management, and event loop for packet I/O.

pub mod headers;
pub mod protocol;
