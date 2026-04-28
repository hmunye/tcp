//! Low-level utilities for handling IPv4/TCP headers.
//!
//! Provides types for constructing, parsing, and serializing/deserializing IPv4
//! and TCP headers. Focuses on the *wire format*, i.e., the byte-level
//! representation transmitted over the network.

mod ipv4;
pub use ipv4::{Ipv4Header, Protocol};

mod tcp;
pub use tcp::TcpHeader;
