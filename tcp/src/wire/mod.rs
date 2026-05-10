//! Wire-format types for IPv4-based TCP packet handling.
//!
//! Provides types and utilities for constructing, parsing, and serializing IPv4
//! headers and TCP headers/segments.

mod ipv4;
pub use ipv4::{Ipv4Header, Ipv4Options, Protocol};

mod tcp;
pub use tcp::{TcpHeader, TcpOptions, TcpSegment};

mod fixed_buf;
pub use fixed_buf::FixedBuf;
