//! Networking primitives for TCP over IPv4.
//!
//! This module implements core components for the Transmission Control Protocol
//! (TCP) over IPv4, including TCP and IPv4 header definitions, protocol state
//! management, and event loop for processing raw packet I/O, timers, and
//! signals.

pub mod event_loop;
