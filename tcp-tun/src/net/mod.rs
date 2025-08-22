//! Networking interface for TCP over IPv4.
//!
//! This module provides an event loop for processing raw packet I/O, timers,
//! and OS signals, a [Manager] for facilitating user-space TCP, and
//! [TcpListener] and [TcpStream] for functional communication over TCP.

pub mod event_loop;
pub use event_loop::event_loop;

pub mod manager;
