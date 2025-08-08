//! TCP implementation in user-space, built for learning purposes, using the
//! TUN/TAP interface.
//!
//! Not suitable for production use.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "This crate is only compatible with Linux systems that support TUN/TAP devices and the epoll interface."
);

pub mod error;
pub mod log;
pub mod net;
pub mod tun_tap;

pub use error::{Error, HeaderError, ParseError, Result};
