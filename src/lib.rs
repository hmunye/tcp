//! TCP implementation in user-space designed for learning purposes, using the
//! TUN/TAP interface.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "This crate only supports Linux operating systems with TUN/TAP device support and epoll."
);

pub mod log;
pub mod net;
pub mod tun_tap;
