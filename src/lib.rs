//! TCP implementation in user-space designed for learning purposes.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

// [TUN/TAP](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "solaris")))]
compile_error!(
    "This crate only supports Unix-like operating systems with TUN/TAP device driver support."
);

pub mod log;
pub mod net;
pub mod tun_tap;
