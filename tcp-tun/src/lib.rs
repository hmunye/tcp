//! TCP implementation in user-space, built for learning purposes, using the
//! TUN/TAP interface.
//!
//! Not suitable for production use.

#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "This crate is only compatible with Linux systems that support TUN/TAP devices and epoll."
);

pub mod net;
pub mod tun_tap;

/// Creates a [tcp_core::Error::Io] with a message prefixed to the `errno` value.
#[macro_export]
macro_rules! errno {
    ($($arg:tt)+) => {{
        let errno = ::std::io::Error::last_os_error();
        let prefix = format!($($arg)+);

        let msg = format!("{prefix}: {errno}");

        tcp_core::Error::Io(::std::io::Error::new(errno.kind(), msg))
    }};
}
