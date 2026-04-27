//! Linux-only crate enabling TUN/TAP networking for user-space TCP via
//! [tcp], exposing a [std::net]-like API for TCP communication.
//!
//! [tcp]: https://github.com/hmunye/tcp/tree/main/tcp
//! [std::net]: https://doc.rust-lang.org/std/net/index.html

#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "This crate is only compatible with Linux systems that support TUN/TAP devices and epoll."
);

pub mod net;

pub(crate) mod event_loop;
pub(crate) mod tun;

/// Creates a [tcp::Error::Io] with a message prefixed to the `errno` value.
macro_rules! errno {
    ($($arg:tt)+) => {{
        let errno = ::std::io::Error::last_os_error();
        let prefix = format!($($arg)+);
        tcp::Error::Io(::std::io::Error::new(errno.kind(), format!("{prefix}: {errno}")))
    }};
}
pub(crate) use errno;
