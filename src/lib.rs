//! TCP implementation in user-space designed for learning purposes.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

// [TUN/TAP](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
//
// Currently driver has been written for 3 Unices:
//
// - Linux kernels 2.2.x, 2.4.x
// - FreeBSD 3.x, 4.x, 5.x
// - Solaris 2.6, 7.0, 8.0
//
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "solaris")))]
compile_error!(
    "This crate only supports Linux, FreeBSD, or Solaris with the TUN/TAP device driver."
);

pub mod tun_tap;

/// Outputs a formatted error message to standard error.
pub fn log_err<T: std::fmt::Display>(msg: T) {
    eprintln!("\x1b[1mtcp\x1b[0m: \x1b[1;91merror\x1b[0m: {msg}");
}
