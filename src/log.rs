//! Logging utility for basic message output with severity levels.

use std::ffi::CStr;
use std::{fmt, io, ptr};

const SOURCE: &str = "tcp";

/// Represents the severity level of a log message.
#[derive(Debug)]
pub enum Level {
    /// Designates very serious errors.
    Error,
    /// Designates hazardous situations.
    Warn,
    /// Designates useful information.
    Info,
    /// Designates lower priority information.
    Debug,
}

/// Logs a message at the [Level::Error] level.
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {{
        $crate::log::log($crate::log::Level::Error, format!($($arg)+));
    }};
}

/// Logs a message at the [Level::Warn] level.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {{
        $crate::log::log($crate::log::Level::Warn, format!($($arg)+));
    }};
}

/// Logs a message at the [Level::Info] level.
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {{
        $crate::log::log($crate::log::Level::Info, format!($($arg)+));
    }};
}

/// Logs a message at the [Level::Debug] level.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {{
        $crate::log::log($crate::log::Level::Debug, format!($($arg)+));
    }};
}

/// Logs a message with the given severity level.
///
/// - Messages with level [Level::Info] and [Level::Debug] are printed to stdout.
/// - Messages with level [Level::Warn] and [Level::Error] are printed to stderr.
///
/// # Panics
///
/// This function will terminate the process if the current timestamp could not
/// be determined.
pub fn log(level: Level, msg: impl fmt::Display) {
    let mut buf = [0u8; 20]; // "YYYY-MM-DD HH:MM:SS"

    unsafe {
        // time() returns the time as the number of seconds of type `time_t`
        // since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
        let now = libc::time(ptr::null_mut());

        // localtime() converts the time provided of type `time_t` to broken-down
        // time representation.
        let tm_ptr = libc::localtime(&now);
        if tm_ptr.is_null() {
            panic!("{}", io::Error::last_os_error());
        }

        // strftime() formats the broken-down time of type `tm` according
        // to the format specification string and places the result in `buf`.
        //
        // If the length of `buf` (including the terminating null byte)
        // would exceed `buf.len()`, then strftime() returns 0, and the contents
        // of `buf` are undefined.
        if libc::strftime(
            buf.as_mut_ptr() as *mut i8,
            buf.len(),
            c"%F %T".as_ptr(),
            tm_ptr,
        ) == 0
        {
            panic!("strftime function returned 0");
        }
    }

    // SAFETY: `buf` is zero-initialized and `strftime()` writes a null terminator
    // on success.
    let timestamp = unsafe { CStr::from_bytes_with_nul_unchecked(&buf) }
        .to_str()
        .unwrap_or("UNKN");

    match level {
        Level::Error => {
            eprintln!(
                "\x1b[2m[{timestamp}]\x1b[0m \x1b[1;37m[{SOURCE}]\x1b[0m \x1b[31mERROR\x1b[0m: {msg}"
            );
        }
        Level::Warn => {
            eprintln!(
                "\x1b[2m[{timestamp}]\x1b[0m \x1b[1;37m[{SOURCE}]\x1b[0m \x1b[33mWARN \x1b[0m: {msg}"
            );
        }
        Level::Info => {
            println!(
                "\x1b[2m[{timestamp}]\x1b[0m \x1b[1;37m[{SOURCE}]\x1b[0m \x1b[32mINFO \x1b[0m: {msg}"
            );
        }
        Level::Debug => {
            println!(
                "\x1b[2m[{timestamp}]\x1b[0m \x1b[1;37m[{SOURCE}]\x1b[0m \x1b[34mDEBUG \x1b[0m: {msg}"
            );
        }
    }
}
