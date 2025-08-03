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
    let mut buf = [0u8; 20]; // "YYYY-MM-DD HH:MM:SS\0"

    unsafe {
        let now = libc::time(ptr::null_mut());
        if now == -1 {
            panic!("{}", io::Error::last_os_error());
        }

        let tm_ptr = libc::localtime(&now);
        if tm_ptr.is_null() {
            panic!("{}", io::Error::last_os_error());
        }

        // Note:
        //
        // The return value 0 does not necessarily indicate an error. For
        // example, in many locales %p yields an empty string. An empty format
        // string will likewise yield an empty string.
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

    // SAFETY: `buf` is zero-initialized and `strftime()` writes a null
    // terminator on success.
    let timestamp = unsafe { CStr::from_bytes_with_nul_unchecked(&buf) }
        .to_str()
        .unwrap_or("N/A");

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
