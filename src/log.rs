//! A simple logging utility for emitting messages based on severity levels.

use std::time;

/// Source of the log message.
const SOURCE: &str = "tcp";

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

/// Severity levels for log messages.
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

/// Logs a message with the specified severity level.
///
/// - [Level::Info] and [Level::Debug] messages are printed to `stdout`.
/// - [Level::Warn] and [Level::Error] messages are printed to `stderr`.
///
/// The log message will include a timestamp, severity level, and the source of
/// the log (`tcp`).
pub fn log(level: Level, msg: impl std::fmt::Display) {
    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let time = now as i64;
    let tm = unsafe { libc::localtime(&time) };

    let timestamp = if tm.is_null() {
        "UNKNOWN".to_string()
    } else {
        let tm = unsafe { *tm };
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    };

    match level {
        Level::Error => {
            eprintln!(
                "[\x1b[1;37m{timestamp}\x1b[0m] \x1b[1;31mERROR\x1b[0m [\x1b[1;37m{SOURCE}\x1b[0m] {msg}"
            );
        }
        Level::Warn => {
            eprintln!(
                "[\x1b[1;37m{timestamp}\x1b[0m] \x1b[1;33mWARN \x1b[0m [\x1b[1;37m{SOURCE}\x1b[0m] {msg}"
            );
        }
        Level::Info => {
            println!(
                "[\x1b[1;37m{timestamp}\x1b[0m] \x1b[1;32mINFO \x1b[0m [\x1b[1;37m{SOURCE}\x1b[0m] {msg}"
            );
        }
        Level::Debug => {
            println!(
                "[\x1b[1;37m{timestamp}\x1b[0m] \x1b[1;34mDEBUG\x1b[0m [\x1b[1;37m{SOURCE}\x1b[0m] {msg}"
            );
        }
    }
}
