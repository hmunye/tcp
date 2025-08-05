//! Simple internal logger for emitting severity-based messages.

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
pub fn log(level: Level, msg: impl std::fmt::Display) {
    match level {
        Level::Error => {
            eprintln!("\x1b[1;37m[{SOURCE}]\x1b[0m \x1b[31mERROR\x1b[0m: {msg}");
        }
        Level::Warn => {
            eprintln!("\x1b[1;37m[{SOURCE}]\x1b[0m \x1b[33mWARN \x1b[0m: {msg}");
        }
        Level::Info => {
            println!("\x1b[1;37m[{SOURCE}]\x1b[0m \x1b[32mINFO \x1b[0m: {msg}");
        }
        Level::Debug => {
            println!("\x1b[1;37m[{SOURCE}]\x1b[0m \x1b[34mDEBUG\x1b[0m: {msg}");
        }
    }
}
