//! Macros for logging TCP-related events in debug builds.

/// Prints an error-level log message to `stderr` (debug builds only).
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        eprintln!("[\x1b[1;31mERROR\x1b[0m] {}", format!($($arg)+));
    }};
}

/// Prints a warn-level log message to `stderr` (debug builds only).
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        eprintln!("[\x1b[1;33mWARN\x1b[0m] {}", format!($($arg)+));
    }};
}

/// Prints a debug-level log message to `stdout` (debug builds only).
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        println!("[\x1b[1;34mDEBUG\x1b[0m] {}", format!($($arg)+));
    }};
}

/// Prints an info-level log message to `stdout` (debug builds only).
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        println!("[\x1b[1;32mINFO\x1b[0m] {}", format!($($arg)+));
    }};
}
