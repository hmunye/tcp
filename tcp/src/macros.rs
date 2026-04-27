#![allow(unused_macros)]

macro_rules! cfg_trace {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "trace")]
            $item
        )*
    }
}

cfg_trace! {
    const ANSI_RESET: &str = "\x1b[0m";
    const ANSI_RED_BOLD: &str = "\x1b[1;31m";
    const ANSI_YELLOW_BOLD: &str = "\x1b[1;33m";
    const ANSI_BLUE_BOLD: &str = "\x1b[1;34m";
    const ANSI_GREEN_BOLD: &str = "\x1b[1;32m";
}

macro_rules! tcp_debug {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        eprintln!(
            "[{}DEBUG{}]: {}",
            ANSI_BLUE_BOLD,
            ANSI_RESET,
            format!($($tt)+)
        );
    }};
}

macro_rules! tcp_info {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        eprintln!(
            "[{}INFO{}]:  {}",
            ANSI_GREEN_BOLD,
            ANSI_RESET,
            format!($($tt)+)
        );
    }};
}

macro_rules! tcp_warn {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        eprintln!(
            "[{}WARN{}]:  {}",
            ANSI_YELLOW_BOLD,
            ANSI_RESET,
            format!($($tt)+)
        );
    }};
}

macro_rules! tcp_error {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        eprintln!(
            "[{}ERROR{}]: {}",
            ANSI_RED_BOLD,
            ANSI_RESET,
            format!($($tt)+)
        );
    }};
}
