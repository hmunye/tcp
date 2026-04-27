#![allow(unused_macros)]

macro_rules! cfg_trace {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "trace")]
            $item
        )*
    }
}

macro_rules! tcp_debug {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        // blue-bold
        eprintln!(
            "[\x1b[1;34mDEBUG\x1b[0m]: {}",
            format!($($tt)+)
        );
    }};
}

macro_rules! tcp_info {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        // green-bold
        eprintln!(
            "[\x1b[1;32mINFO\x1b[0m]:  {}",
            format!($($tt)+)
        );
    }};
}

macro_rules! tcp_warn {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        // yellow-bold
        eprintln!(
            "[\x1b[1;33mWARN\x1b[0m]:  {}",
            format!($($tt)+)
        );
    }};
}

macro_rules! tcp_error {
    ($($tt:tt)+) => {{
        #[cfg(feature = "trace")]
        // red-bold
        eprintln!(
            "[\x1b[1;31mERROR\x1b[0m]: {}",
            format!($($tt)+)
        );
    }};
}
