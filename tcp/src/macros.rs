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

macro_rules! tcp_log_segment {
    ($iph:expr, $tcph:expr, $payload:expr) => {
        #[cfg(feature = "trace")]
        {
            let iph = $iph;
            let tcph = $tcph;
            let payload = $payload;

            tcp_debug!(
                "received ipv4 datagram | version: {}, ihl: {}, tos: {}, total_len: {}, id: {}, DF: {}, MF: {}, frag_offset: {}, ttl: {}, protocol: {:?}, chksum: 0x{:04x} (valid: {}), src: {:?}, dst: {:?}",
                iph.version(),
                iph.ihl(),
                iph.tos(),
                iph.total_length(),
                iph.id(),
                iph.dont_fragment(),
                iph.more_fragments(),
                iph.fragment_offset(),
                iph.ttl(),
                iph.protocol(),
                iph.header_checksum(),
                iph.is_valid_checksum(),
                iph.src_addr(),
                iph.dst_addr(),
            );

            tcp_debug!(
                "received tcp segment   | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), mss: {:?}",
                tcph.src_port(),
                tcph.dst_port(),
                tcph.seq_number(),
                tcph.ack_number(),
                tcph.data_offset(),
                tcph.urg(),
                tcph.ack(),
                tcph.psh(),
                tcph.rst(),
                tcph.syn(),
                tcph.fin(),
                tcph.window(),
                tcph.checksum(),
                tcph.is_valid_checksum(iph, payload),
                tcph.options().mss(),
            );

            tcp_debug!(
                "received {} bytes of payload: {:x?}",
                payload.len(),
                payload
            );
        }
    }
}
