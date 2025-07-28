//! Minimal implementation of the Transmission Control Protocol (TCP).

use std::net::Ipv4Addr;

use crate::info;
use crate::parse::{IPv4Header, TCPHeader};

/// Representation of a unique TCP connection.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Socket {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

impl Socket {
    /// Creates a new [Socket] using provided (source address, source port) and
    /// (destination address, destination port).
    pub fn new(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16)) -> Self {
        Self { src, dst }
    }
}

/// Transmission Control Block
///
/// Stores information about the state and control data for managing a TCP
/// connection.
#[derive(Debug, Default)]
pub struct TCB {}

impl TCB {
    /// Handles an incoming TCP segment.
    pub fn on_packet(&mut self, iph: &IPv4Header, tcph: &TCPHeader, payload: &[u8]) {
        info!(
            "ipv4 datagram | src: {:?}, dst: {:?}, chksum: 0x{:04x} (valid: {}), payload: {} bytes",
            iph.src(),
            iph.dst(),
            iph.header_checksum(),
            iph.compute_header_checksum() == iph.header_checksum(),
            iph.payload_len().unwrap_or(u16::MAX)
        );

        info!(
            "tcp segment | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), mss: {:?}, payload: {} bytes",
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
            tcph.compute_checksum(iph, payload) == tcph.checksum(),
            tcph.options().mss(),
            payload.len()
        );

        info!("payload bytes: {:x?}", payload);
    }
}
