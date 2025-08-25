//! Construction and serialization of TCP segments.

use std::io::Write;

use crate::Result;
use crate::protocol::headers::{Ipv4Header, TcpHeader};

/// Fully constructed TCP segment.
#[derive(Debug)]
pub struct TcpSegment {
    /// IPv4 header of the segment.
    pub ip: Ipv4Header,
    /// TCP header of the segment.
    pub tcp: TcpHeader,
    /// Payload of the segment.
    pub payload: Vec<u8>,
}

impl TcpSegment {
    /// Create a new TCP segment given the IPv4/TCP headers and payload.
    pub fn new(ip: Ipv4Header, tcp: TcpHeader, payload: &[u8]) -> Self {
        Self {
            ip,
            tcp,
            payload: payload.into(),
        }
    }

    /// Returns the memory representation of the TCP segment as a vector of
    /// bytes in big-endian (network) byte order.
    pub fn to_be_bytes(self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.ip.write(&mut buf)?;
        self.tcp.write(&mut buf)?;
        buf.write_all(&self.payload)?;

        Ok(buf)
    }
}
