//! Representing unique TCP connections through socket addresses.

use std::fmt;

/// An IPv4 address and a port number.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct SocketAddr {
    /// IPv4 address.
    pub addr: [u8; 4],
    /// Port number.
    pub port: u16,
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.port,
        )
    }
}

/// Unique TCP connection, identified by both the source and destination
/// socket addresses.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Socket {
    /// The source socket address (local IP and port).
    pub src: SocketAddr,
    /// The destination socket address (remote IP and port).
    pub dst: SocketAddr,
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
