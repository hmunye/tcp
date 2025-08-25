//! Representation for unique TCP connections using socket addresses.

use std::{fmt, io};

/// An IPv4 address and port number.
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

impl TryFrom<&str> for SocketAddr {
    type Error = io::Error;

    // TODO: provide a random port if `0` is parsed.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        fn invalid_format() -> io::Error {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 address format")
        }

        let mut parts = value.splitn(2, ':');
        let ip = parts.next();
        let port = parts.next();

        match (ip, port) {
            (Some(ip), Some(port)) => {
                let mut addr = [0u8; 4];
                let mut octets = ip.split('.');

                for octet in addr.iter_mut() {
                    *octet = octets
                        .next()
                        .ok_or_else(invalid_format)?
                        .parse::<u8>()
                        .map_err(|_| invalid_format())?;
                }

                if octets.next().is_some() {
                    return Err(invalid_format());
                }

                let port = port.parse::<u16>().map_err(|_| invalid_format())?;

                Ok(SocketAddr { addr, port })
            }
            _ => Err(invalid_format()),
        }
    }
}

/// Identification for a unique TCP connection, using the source and destination
/// socket addresses.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Socket {
    /// The source socket address (local IP and port).
    pub src: SocketAddr,
    /// The destination socket address (peer IP and port).
    pub dst: SocketAddr,
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
