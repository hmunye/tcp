//! TCP connection identifier based on IPv4 socket addresses.
//!
//! [`Socket`] represents the TCP 4-tuple (source and destination IP/port),
//! grouped into source and destination [`SocketAddr`]s.

use std::fmt;
use std::str::FromStr;

/// Error returned from parsing an invalid [`SocketAddr`].
#[derive(Debug)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv4 socket address")
    }
}

impl std::error::Error for AddrParseError {}

/// An IPv4 socket address (IP + port).
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SocketAddr {
    pub addr: [u8; 4],
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

impl FromStr for SocketAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, port) = s.split_once(':').ok_or(AddrParseError)?;

        let mut octets = [0u8; 4];
        let mut i = 0;

        for part in ip.split('.') {
            if i >= 4 {
                return Err(AddrParseError);
            }

            octets[i] = part.parse::<u8>().map_err(|_| AddrParseError)?;
            i += 1;
        }

        if i != 4 {
            return Err(AddrParseError);
        }

        let port = port.parse::<u16>().map_err(|_| AddrParseError)?;

        Ok(SocketAddr { addr: octets, port })
    }
}

impl From<([u8; 4], u16)> for SocketAddr {
    fn from(parts: ([u8; 4], u16)) -> Self {
        SocketAddr {
            addr: parts.0,
            port: parts.1,
        }
    }
}

/// Unique identifier for a TCP connection defined by its source and destination
/// [`SocketAddr`]s.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Socket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_display_fmt() {
        let addr: SocketAddr = ([127, 0, 0, 1], 8008).into();
        assert_eq!("127.0.0.1:8008", format!("{addr}"));

        let addr: SocketAddr = "127.0.0.1:4007"
            .parse()
            .expect("should be a valid IPv4 socket address");
        assert_eq!("127.0.0.1:4007", format!("{addr}"));
    }

    #[test]
    fn test_addr_parse_valid() {
        let cases = [
            ("0.0.0.0:0", [0, 0, 0, 0], 0),
            ("255.255.255.255:65535", [255, 255, 255, 255], 65535),
            ("192.168.1.1:80", [192, 168, 1, 1], 80),
            ("127.0.0.1:8080", [127, 0, 0, 1], 8080),
        ];

        for (input, expected_ip, expected_port) in cases {
            let addr: SocketAddr = input
                .parse()
                .expect("should be a valid IPv4 socket address");
            assert_eq!(addr.addr, expected_ip);
            assert_eq!(addr.port, expected_port);
            assert_eq!(format!("{addr}"), input);
        }
    }

    #[test]
    fn test_addr_parse_invalid() {
        let cases = [
            "",
            "127.0.0.1",
            "127.0.0.1:",
            ":8080",
            "256.0.0.1:80",
            "127.0.0:80",
            "127.0.0.0.1:80",
            "127.0.0.1:65536",
            "abc.def.ghi.jkl:80",
            "127.0.0.1:port",
            "127..0.1:80",
        ];

        for input in cases {
            assert!(
                input.parse::<SocketAddr>().is_err(),
                "'{input}' should not be parsed as a valid IPv4 socket address"
            );
        }
    }
}
