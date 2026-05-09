//! TCP connection identifiers over IPv4.
//!
//! [`SocketAddrV4`] represents a single IPv4 endpoint (IP and port), while
//! [`SocketV4`] combines source and destination endpoints to form the standard
//! TCP 4-tuple.

use std::fmt;
use std::str::FromStr;

/// Error returned from parsing an invalid [`SocketAddrV4`].
#[derive(Debug)]
pub struct Ipv4AddrParseError;

impl fmt::Display for Ipv4AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv4 socket address")
    }
}

impl std::error::Error for Ipv4AddrParseError {}

/// IPv4 socket address (IP + port).
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SocketAddrV4 {
    pub addr: [u8; 4],
    pub port: u16,
}

impl fmt::Display for SocketAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.port,
        )
    }
}

impl FromStr for SocketAddrV4 {
    type Err = Ipv4AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, port) = s.split_once(':').ok_or(Ipv4AddrParseError)?;

        let mut octets = [0u8; 4];
        let mut i = 0;

        for part in ip.split('.') {
            if i >= 4 {
                return Err(Ipv4AddrParseError);
            }

            octets[i] = part.parse::<u8>().map_err(|_| Ipv4AddrParseError)?;
            i += 1;
        }

        if i != 4 {
            return Err(Ipv4AddrParseError);
        }

        let port = port.parse::<u16>().map_err(|_| Ipv4AddrParseError)?;

        Ok(SocketAddrV4 { addr: octets, port })
    }
}

impl From<([u8; 4], u16)> for SocketAddrV4 {
    fn from(parts: ([u8; 4], u16)) -> Self {
        SocketAddrV4 {
            addr: parts.0,
            port: parts.1,
        }
    }
}

/// Unique identifier for a TCP connection defined by its source and destination
/// [`SocketAddrV4`]s.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SocketV4 {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
}

impl fmt::Display for SocketV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_display_fmt() {
        let addr: SocketAddrV4 = ([127, 0, 0, 1], 8008).into();
        assert_eq!("127.0.0.1:8008", format!("{addr}"));

        let addr: SocketAddrV4 = "127.0.0.1:4007"
            .parse()
            .expect("should be a valid IPv4 socket address");
        assert_eq!("127.0.0.1:4007", format!("{addr}"));
    }

    #[test]
    fn test_socket_display_fmt() {
        let src: SocketAddrV4 = ([127, 0, 0, 1], 43221).into();
        let dst: SocketAddrV4 = ([127, 0, 0, 1], 443).into();
        let sock = SocketV4 { src, dst };

        assert_eq!("127.0.0.1:43221 -> 127.0.0.1:443", format!("{sock}"));
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
            let addr: SocketAddrV4 = input
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
                input.parse::<SocketAddrV4>().is_err(),
                "'{input}' should not be parsed as a valid IPv4 socket address"
            );
        }
    }
}
