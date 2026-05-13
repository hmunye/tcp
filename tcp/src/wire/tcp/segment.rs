use crate::wire::{Ipv4Header, TcpHeader};

/// TCP segment encapsulated within an IPv4 header.
#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub(crate) iph: Ipv4Header,
    pub(crate) tcph: TcpHeader,
    pub(crate) payload: Vec<u8>,
}

impl TcpSegment {
    /// Creates a new `TcpSegment` using an existing [`Ipv4Header`],
    /// [`TcpHeader`], and payload.
    #[inline]
    #[must_use]
    pub fn new(iph: Ipv4Header, tcph: TcpHeader, payload: &[u8]) -> Self {
        TcpSegment {
            iph,
            tcph,
            payload: payload.to_vec(),
        }
    }

    /// Returns the memory representation of the TCP segment as a `Vec` in
    /// big-endian (network) byte order.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcp::wire::{Ipv4Header, Protocol, TcpHeader, TcpSegment};
    ///
    /// let mut tcph = TcpHeader::new(41324, 80, 0, 65535);
    /// let payload = b"hello, world";
    ///
    /// let mut iph = Ipv4Header::new(
    ///     0,
    ///     [192, 168, 0, 1],
    ///     [192, 168, 0, 44],
    ///     (tcph.header_len() + payload.len()) as u16,
    ///     64,
    ///     Protocol::TCP,
    /// )
    /// .unwrap();
    ///
    /// iph.set_header_checksum();
    /// tcph.set_checksum(&iph, payload);
    ///
    /// let mut seg = TcpSegment::new(iph, tcph, payload);
    ///
    /// // Network-byte order representation of the TCP segment.
    /// let bytes = seg.to_bytes();
    /// ```
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(self.iph.header_len() + self.tcph.header_len() + self.payload.len());

        buf.extend(self.iph.to_bytes().as_slice());
        buf.extend(self.tcph.to_bytes().as_slice());
        buf.extend(&self.payload);

        buf
    }

    /// Returns a reference to the IPv4 header of the segment.
    #[inline]
    #[must_use]
    pub const fn iph(&self) -> &Ipv4Header {
        &self.iph
    }

    /// Returns a reference to the TCP header of the segment.
    #[inline]
    #[must_use]
    pub const fn tcph(&self) -> &TcpHeader {
        &self.tcph
    }

    /// Returns a reference to the payload of the segment.
    #[inline]
    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }
}
