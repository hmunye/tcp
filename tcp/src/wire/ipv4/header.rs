use crate::wire::{FixedBuf, Ipv4Options, Protocol};
use crate::{Error, HeaderError, ParseError, Result};

/// IPv4 Datagram Header [(RFC 791, Section 3.1)].
///
/// ```text
///  0                   1                   2                   3   
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |Type of Service|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [(RFC 791, Section 3.1)]: https://www.rfc-editor.org/rfc/rfc791#section-3.1
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    /// `Version` of the IP header (4 for IPv4).
    ///
    /// `Internet Header Length` (IHL), in 32-bit words. Minimum valid header is
    /// 5 words (20 bytes).
    version_ihl: u8,
    /// `Type of Service` indicates desired quality of service.
    ///
    /// Used to guide selection of service parameters when transmitting a
    /// datagram. Several networks offer service precedence, treating
    /// high-precedence traffic as more important. The main tradeoff is among
    /// low-delay, high-reliability, and high-throughput.
    ///
    /// ```text
    /// Bits 0-2:  Precedence.
    /// Bit    3:  0 = Normal Delay,      1 = Low Delay.
    /// Bits   4:  0 = Normal Throughput, 1 = High Throughput.
    /// Bits   5:  0 = Normal Reliability, 1 = High Reliability.
    /// Bit  6-7:  Reserved for Future Use.
    ///
    ///    0     1     2     3     4     5     6     7
    /// +-----+-----+-----+-----+-----+-----+-----+-----+
    /// |                 |     |     |     |     |     |
    /// |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
    /// |                 |     |     |     |     |     |
    /// +-----+-----+-----+-----+-----+-----+-----+-----+
    ///
    ///   Precedence
    ///
    ///     111 - Network Control
    ///     110 - Internetwork Control
    ///     101 - CRITIC/ECP
    ///     100 - Flash Override
    ///     011 - Flash
    ///     010 - Immediate
    ///     001 - Priority
    ///     000 - Routine
    /// ```
    tos: u8,
    /// `Total length` of the datagram in bytes, including header and payload.
    /// Maximum is 65,535 bytes (`u16::MAX`); all hosts must accept at least 576
    /// bytes.
    total_length: u16,
    /// Identifying value assigned by the sender to aid in assembling the
    /// fragments of a datagram.
    id: u16,
    /// Various Control Flags:
    ///
    /// ```text
    /// Bit 0: reserved, must be zero
    /// Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
    /// Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
    ///
    ///     0   1   2
    ///   +---+---+---+
    ///   |   | D | M |
    ///   | 0 | F | F |
    ///   +---+---+---+
    /// ```
    ///
    /// `Fragment Offset` indicates where in the datagram this fragment belongs,
    /// measured in 8-octet units (64-bits).
    flags_and_offset: u16,
    /// Indicates the maximum time the datagram is allowed to exist in the
    /// network (measured in units of seconds), decremented by each module. A
    /// value of zero means the datagram must be discarded.
    ttl: u8,
    /// Indicates the next level protocol used in the data portion of the
    /// internet datagram.
    protocol: Protocol,
    /// A checksum on the header only. Since some header fields change (e.g.,
    /// `ttl`), this is recomputed and verified at each point that the internet
    /// header is processed.
    header_checksum: u16,
    /// The source address.
    src_addr: [u8; 4],
    /// The destination address.
    dst_addr: [u8; 4],
    /// Options that may occupy space at the end of the IPv4 header and are a
    /// multiple of 8-bits in length.
    ///
    /// Available options, as defined in RFC 791:
    ///
    /// ```text
    /// CLASS NUMBER LENGTH DESCRIPTION
    /// ----- ------ ------ -----------
    ///   0     0      -    End of Option list.  This option occupies only
    ///                     1 octet; it has no length octet.
    ///   0     1      -    No Operation.  This option occupies only 1
    ///                     octet; it has no length octet.
    ///   0     2     11    Security.  Used to carry Security,
    ///                     Compartmentation, User Group (TCC), and
    ///                     Handling Restriction Codes compatible with DOD
    ///                     requirements.
    ///   0     3     var.  Loose Source Routing.  Used to route the
    ///                     internet datagram based on information
    ///                     supplied by the source.
    ///   0     9     var.  Strict Source Routing.  Used to route the
    ///                     internet datagram based on information
    ///                     supplied by the source.
    ///   0     7     var.  Record Route.  Used to trace the route an
    ///                     internet datagram takes.
    ///   0     8      4    Stream ID.  Used to carry the stream
    ///                     identifier.
    ///   2     4     var.  Internet Timestamp.
    /// ```
    options: Ipv4Options,
}

impl Ipv4Header {
    /// Minimum allowed length for an IPv4 header in bytes.
    pub const MIN_HEADER_LEN: usize = (Self::MIN_IHL << 2) as usize;

    /// Maximum allowed length for an IPv4 header in bytes.
    ///
    /// `IHL` has a minimum value of 5 words (20 bytes).
    ///
    /// Given its 4-bit representation:
    ///
    /// ```text
    ///     1001
    /// ```
    /// the maximum `IHL` is:
    ///
    /// ```text
    ///     1111
    /// ```
    ///
    /// An `IHL` of 15 words corresponds to 60 bytes.
    pub const MAX_HEADER_LEN: usize = (Self::MAX_IHL << 2) as usize;

    /// Minimum allowed `IHL` for an IPv4 header.
    const MIN_IHL: u8 = 5;

    /// Maximum allowed `IHL` for an IPv4 header.
    const MAX_IHL: u8 = 15;

    /// Creates a new `Ipv4Header` with the given id, source and destination
    /// addresses, payload length, `TTL`, and protocol. Other fields are set to
    /// their _defaults_.
    ///
    /// # Errors
    ///
    /// Returns an error if `payload_len` exceeds the maximum allowed payload
    /// length.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcp::wire::{Protocol, Ipv4Header};
    ///
    /// let iph = Ipv4Header::new(
    ///     0,
    ///     [192, 168, 0, 1],
    ///     [192, 168, 0, 44],
    ///     0,
    ///     64,
    ///     Protocol::TCP,
    /// )
    /// .unwrap();
    /// ```
    #[inline]
    pub fn new(
        id: u16,
        src: [u8; 4],
        dst: [u8; 4],
        payload_len: u16,
        ttl: u8,
        protocol: Protocol,
    ) -> Result<Self> {
        let mut header = Ipv4Header {
            // Version = 4, IHL = 5
            version_ihl: 0b0100_0101,
            tos: 0,
            total_length: 0,
            id,
            #[allow(clippy::unusual_byte_groupings)]
            //                       Fragment Off.
            //                   D|M +-----------+
            //                   F|F |           |
            flags_and_offset: 0b01_0_0000000000000,
            ttl,
            protocol,
            header_checksum: 0,
            src_addr: src,
            dst_addr: dst,
            options: Ipv4Options::new()
        };

        header.total_length = header.compute_total_length(payload_len)?;

        Ok(header)
    }

    /// Returns the IPv4 `Version` field.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Returns the IPv4 `IHL` field.
    ///
    /// To get the header length in bytes, use [`Ipv4Header::header_len`].
    #[inline]
    #[must_use]
    pub const fn ihl(&self) -> u8 {
        self.version_ihl & 0xF
    }

    /// Returns the IPv4 `Type of Service` field.
    #[inline]
    #[must_use]
    pub const fn tos(&self) -> u8 {
        self.tos
    }

    /// Returns the IPv4 `Total Length` field.
    #[inline]
    #[must_use]
    pub const fn total_length(&self) -> u16 {
        self.total_length
    }

    /// Returns the IPv4 `Identification` field.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Returns `true` if the `DF` (Don't Fragment) flag is set.
    #[inline]
    #[must_use]
    pub const fn dont_fragment(&self) -> bool {
        (self.flags_and_offset >> 14) & 1 == 1
    }

    /// Sets the `DF` (Don't Fragment) flag.
    #[inline]
    pub const fn set_dont_fragment(&mut self) {
        self.flags_and_offset |= 1 << 14;
    }

    /// Returns `true` if the `MF` (More Fragments) flag is set.
    #[inline]
    #[must_use]
    pub const fn more_fragments(&self) -> bool {
        (self.flags_and_offset >> 13) & 1 == 1
    }

    /// Sets the `MF` (More Fragment) flag.
    #[inline]
    pub const fn set_more_fragments(&mut self) {
        self.flags_and_offset |= 1 << 13;
    }

    /// Returns the IPv4 `Fragment Offset` field.
    #[inline]
    #[must_use]
    pub const fn fragment_offset(&self) -> u16 {
        self.flags_and_offset & 0x1FFF
    }

    /// Returns the IPv4 `Time to Live` field.
    #[inline]
    #[must_use]
    pub const fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Returns the IPv4 `Protocol` field.
    #[inline]
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the IPv4 `Header Checksum` field.
    #[inline]
    #[must_use]
    pub const fn header_checksum(&self) -> u16 {
        self.header_checksum
    }

    /// Sets the IPv4 `Header Checksum` field.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcp::wire::{Protocol, Ipv4Header};
    ///
    /// let mut iph = Ipv4Header::new(
    ///     0,
    ///     [192, 168, 0, 1],
    ///     [192, 168, 0, 44],
    ///     0,
    ///     64,
    ///     Protocol::TCP,
    /// )
    /// .unwrap();
    ///
    /// // Set initial header checksum.
    /// iph.set_header_checksum();
    /// assert!(iph.is_valid_checksum());
    ///
    /// // Invalidate header checksum.
    /// iph.set_payload_len(255).unwrap();
    /// assert!(!iph.is_valid_checksum());
    ///
    /// iph.set_header_checksum();
    /// assert!(iph.is_valid_checksum());
    /// ```
    #[inline]
    pub fn set_header_checksum(&mut self) {
        self.header_checksum = self.compute_header_checksum();
    }

    /// Returns `true` if the IPv4 `Header Checksum` field is valid.
    #[inline]
    #[must_use]
    pub fn is_valid_checksum(&self) -> bool {
        self.header_checksum == self.compute_header_checksum()
    }

    /// Returns the IPv4 `Source Address` field.
    #[inline]
    #[must_use]
    pub const fn src_addr(&self) -> [u8; 4] {
        self.src_addr
    }

    /// Returns the IPv4 `Destination Address` field.
    #[inline]
    #[must_use]
    pub const fn dst_addr(&self) -> [u8; 4] {
        self.dst_addr
    }

    /// Returns a reference to the `Ipv4Options`.
    #[inline]
    #[must_use]
    pub const fn options(&self) -> &Ipv4Options {
        &self.options
    }

    /// Returns the payload length (excluding header).
    #[inline]
    #[must_use]
    pub const fn payload_len(&self) -> u16 {
        self.total_length - self.header_len() as u16
    }

    /// Sets the IPv4 `Total Length` field given a payload length.
    ///
    /// # Errors
    ///
    /// Returns an error if `payload_len` exceeds the maximum allowed payload
    /// length.
    #[inline]
    pub fn set_payload_len(&mut self, payload_len: u16) -> Result<()> {
        self.total_length = self.compute_total_length(payload_len)?;
        Ok(())
    }

    /// Returns the length of the header in bytes (including options).
    #[inline]
    #[must_use]
    pub const fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN + self.options.len()
    }

    /// Returns the memory representation of the IPv4 header as a [`FixedBuf`]
    /// in big-endian (network) byte order.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcp::wire::{Protocol, Ipv4Header};
    ///
    /// let mut iph = Ipv4Header::new(
    ///     0,
    ///     [192, 168, 0, 1],
    ///     [192, 168, 0, 44],
    ///     0,
    ///     64,
    ///     Protocol::TCP,
    /// )
    /// .unwrap();
    /// let buf = iph.to_bytes();
    ///
    /// // Network-byte order representation of the IPv4 header.
    /// let bytes = buf.as_slice();
    /// ```
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> FixedBuf<{ Self::MAX_HEADER_LEN }> {
        let mut buf: FixedBuf<{ Self::MAX_HEADER_LEN }> = FixedBuf::new();

        buf.append(&[self.version_ihl, self.tos]);
        buf.append(&self.total_length.to_be_bytes());
        buf.append(&self.id.to_be_bytes());
        buf.append(&self.flags_and_offset.to_be_bytes());
        buf.append(&[self.ttl, self.protocol.into()]);
        buf.append(&self.header_checksum.to_be_bytes());
        buf.append(&self.src_addr);
        buf.append(&self.dst_addr);
        buf.append(self.options().as_slice());

        buf
    }

    /// Parses an `Ipv4Header` from the given reader.
    ///
    /// # Errors
    ///
    /// Returns any encountered I/O error or an error if the available bytes are
    /// insufficient or malformed to form a valid `Ipv4Header`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use tcp::wire::Ipv4Header;
    ///
    /// // Minimal IPv4 header bytes (no options).
    /// let data: [u8; 20] = [
    ///     0x45, 0x00, 0x00, 0x28,
    ///     0x00, 0x01, 0x00, 0x00,
    ///     0x40, 0x06, 0x00, 0x00,
    ///     192, 168, 0, 1,
    ///     192, 168, 0, 2,
    /// ];
    ///
    /// let mut cursor = Cursor::new(&data);
    /// let iph = Ipv4Header::read(&mut cursor).unwrap();
    ///
    /// assert_eq!(iph.version(), 4);
    /// assert_eq!(iph.ihl(), 5);
    /// ```
    pub fn read<T: std::io::Read>(r: &mut T) -> Result<Self> {
        // TODO: Use `Read::read_buf` with `FixedBuf` when it is stable.
        //
        // <https://github.com/rust-lang/rust/issues/78485>
        let mut buf = [0u8; Self::MAX_HEADER_LEN];

        r.read_exact(&mut buf[..Self::MIN_HEADER_LEN])?;

        let ihl = (buf[0] & 0xF) as usize;
        let header_len = ihl << 2;
        let remaining = header_len.saturating_sub(Self::MIN_HEADER_LEN);

        if remaining != 0 {
            r.read_exact(&mut buf[Self::MIN_HEADER_LEN..Self::MIN_HEADER_LEN + remaining])?;
        }

        Ipv4Header::try_from(&buf[..header_len])
    }

    /// Writes the `Ipv4Header` to the given writer.
    ///
    /// It is the callers responsibility to ensure the checksum is [`set`]
    /// before writing the header.
    ///
    /// # Errors
    ///
    /// Returns any encountered I/O error.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcp::wire::{Protocol, Ipv4Header};
    ///
    /// let mut iph = Ipv4Header::new(
    ///     0,
    ///     [192, 168, 0, 1],
    ///     [192, 168, 0, 44],
    ///     0,
    ///     64,
    ///     Protocol::TCP,
    /// )
    /// .unwrap();
    ///
    /// // **Must** set header checksum before writing IPv4 header.
    /// iph.set_header_checksum();
    ///
    /// let mut buf = Vec::new();
    /// iph.write(&mut buf).unwrap();
    /// assert_eq!(buf.len(), 20);
    /// ```
    ///
    /// [`set`]: Ipv4Header::set_header_checksum
    pub fn write<T: std::io::Write>(&self, w: &mut T) -> Result<()> {
        Ok(w.write_all(self.to_bytes().as_slice())?)
    }

    /// Returns the computed TCP header checksum.
    ///
    /// The checksum is the 16-bit one's complement of the one's complement sum
    /// of all 16-bit words in the header. The checksum field itself is treated
    /// as zero during computation.
    fn compute_header_checksum(&self) -> u16 {
        let mut buf = self.to_bytes();
        let header_bytes = buf.as_slice_mut();

        // Zero-out checksum field, based on layout of an IPv4 header.
        header_bytes[10] = 0x00;
        header_bytes[11] = 0x00;

        let mut sum = 0u32;

        for i in (0..header_bytes.len()).step_by(2) {
            let word = u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]]);

            sum += u32::from(word);

            // Handle potential overflow with carry folding.
            if sum > 0xFFFF {
                // Add the higher 16-bits to the lower 16-bits.
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        // Handle any remaining overflow with carry folding.
        while sum > 0xFFFF {
            // Add the higher 16-bits to the lower 16-bits.
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    #[inline]
    fn compute_total_length(&self, payload_len: u16) -> Result<u16> {
        (self.header_len() as u16)
            .checked_add(payload_len)
            .ok_or_else(|| {
                Error::Header(HeaderError::PayloadTooLarge {
                    provided: payload_len,
                    max: self.max_payload_len(),
                })
            })
    }

    #[inline]
    const fn max_payload_len(&self) -> u16 {
        u16::MAX - self.header_len() as u16
    }
}

impl TryFrom<&[u8]> for Ipv4Header {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> core::result::Result<Self, Self::Error> {
        let len = bytes.len();

        if len < Self::MIN_HEADER_LEN {
            return Err(Error::Parse(ParseError::InvalidBufferLength {
                provided: len,
                min: Self::MIN_HEADER_LEN,
                max: Self::MAX_HEADER_LEN,
            }));
        }

        let version_ihl = bytes[0];
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0xF;
        let header_len = (ihl << 2) as usize;

        if version != 4 {
            return Err(Error::Parse(ParseError::InvalidVersion {
                provided: version,
                expected: 4,
            }));
        }

        if ihl < Self::MIN_IHL {
            return Err(Error::Parse(ParseError::InvalidIhl {
                provided: ihl,
                min: Self::MIN_IHL,
                max: Self::MAX_IHL,
            }));
        }

        if header_len > len {
            return Err(Error::Parse(ParseError::InvalidHeaderLength {
                provided: len,
                expected: header_len,
            }));
        }

        let options = Ipv4Options::from_bytes(&bytes[Self::MIN_HEADER_LEN..header_len])?;

        Ok(Self {
            version_ihl,
            tos: bytes[1],
            total_length: {
                let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);

                if total_length < header_len as u16 {
                    return Err(Error::Parse(ParseError::InvalidTotalLength {
                        provided: total_length,
                        expected: header_len as u16,
                    }));
                }

                total_length
            },
            id: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_and_offset: u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl: bytes[8],
            protocol: Protocol::try_from(bytes[9])?,
            header_checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            src_addr: [bytes[12], bytes[13], bytes[14], bytes[15]],
            dst_addr: [bytes[16], bytes[17], bytes[18], bytes[19]],
            options,
        })
    }
}

#[cfg(test)]
impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            // Version = 4, IHL = 5
            version_ihl: 0b0100_0101,
            tos: 0,
            total_length: Self::MIN_HEADER_LEN as u16,
            id: 0,
            #[allow(clippy::unusual_byte_groupings)]
            //                       Fragment Off.
            //                   D|M +-----------+
            //                   F|F |           |
            flags_and_offset: 0b01_0_0000000000000,
            ttl: 0,
            protocol: Protocol::TCP,
            header_checksum: 0,
            src_addr: [0u8; 4],
            dst_addr: [0u8; 4],
            options: Ipv4Options::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(miri))]
    use proptest::prelude::*;

    #[cfg(not(miri))]
    proptest! {
        #[test]
        fn test_ipv4_header_proptest(header_bytes in prop::collection::vec(any::<u8>(), 0..Ipv4Header::MAX_HEADER_LEN)) {
            if let Ok(header) = Ipv4Header::try_from(&header_bytes[..]) {
                let header_bytes = header.to_bytes();

                if let Ok(round_trip) = Ipv4Header::try_from(header_bytes.as_slice()) {
                    let parsed_bytes = round_trip.to_bytes();
                    prop_assert_eq!(header_bytes.as_slice(), parsed_bytes.as_slice());
                }
            }
        }
    }

    #[test]
    fn test_ipv4_header_valid() {
        let header_bytes: [u8; 40] = [
            0x4a, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let header = Ipv4Header::read(&mut &header_bytes[..]);
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 10);
        assert_eq!(header.tos(), 0);
        assert_eq!(header.total_length(), 60);
        assert_eq!(header.id(), 48890);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), Protocol::TCP);
        assert_eq!(header.header_checksum(), 0xFA43);
        assert_eq!(header.src_addr(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst_addr(), [192u8, 168u8, 0u8, 44u8]);
        assert_eq!(header.options().as_slice().len(), 20);
    }

    #[test]
    fn test_ipv4_header_round_trip() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.tos(), 0);
        assert_eq!(header.total_length(), 60);
        assert_eq!(header.id(), 48890);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), Protocol::TCP);
        assert_eq!(header.header_checksum(), 0xFA43);
        assert_eq!(header.src_addr(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst_addr(), [192u8, 168u8, 0u8, 44u8]);

        let header = Ipv4Header::try_from(header.to_bytes().as_slice());
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.tos(), 0);
        assert_eq!(header.total_length(), 60);
        assert_eq!(header.id(), 48890);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), Protocol::TCP);
        assert_eq!(header.header_checksum(), 0xFA43);
        assert_eq!(header.src_addr(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst_addr(), [192u8, 168u8, 0u8, 44u8]);
    }

    #[test]
    fn test_ipv4_header_checksum_valid() {
        let header_bytes: [u8; 40] = [
            0x4a, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0x80, 0x66, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let header = Ipv4Header::read(&mut &header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        assert_eq!(header.header_checksum(), header.compute_header_checksum());

        // Invalidate the header checksum.
        header.set_payload_len(22).expect("should not overflow u16");

        assert_ne!(header.header_checksum(), header.compute_header_checksum());
    }

    #[test]
    fn test_ipv4_header_flags_bits() {
        // Check if all permutations of `DF` and `MF` bits can be parsed.
        for flags in 0..=0b111 {
            let mut header_bytes: [u8; 20] = [
                0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
            ];

            header_bytes[6] = flags;

            let header = Ipv4Header::try_from(&header_bytes[..]);
            assert!(header.is_ok());
            let header = header.unwrap();

            assert_eq!(
                header.dont_fragment(),
                (flags & 0b0100_0000) != 0,
                "DF failed for {flags:06b}"
            );
            assert_eq!(
                header.more_fragments(),
                (flags & 0b0010_0000) != 0,
                "MF failed for {flags:06b}"
            );
        }
    }

    #[test]
    fn test_ipv4_header_fragment_offset_valid() {
        {
            let header_bytes: [u8; 40] = [
                0x4a, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x5F, 0xFF, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
            ];

            let header = Ipv4Header::try_from(&header_bytes[..]);

            assert!(header.is_ok());
            assert_eq!(header.unwrap().fragment_offset(), 8191);
        }

        {
            let header_bytes: [u8; 40] = [
                0x4a, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
            ];

            let header = Ipv4Header::try_from(&header_bytes[..]);

            assert!(header.is_ok());
            assert_eq!(header.unwrap().fragment_offset(), 0);
        }
    }

    #[test]
    fn test_ipv4_header_with_payload() {
        // `IHL` of 6 indicates a 24-byte header (20 base + 4 options).
        //
        // The buffer contains 60 bytes total. Parsing should ignore the extra
        // 36 bytes (payload) and succeed.
        let header_bytes: [u8; 60] = [
            0x46, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x5F, 0xFF, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_ok());
    }

    #[test]
    fn test_ipv4_header_buffer_length_invalid() {
        let header_bytes: [u8; 14] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(
            matches!(
                header,
                Err(Error::Parse(ParseError::InvalidBufferLength { .. }))
            ),
            "expected error: `InvalidBufferLength`, got: {header:?}"
        );
    }

    #[test]
    fn test_ipv4_header_version_invalid() {
        let header_bytes: [u8; 20] = [
            0x65, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(
            matches!(header, Err(Error::Parse(ParseError::InvalidVersion { .. }))),
            "expected error: `InvalidVersion`, got: {header:?}"
        );
    }

    #[test]
    fn test_ipv4_header_ihl_invalid() {
        let header_bytes: [u8; 20] = [
            0x43, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(
            matches!(header, Err(Error::Parse(ParseError::InvalidIhl { .. }))),
            "expected error: `InvalidIhl`, got: {header:?}"
        );
    }

    #[test]
    fn test_ipv4_header_total_len_invalid() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x00, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(
            matches!(
                header,
                Err(Error::Parse(ParseError::InvalidTotalLength { .. }))
            ),
            "expected error: `InvalidTotalLength`, got: {header:?}"
        );
    }
}
