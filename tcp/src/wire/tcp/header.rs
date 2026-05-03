use super::TcpOptions;

use crate::util::FixedBuf;
use crate::wire::ipv4::Ipv4Header;
use crate::{Error, ParseError, Result};

/// TCP Segment Header [(RFC 793, Section 3.1)].
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Acknowledgment Number                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Data |           |U|A|P|R|S|F|                               |
/// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
/// |       |           |G|K|H|T|N|N|                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |         Urgent Pointer        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             data                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [(RFC 793, Section 3.1)]: https://www.rfc-editor.org/rfc/rfc793#section-3.1
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    /// The source port number.
    src_port: u16,
    /// The destination port number.
    dst_port: u16,
    /// Sequence number of the first data octet in this segment (except when
    /// `SYN` is present). If `SYN` is present the sequence number is the
    /// initial sequence number (`ISN`) and the first data octet is `ISN` + 1.
    seq_number: u32,
    /// If the `ACK` control bit is set this field contains the value of the
    /// next sequence number the sender of the segment is expecting to receive.
    /// Once a connection is established this is always sent.
    ack_number: u32,
    /// ```text
    /// 0                   1          
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Data |           |U|A|P|R|S|F|
    /// | Offset| Reserved  |R|C|S|S|Y|I|
    /// |       |           |G|K|H|T|N|N|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// Data offset is the number of 32-bit words in the TCP Header (4-bits).
    /// This indicates where the data begins.
    ///
    /// 6-bits are _reserved_ for future use, as defined in RFC 793.
    ///
    /// Control bits (6-bits):
    ///
    /// ```text
    ///    URG:  Urgent Pointer field significant
    ///    ACK:  Acknowledgment field significant
    ///    PSH:  Push Function
    ///    RST:  Reset the connection
    ///    SYN:  Synchronize sequence numbers
    ///    FIN:  No more data from sender
    /// ```
    data_offset_and_flags: u16,
    /// Number of data octets beginning with the one indicated in the
    /// acknowledgment field which the sender of this segment is willing to
    /// accept.
    window: u16,
    /// Checksum field is the 16-bit one's complement of the one's complement
    /// sum of all 16-bit words in the header and text.
    ///
    /// The checksum also covers a 96-bit pseudo header conceptually prefixed
    /// to the TCP header and gives the TCP protection against misrouted
    /// segments.
    ///
    /// ```text
    ///        +--------+--------+--------+--------+
    ///        |           Source Address          |
    ///        +--------+--------+--------+--------+
    ///        |         Destination Address       |
    ///        +--------+--------+--------+--------+
    ///        |  zero  |  PTCL  |    TCP Length   |
    ///        +--------+--------+--------+--------+
    ///                     ^
    ///                     Protocol
    /// ```
    checksum: u16,
    /// Current value of the urgent pointer as a positive offset from the
    /// sequence number in this segment.
    urg_pointer: u16,
    /// Options that may occupy space at the end of the TCP header and are a
    /// multiple of 8-bits in length.
    ///
    /// Available options, as defined in RFC 793:
    ///
    /// ```text
    ///      Kind     Length    Meaning
    ///      ----     ------    -------
    ///       0         -       End of option list.
    ///       1         -       No-Operation.
    ///       2         4       Maximum Segment Size.
    /// ```
    options: TcpOptions,
}

impl TcpHeader {
    /// Minimum length of a TCP header in bytes.
    pub const MIN_HEADER_LEN: usize = (Self::MIN_DATA_OFFSET << 2) as usize;

    /// Maximum length of a TCP header in bytes.
    ///
    /// `data offset` has a minimum value of 5 words (20 bytes).
    ///
    /// Given its 4-bit representation:
    ///
    /// ```text
    ///     1001
    /// ```
    /// the maximum `data_offset` is:
    ///
    /// ```text
    ///     1111
    /// ```
    ///
    /// A `data_offset` of 15 words corresponds to 60 bytes.
    pub const MAX_HEADER_LEN: usize = (Self::MAX_DATA_OFFSET << 2) as usize;

    /// Minimum `data_offset` value of a TCP header.
    const MIN_DATA_OFFSET: u8 = 5;

    /// Maximum `data_offset` value of a TCP header.
    const MAX_DATA_OFFSET: u8 = 15;

    /// Creates a new TCP header with the given source and destination ports,
    /// initial sequence number (ISN), and window size. Other fields are set to
    /// their _defaults_.
    #[inline]
    #[must_use]
    pub const fn new(src_port: u16, dst_port: u16, seq_number: u32, window: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq_number,
            ack_number: 0,
            #[allow(clippy::unusual_byte_groupings)]
            //                       Off   Resv  U|A|P|R|S|F
            //                       +--+ +----+ R|C|S|S|Y|I
            //                       |  | |    | G|K|H|T|N|N
            data_offset_and_flags: 0b0101_000000_0_0_0_0_0_0,
            window,
            checksum: 0,
            urg_pointer: 0,
            options: TcpOptions::new(),
        }
    }

    /// Returns the `Source Port` field of the TCP header.
    #[inline]
    pub const fn src_port(&self) -> u16 {
        self.src_port
    }

    /// Returns the `Destination Port` field of the TCP header.
    #[inline]
    pub const fn dst_port(&self) -> u16 {
        self.dst_port
    }

    /// Returns the `Sequence Number` field of the TCP header.
    #[inline]
    pub const fn seq_number(&self) -> u32 {
        self.seq_number
    }

    /// Returns the `Acknowledgment Number` field of the TCP header.
    #[inline]
    pub const fn ack_number(&self) -> u32 {
        self.ack_number
    }

    /// Sets the `Acknowledgment Number` field of the TCP header with the
    /// given value.
    #[inline]
    pub const fn set_ack_number(&mut self, ack: u32) {
        self.ack_number = ack;
    }

    /// Returns the `Data Offset` field of the TCP header.
    ///
    /// To get the header length (including options) in bytes, use
    /// [TcpHeader::header_len].
    #[inline]
    pub const fn data_offset(&self) -> u8 {
        (self.data_offset_and_flags >> 12) as u8
    }

    /// Returns `true` if the `URG` (Urgent) flag is set in the TCP header.
    #[inline]
    pub const fn urg(&self) -> bool {
        (self.data_offset_and_flags >> 5) & 1 == 1
    }

    /// Sets the `URG` (Urgent) flag in the TCP header.
    #[inline]
    pub const fn set_urg(&mut self) {
        self.data_offset_and_flags |= 1 << 5;
    }

    /// Returns `true` if the `ACK` (Acknowledgment) flag is set in the TCP
    /// header.
    #[inline]
    pub const fn ack(&self) -> bool {
        (self.data_offset_and_flags >> 4) & 1 == 1
    }

    /// Sets the `ACK` (Acknowledgment) flag in the TCP header.
    #[inline]
    pub const fn set_ack(&mut self) {
        self.data_offset_and_flags |= 1 << 4;
    }

    /// Returns `true` if the `PSH` (Push) flag is set in the TCP header.
    #[inline]
    pub const fn psh(&self) -> bool {
        (self.data_offset_and_flags >> 3) & 1 == 1
    }

    /// Sets the `PSH` (Push) flag in the TCP header.
    #[inline]
    pub const fn set_psh(&mut self) {
        self.data_offset_and_flags |= 1 << 3;
    }

    /// Returns `true` if the `RST` (Reset) flag is set in the TCP header.
    #[inline]
    pub const fn rst(&self) -> bool {
        (self.data_offset_and_flags >> 2) & 1 == 1
    }

    /// Sets the `RST` (Reset) flag in the TCP header.
    #[inline]
    pub const fn set_rst(&mut self) {
        self.data_offset_and_flags |= 1 << 2;
    }

    /// Returns `true` if the `SYN` (Synchronize) flag is set in the TCP header.
    #[inline]
    pub const fn syn(&self) -> bool {
        (self.data_offset_and_flags >> 1) & 1 == 1
    }

    /// Sets the `SYN` (Synchronize) flag in the TCP header.
    #[inline]
    pub const fn set_syn(&mut self) {
        self.data_offset_and_flags |= 1 << 1;
    }

    /// Returns `true` if the `FIN` (Finish) flag is set in the TCP header.
    #[inline]
    pub const fn fin(&self) -> bool {
        self.data_offset_and_flags & 1 == 1
    }

    /// Sets the `FIN` (Finish) flag in the TCP header.
    #[inline]
    pub const fn set_fin(&mut self) {
        self.data_offset_and_flags |= 1;
    }

    /// Returns the `Window` field of the TCP header.
    #[inline]
    pub const fn window(&self) -> u16 {
        self.window
    }

    /// Returns the `Checksum` field of the TCP header.
    #[inline]
    pub const fn checksum(&self) -> u16 {
        self.checksum
    }

    /// Computes and sets the TCP header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, ip_header: &Ipv4Header, payload: &[u8]) {
        self.checksum = self.compute_checksum(ip_header, payload);
    }

    /// Returns `true` if the TCP header checksum is valid.
    #[inline]
    pub fn is_valid_checksum(&self, ip_header: &Ipv4Header, payload: &[u8]) -> bool {
        self.checksum == self.compute_checksum(ip_header, payload)
    }

    /// Returns the `Urgent Pointer` field of the TCP header.
    #[inline]
    pub const fn urgent_pointer(&self) -> u16 {
        self.urg_pointer
    }

    /// Returns a reference to the `Options` field of the TCP header.
    #[inline]
    pub const fn options(&self) -> &TcpOptions {
        &self.options
    }

    /// Returns the length of the TCP header in bytes (including options).
    #[inline]
    pub const fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN + self.options.len()
    }

    /// Appends the `Maximum Segment Size` (MSS) option to the TCP header's
    /// options.
    ///
    /// # Errors
    ///
    /// Returns an error if the header's [`TcpOptions`] lack sufficient space to
    /// append the `MSS`, or if `mss` is zero.
    #[inline]
    pub fn set_option_mss(&mut self, mss: u16) -> Result<()> {
        self.options.set_mss(mss)?;

        let new_data_offset = ((TcpOptions::MSS_LEN >> 2) as u8 + self.data_offset()) as u16;

        debug_assert!(
            new_data_offset <= Self::MAX_DATA_OFFSET as u16,
            "header length overflow appending MSS; new_data_offset: {new_data_offset}, maximum data_offset: {}",
            Self::MAX_DATA_OFFSET
        );

        // Clear previous `data_offset`.
        self.data_offset_and_flags &= 0x0FFF;
        // Shift and combine `new_data_offset` with the cleared `data_offset`.
        self.data_offset_and_flags |= new_data_offset << 12;

        Ok(())
    }

    /// Computes the TCP header checksum.
    ///
    /// The checksum field is the 16-bit one's complement of the one's
    /// complement sum of all 16-bit words in the pseudo header, TCP header,
    /// and payload. The checksum field itself is treated as zero during
    /// computation.
    pub fn compute_checksum(&self, ip_header: &Ipv4Header, payload: &[u8]) -> u16 {
        // ```
        //        +--------+--------+--------+--------+
        //        |           Source Address          |
        //        +--------+--------+--------+--------+
        //        |         Destination Address       |
        //        +--------+--------+--------+--------+
        //        |  zero  |  PTCL  |    TCP Length   |
        //        +--------+--------+--------+--------+
        // ```
        let mut pseudo_header = [0u8; 12];

        pseudo_header[0..4].copy_from_slice(&ip_header.src_addr());
        pseudo_header[4..8].copy_from_slice(&ip_header.dst_addr());
        pseudo_header[8] = 0;
        pseudo_header[9] = ip_header.protocol().into();

        let tcp_len: u16 = (self.header_len() + payload.len()) as u16;
        pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

        let mut buf = self.to_bytes();
        let header_bytes = buf.as_slice_mut();

        // Zero-out checksum field, based on layout of a TCP header.
        header_bytes[16] = 0x00;
        header_bytes[17] = 0x00;

        let mut checksum_iter = pseudo_header
            .iter()
            .chain(header_bytes.iter())
            .chain(payload.iter());

        let mut sum = 0u32;

        loop {
            let word = match (checksum_iter.next(), checksum_iter.next()) {
                (Some(h), Some(l)) => u16::from_be_bytes([*h, *l]),
                (Some(h), None) => {
                    // RFC 793, Section 3.1:
                    //
                    // If a segment contains an odd number of header and text
                    // octets to be checksummed, the last octet is padded on
                    // the right with zeros to form a 16-bit word for checksum
                    // purposes. The pad is not transmitted as part of the
                    // segment.
                    u16::from_be_bytes([*h, 0x00])
                }
                _ => {
                    break;
                }
            };

            sum += word as u32;

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

    /// Returns the memory representation of the TCP header as a [`FixedBuf`]
    /// in big-endian (network) byte order.
    #[inline]
    pub fn to_bytes(&self) -> FixedBuf<{ Self::MAX_HEADER_LEN }> {
        let mut buf: FixedBuf<{ Self::MAX_HEADER_LEN }> = FixedBuf::new();

        buf.append(&self.src_port.to_be_bytes());
        buf.append(&self.dst_port.to_be_bytes());
        buf.append(&self.seq_number.to_be_bytes());
        buf.append(&self.ack_number.to_be_bytes());
        buf.append(&self.data_offset_and_flags.to_be_bytes());
        buf.append(&self.window.to_be_bytes());
        buf.append(&self.checksum.to_be_bytes());
        buf.append(&self.urg_pointer.to_be_bytes());
        buf.append(self.options.as_slice());

        buf
    }

    /// Reads and parses a TCP header from the given reader.
    ///
    /// # Errors
    ///
    /// Returns an error if an I/O error is encountered or the available bytes
    /// are insufficient or malformed to form a valid TCP header.
    #[inline]
    pub fn read<T: std::io::Read>(r: &mut T) -> Result<Self> {
        // FIXME: Use `Read::read_buf` with `FixedBuf` when it is stable.
        //
        // <https://github.com/rust-lang/rust/issues/78485>
        let mut buf = [0u8; Self::MAX_HEADER_LEN];

        r.read_exact(&mut buf[..Self::MIN_HEADER_LEN])?;

        let data_offset = (buf[12] >> 4) as usize;
        let header_len = data_offset << 2;
        let remaining = header_len.saturating_sub(Self::MIN_HEADER_LEN);

        if remaining != 0 {
            r.read_exact(&mut buf[Self::MIN_HEADER_LEN..Self::MIN_HEADER_LEN + remaining])?;
        }

        TcpHeader::try_from(&buf[..header_len])
    }

    /// Writes the TCP header to the given writer.
    ///
    /// It is the callers responsibility to ensure the checksum is [`set`]
    /// before writing the header.
    ///
    /// # Errors
    ///
    /// Returns an error if an I/O error is encountered.
    ///
    /// [`set`]: TcpHeader::set_checksum
    #[inline]
    pub fn write<T: std::io::Write>(&self, w: &mut T) -> Result<()> {
        Ok(w.write_all(self.to_bytes().as_slice())?)
    }
}

impl TryFrom<&[u8]> for TcpHeader {
    type Error = Error;

    #[inline]
    fn try_from(bytes: &[u8]) -> core::result::Result<Self, Self::Error> {
        let len = bytes.len();

        if len < Self::MIN_HEADER_LEN {
            return Err(Error::Parse(ParseError::InvalidBufferLength {
                provided: len,
                min: Self::MIN_HEADER_LEN,
                max: Self::MAX_HEADER_LEN,
            }));
        }

        let data_offset_and_flags = u16::from_be_bytes([bytes[12], bytes[13]]);
        let data_offset = (data_offset_and_flags >> 12) as u8;
        let header_len = (data_offset << 2) as usize;

        if data_offset < Self::MIN_DATA_OFFSET {
            return Err(Error::Parse(ParseError::InvalidDataOffset {
                provided: data_offset as u16,
                min: Self::MIN_DATA_OFFSET,
                max: Self::MAX_DATA_OFFSET,
            }));
        }

        if header_len > len {
            return Err(Error::Parse(ParseError::InvalidHeaderLength {
                provided: len,
                expected: header_len,
            }));
        }

        let options = TcpOptions::from_bytes(&bytes[Self::MIN_HEADER_LEN..header_len])?;

        Ok(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq_number: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack_number: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            data_offset_and_flags,
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            urg_pointer: u16::from_be_bytes([bytes[18], bytes[19]]),
            options,
        })
    }
}

#[cfg(all(test, not(miri)))]
impl Default for TcpHeader {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            seq_number: 0,
            ack_number: 0,
            #[allow(clippy::unusual_byte_groupings)]
            //                       Off   Resv  U|A|P|R|S|F
            //                       +--+ +----+ R|C|S|S|Y|I
            //                       |  | |    | G|K|H|T|N|N
            data_offset_and_flags: 0b0101_000000_0_0_0_0_0_0,
            window: 0,
            checksum: 0,
            urg_pointer: 0,
            options: TcpOptions::new(),
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
        fn test_tcp_header_proptest(header_bytes in prop::collection::vec(any::<u8>(), 0..TcpHeader::MAX_HEADER_LEN)) {
            if let Ok(header) = TcpHeader::try_from(&header_bytes[..]) {
                let header_bytes = header.to_bytes();

                if let Ok(round_trip) = TcpHeader::try_from(header_bytes.as_slice()) {
                    let parsed_bytes = round_trip.to_bytes();
                    prop_assert_eq!(header_bytes.as_slice(), parsed_bytes.as_slice());
                }
            }
        }
    }

    #[test]
    fn test_tcp_header_valid() {
        let header_bytes: [u8; 40] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let mut header_bytes = &header_bytes[..];

        let header = TcpHeader::read(&mut header_bytes);
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.src_port(), 40982);
        assert_eq!(header.dst_port(), 443);
        assert_eq!(header.seq_number(), 3166393512);
        assert_eq!(header.ack_number(), 0);
        assert_eq!(header.data_offset(), 10);
        assert!(!header.urg());
        assert!(!header.ack());
        assert!(!header.psh());
        assert!(!header.rst());
        assert!(header.syn());
        assert!(!header.fin());
        assert_eq!(header.window(), 64240);
        assert_eq!(header.checksum(), 0xBB4C);
        assert_eq!(header.urgent_pointer(), 0);
        assert_eq!(header.options().as_slice().len(), 20);
        assert_eq!(header.options().mss(), Some(1460));
    }

    #[test]
    fn test_tcp_header_round_trip() {
        let header_bytes: [u8; 40] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let mut header_bytes = &header_bytes[..];

        let header = TcpHeader::read(&mut header_bytes);
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.src_port(), 40982);
        assert_eq!(header.dst_port(), 443);
        assert_eq!(header.seq_number(), 3166393512);
        assert_eq!(header.ack_number(), 0);
        assert_eq!(header.data_offset(), 10);
        assert!(!header.urg());
        assert!(!header.ack());
        assert!(!header.psh());
        assert!(!header.rst());
        assert!(header.syn());
        assert!(!header.fin());
        assert_eq!(header.window(), 64240);
        assert_eq!(header.checksum(), 0xBB4C);
        assert_eq!(header.urgent_pointer(), 0);
        assert_eq!(header.options().as_slice().len(), 20);
        assert_eq!(header.options().mss(), Some(1460));

        let buf = header.to_bytes();

        let header = TcpHeader::try_from(buf.as_slice());
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.src_port(), 40982);
        assert_eq!(header.dst_port(), 443);
        assert_eq!(header.seq_number(), 3166393512);
        assert_eq!(header.ack_number(), 0);
        assert_eq!(header.data_offset(), 10);
        assert!(!header.urg());
        assert!(!header.ack());
        assert!(!header.psh());
        assert!(!header.rst());
        assert!(header.syn());
        assert!(!header.fin());
        assert_eq!(header.window(), 64240);
        assert_eq!(header.checksum(), 0xBB4C);
        assert_eq!(header.urgent_pointer(), 0);
        assert_eq!(header.options().as_slice().len(), 20);
        assert_eq!(header.options().mss(), Some(1460));
    }

    #[test]
    fn test_tcp_header_checksum_valid() {
        let header_bytes: [u8; 40] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        let iph = Ipv4Header::new(
            0,
            [192, 168, 0, 1],
            [192, 168, 0, 44],
            header.header_len() as u16,
            64,
            crate::wire::ipv4::Protocol::TCP,
        )
        .unwrap();

        assert_eq!(header.checksum(), header.compute_checksum(&iph, &[]));

        // Invalidate the header checksum.
        header.set_ack_number(22);

        assert_ne!(header.checksum(), header.compute_checksum(&iph, &[]));
    }

    #[test]
    fn test_tcp_header_control_bits() {
        // Check if all permutations of `URG`, `ACK`, `PSH`, `RST`, `SYN`, and
        // `FIN` bits can be parsed.
        for flags in 0u8..=0b00111111 {
            let mut header_bytes: [u8; 40] = [
                0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00,
                0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
            ];

            header_bytes[13] = flags;

            let header = TcpHeader::try_from(&header_bytes[..]);
            assert!(header.is_ok());
            let header = header.unwrap();

            assert_eq!(
                header.urg(),
                (flags & 0b00100000) != 0,
                "URG failed for {:06b}",
                flags
            );
            assert_eq!(
                header.ack(),
                (flags & 0b00010000) != 0,
                "ACK failed for {:06b}",
                flags
            );
            assert_eq!(
                header.psh(),
                (flags & 0b00001000) != 0,
                "PSH failed for {:06b}",
                flags
            );
            assert_eq!(
                header.rst(),
                (flags & 0b00000100) != 0,
                "RST failed for {:06b}",
                flags
            );
            assert_eq!(
                header.syn(),
                (flags & 0b00000010) != 0,
                "SYN failed for {:06b}",
                flags
            );
            assert_eq!(
                header.fin(),
                (flags & 0b00000001) != 0,
                "FIN failed for {:06b}",
                flags
            );
        }
    }

    #[test]
    fn test_tcp_header_data_offset_valid() {
        {
            let header_bytes: [u8; 60] = [
                0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00,
                0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];

            let header = TcpHeader::try_from(&header_bytes[..]);

            assert!(header.is_ok());
            assert_eq!(header.unwrap().data_offset(), 15);
        }

        {
            let header_bytes: [u8; 60] = [
                0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00,
                0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];

            let header = TcpHeader::try_from(&header_bytes[..]);

            assert!(header.is_ok());
            assert_eq!(header.unwrap().data_offset(), 5);
        }

        {
            let header_bytes: [u8; 60] = [
                0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00,
                0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ];

            let header = TcpHeader::try_from(&header_bytes[..]);

            assert!(header.is_ok());
            assert_eq!(header.unwrap().data_offset(), 10);
        }
    }

    #[test]
    fn test_tcp_header_set_mss_option() {
        let header_bytes: [u8; 20] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xfa, 0xf0, 0x80, 0x3e, 0x00, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        // Ensure flags are not clobbered when setting MSS option.
        header.set_syn();
        header.set_psh();
        header.set_urg();

        assert_eq!(header.data_offset(), 5);
        assert_eq!(header.options.mss(), None);

        assert!(header.set_option_mss(1460).is_ok());

        assert!(header.syn());
        assert!(header.psh());
        assert!(header.urg());
        assert_eq!(header.data_offset(), 6);
        assert_eq!(header.options.mss(), Some(1460));

        let buf = header.to_bytes();
        assert!(TcpHeader::try_from(buf.as_slice()).is_ok());
    }

    #[test]
    fn test_tcp_header_with_payload() {
        // `data_offset` of 6 indicates a 24-byte header (20 base + 4 options).
        //
        // The buffer contains 60 bytes total. Parsing should ignore the extra
        // 36 bytes (payload) and succeed.
        let header_bytes: [u8; 60] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_ok());
    }

    #[test]
    fn test_tcp_header_buffer_length_invalid() {
        let header_bytes: [u8; 14] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(
            matches!(
                header,
                Err(Error::Parse(ParseError::InvalidBufferLength { .. }))
            ),
            "expected error: `InvalidBufferLength`, got: {:?}",
            header
        );
    }

    #[test]
    fn test_tcp_header_data_offset_invalid() {
        let header_bytes: [u8; 20] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x20, 0x02,
            0xfa, 0xf0, 0x80, 0x3e, 0x00, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(
            matches!(
                header,
                Err(Error::Parse(ParseError::InvalidDataOffset { .. }))
            ),
            "expected error: `InvalidDataOffset`, got: {:?}",
            header
        );
    }
}
