use std::io;

use crate::{Error, HeaderError, ParseError};

/// IPv4 Datagram Header.
///
/// # Note
///
/// IPv4 options are currently not supported.
///
/// RFC 791 (3.1)
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
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// The version field indicates the format of the internet header.
    ///
    /// Internet Header Length (IHL) is the length of the internet header in
    /// 32-bit words.
    version_ihl: u8,
    /// Type of service provides an indication of the abstract parameters
    /// of the quality of service desired. These parameters are to be used to
    /// guide the selection of the actual service parameters when transmitting
    /// a datagram through a particular network.
    tos: u8,
    /// Total length is the length of the datagram, measured in octets,
    /// including internet header and payload.
    total_len: u16,
    /// An identifying value assigned by the sender to aid in assembling the
    /// fragments of a datagram.
    id: u16,
    /// Control flags:
    ///
    /// ```text
    ///      Bit 0: reserved, must be zero
    ///      Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
    ///      Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
    ///
    ///          0   1   2
    ///        +---+---+---+
    ///        |   | D | M |
    ///        | 0 | F | F |
    ///        +---+---+---+
    /// ```
    ///
    /// Fragment offset indicates where in the datagram this fragment belongs,
    /// measured in units of 8 octets (64-bits).
    flags_and_offset: u16,
    /// Indicates the maximum time the datagram is allowed to remain in the
    /// internet system.
    ttl: u8,
    /// Indicates the next level protocol used in the data portion of the
    /// internet datagram.
    protocol: Protocol,
    /// A checksum on the header only. Since some header fields change (e.g.,
    /// time to live), this is recomputed and verified at each point that the
    /// internet header is processed.
    header_checksum: u16,
    /// The source address.
    src_addr: [u8; 4],
    /// The destination address.
    dst_addr: [u8; 4],
}

impl Ipv4Header {
    /// Minimum length of an IPv4 header in bytes.
    pub const MIN_HEADER_LEN: u16 = 20;

    /// Maximum length of an IPv4 header in bytes.
    ///
    /// The IHL has a minimum value of 5, or 20 bytes.
    ///
    /// Given its 4-bit representation:
    ///
    /// ```text
    ///     1001
    /// ```
    /// the maximum possible size for an IPv4 header is:
    ///
    /// ```text
    ///     1111
    /// ```
    ///
    /// which when converted to decimal, is 15, or 60 bytes.
    pub const MAX_HEADER_LEN: u16 = 60;

    /// Maximum payload length in bytes, accounting for the header length.
    pub const MAX_PAYLOAD_LEN: u16 = u16::MAX - Self::MIN_HEADER_LEN;

    /// Creates a new IPv4 header with the specified source and destination
    /// addresses, payload length, TTL, and protocol, while setting default
    /// values for other fields.
    ///
    /// # Errors
    ///
    /// Returns an error if the `payload_len` exceeds the maximum allowed
    /// payload length.
    pub fn new(
        src: [u8; 4],
        dst: [u8; 4],
        payload_len: u16,
        ttl: u8,
        protocol: Protocol,
    ) -> crate::Result<Self> {
        if payload_len > Self::MAX_PAYLOAD_LEN {
            return Err(Error::Header(HeaderError::PayloadTooLarge {
                provided: payload_len,
                max: Self::MAX_PAYLOAD_LEN,
            }));
        }

        Ok(Self {
            total_len: Self::MIN_HEADER_LEN + payload_len,
            ttl,
            protocol,
            src_addr: src,
            dst_addr: dst,
            ..Default::default()
        })
    }

    /// Returns the `version` field of the IPv4 header.
    pub fn version(&self) -> u8 {
        // Stored in the higher 4 bits.
        self.version_ihl >> 4
    }

    /// Returns the `IHL` field of the IPv4 header, specified 32-bit words.
    ///
    /// To get the header length in bytes, use [Ipv4Header::header_len].
    pub fn ihl(&self) -> u8 {
        // Stored in the lower 4 bits.
        self.version_ihl & 0xF
    }

    /// Returns the `type of service` field of the IPv4 header.
    pub fn tos(&self) -> u8 {
        self.tos
    }

    /// Returns the `total length` field of the IPv4 header.
    pub fn total_len(&self) -> u16 {
        self.total_len
    }

    /// Sets the `total length` field of the IPv4 header given a payload length.
    ///
    /// # Errors
    ///
    /// Returns an error if the `payload_len` exceeds the maximum allowed
    /// payload length.
    pub fn set_payload_len(&mut self, payload_len: u16) -> crate::Result<()> {
        if payload_len > Self::MAX_PAYLOAD_LEN {
            return Err(Error::Header(HeaderError::PayloadTooLarge {
                provided: payload_len,
                max: Self::MAX_PAYLOAD_LEN,
            }));
        }

        self.total_len = Self::MIN_HEADER_LEN + payload_len;

        Ok(())
    }

    /// Returns the `identification` field of the IPv4 header.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns `true` if the `DF` (Don't Fragment) bit is set in the IPv4
    /// header.
    pub fn dont_fragment(&self) -> bool {
        // Stored at the 14th bit.
        (self.flags_and_offset >> 14) & 1 == 1
    }

    /// Returns `true` if the `MF` (More Fragments) bit is set in the IPv4
    /// header.
    pub fn more_fragments(&self) -> bool {
        // Stored at the 13th bit.
        (self.flags_and_offset >> 13) & 1 == 1
    }

    /// Returns the `fragment offset` field of the IPv4 header.
    pub fn fragment_offset(&self) -> u16 {
        // Stored in the lower 13 bits.
        self.flags_and_offset & 0x1FFF
    }

    /// Returns the `time to live` field of the IPv4 header.
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Returns the `protocol` field of the IPv4 header.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the `header checksum` field of the IPv4 header.
    pub fn header_checksum(&self) -> u16 {
        self.header_checksum
    }

    /// Computes and updates the header checksum for the IPv4 header.
    pub fn set_header_checksum(&mut self) {
        self.header_checksum = self.compute_header_checksum();
    }

    /// Returns `true` if the IPv4 header checksum is valid.
    pub fn is_valid_checksum(&self) -> bool {
        self.header_checksum == self.compute_header_checksum()
    }

    /// Returns the `source address` field of the IPv4 header.
    pub fn src(&self) -> [u8; 4] {
        self.src_addr
    }

    /// Returns the `destination address` field of the IPv4 header.
    pub fn dst(&self) -> [u8; 4] {
        self.dst_addr
    }

    /// Returns the length of the IPv4 header in bytes, not including payload.
    pub fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN as usize
    }

    /// Returns the payload length of the IPv4 header.
    pub fn payload_len(&self) -> u16 {
        // SAFETY: total_len >= (IHL << 2) is checked when parsing.
        self.total_len - Self::MIN_HEADER_LEN
    }

    /// Returns the computed checksum of the IPv4 header.
    ///
    /// The checksum algorithm is:
    ///
    /// The checksum field is the 16 bit one's complement of the one's
    /// complement sum of all 16 bit words in the header. For purposes of
    /// computing the checksum, the value of the checksum field is zero.
    pub fn compute_header_checksum(&self) -> u16 {
        let mut header_bytes = self.to_be_bytes();

        // Checksum field must be 0 for computation.
        header_bytes[10] = 0x00;
        header_bytes[11] = 0x00;

        let mut sum = 0u32;

        for i in (0..header_bytes.len()).step_by(2) {
            let word = u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]]);

            sum += word as u32;

            // Handle potential overflow with carry folding.
            if sum > 0xFFFF {
                // Adds the higher 16-bits to the lower 16-bits.
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        // Handle potential remaining overflow with carry folding.
        while sum > 0xFFFF {
            // Adds the higher 16-bits to the lower 16-bits.
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Returns the memory representation of the IPv4 header as a byte array in
    /// big-endian (network) byte order.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_be_bytes(&self) -> [u8; Self::MIN_HEADER_LEN as usize] {
        let mut raw_header = [0u8; Self::MIN_HEADER_LEN as usize];

        raw_header[0] = self.version_ihl;
        raw_header[1] = self.tos;
        raw_header[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        raw_header[4..6].copy_from_slice(&self.id.to_be_bytes());
        raw_header[6..8].copy_from_slice(&self.flags_and_offset.to_be_bytes());
        raw_header[8] = self.ttl;
        raw_header[9] = self.protocol.into();
        raw_header[10..12].copy_from_slice(&self.header_checksum.to_be_bytes());
        raw_header[12..16].copy_from_slice(&self.src_addr);
        raw_header[16..20].copy_from_slice(&self.dst_addr);

        raw_header
    }

    /// Reads an IPv4 header from the given input stream.
    pub fn read<T: io::Read>(input: &mut T) -> crate::Result<Self> {
        let mut raw_header = [0u8; Self::MIN_HEADER_LEN as usize];

        input.read_exact(&mut raw_header[..])?;
        Ipv4Header::try_from(&raw_header[..])
    }

    /// Writes the IPv4 header to the given output stream.
    ///
    /// # Note
    ///
    /// The caller must ensure the checksum is computed and updated before
    /// writing the header.
    pub fn write<T: io::Write>(&self, output: &mut T) -> crate::Result<()> {
        Ok(output.write_all(&self.to_be_bytes())?)
    }
}

impl TryFrom<&[u8]> for Ipv4Header {
    type Error = Error;

    fn try_from(header_raw: &[u8]) -> Result<Self, Self::Error> {
        if header_raw.len() < Self::MIN_HEADER_LEN as usize {
            return Err(Error::Parse(ParseError::InvalidBufferLength {
                provided: header_raw.len(),
                min: Self::MIN_HEADER_LEN,
                max: Self::MAX_HEADER_LEN,
            }));
        }

        let version_ihl = header_raw[0];

        if (version_ihl >> 4) != 4 {
            return Err(Error::Parse(ParseError::InvalidVersion {
                provided: version_ihl >> 4,
                expected: 4,
            }));
        }

        if (version_ihl & 0xF) != 5 {
            return Err(Error::Parse(ParseError::InvalidIhl {
                provided: version_ihl & 0xF,
                expected: 5,
            }));
        }

        Ok(Self {
            version_ihl,
            tos: header_raw[1],
            total_len: {
                let total_len = u16::from_be_bytes([header_raw[2], header_raw[3]]);

                // Total length is less than the header length.
                if total_len < ((version_ihl & 0xF) << 2) as u16 {
                    return Err(Error::Parse(ParseError::InvalidTotalLength {
                        provided: total_len,
                        expected: ((version_ihl & 0xF) << 2),
                    }));
                }

                total_len
            },
            id: u16::from_be_bytes([header_raw[4], header_raw[5]]),
            flags_and_offset: u16::from_be_bytes([header_raw[6], header_raw[7]]),
            ttl: header_raw[8],
            protocol: Protocol::try_from(header_raw[9])?,
            header_checksum: u16::from_be_bytes([header_raw[10], header_raw[11]]),
            src_addr: [
                header_raw[12],
                header_raw[13],
                header_raw[14],
                header_raw[15],
            ],
            dst_addr: [
                header_raw[16],
                header_raw[17],
                header_raw[18],
                header_raw[19],
            ],
        })
    }
}

impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            // Version = 4
            // IHL = 5
            version_ihl: 0b0100_0101,
            tos: 0,
            id: 0,
            // Bit 0 = 0 (Reserved)
            // Bit 1 = 1 (Don't Fragment)
            // Bit 2 = 0 (Last Fragment)
            //
            // Fragment Offset = 0
            flags_and_offset: 0b010_0000000000000,
            header_checksum: 0,

            total_len: Self::MIN_HEADER_LEN,
            ttl: 0,
            protocol: Protocol::TCP,
            src_addr: [0; 4],
            dst_addr: [0; 4],
        }
    }
}

/// Assigned Internet Protocol Numbers (RFC 1700).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    /// Internet Control Message
    ICMP = 1,
    /// Internet Group Management
    IGMP = 2,
    /// Gateway-to-Gateway
    GGP = 3,
    /// IP in IP (encapsulation)
    IP = 4,
    /// Stream
    ST = 5,
    /// Transmission Control
    TCP = 6,
    /// UCL
    UCL = 7,
    /// Exterior Gateway Protocol
    EGP = 8,
    /// Any private interior gateway
    IGP = 9,
    /// BBN RCC Monitoring
    BBN_RCC_MON = 10,
    /// Network Voice Protocol
    NVP_II = 11,
    /// PUP
    PUP = 12,
    /// ARGUS
    ARGUS = 13,
    /// EMCON
    EMCON = 14,
    /// Cross Net Debugger
    XNET = 15,
    /// Chaos
    CHAOS = 16,
    /// User Datagram
    UDP = 17,
    /// Multiplexing
    MUX = 18,
    /// DCN Measurement Subsystems
    DCN_MEAS = 19,
    /// Host Monitoring
    HMP = 20,
    /// Packet Radio Measurement
    PRM = 21,
    /// XEROX NS IDP
    XNS_IDP = 22,
    /// Trunk-1
    TRUNK_1 = 23,
    /// Trunk-2
    TRUNK_2 = 24,
    /// Leaf-1
    LEAF_1 = 25,
    /// Leaf-2
    LEAF_2 = 26,
    /// Reliable Data Protocol
    RDP = 27,
    /// Internet Reliable Transaction
    IRTP = 28,
    /// ISO Transport Protocol Class 4
    ISO_TP4 = 29,
    /// Bulk Data Transfer Protocol
    NETBLT = 30,
    /// MFE Network Services Protocol
    MFE_NSP = 31,
    /// MERIT Internodal Protocol
    MERIT_INP = 32,
    /// Sequential Exchange Protocol
    SEP = 33,
    /// Third Party Connect Protocol
    _3PC = 34,
    /// Inter-Domain Policy Routing Protocol
    IDPR = 35,
}

impl From<Protocol> for u8 {
    fn from(proto: Protocol) -> u8 {
        proto as u8
    }
}

impl TryFrom<u8> for Protocol {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Protocol::ICMP),
            2 => Ok(Protocol::IGMP),
            3 => Ok(Protocol::GGP),
            4 => Ok(Protocol::IP),
            5 => Ok(Protocol::ST),
            6 => Ok(Protocol::TCP),
            7 => Ok(Protocol::UCL),
            8 => Ok(Protocol::EGP),
            9 => Ok(Protocol::IGP),
            10 => Ok(Protocol::BBN_RCC_MON),
            11 => Ok(Protocol::NVP_II),
            12 => Ok(Protocol::PUP),
            13 => Ok(Protocol::ARGUS),
            14 => Ok(Protocol::EMCON),
            15 => Ok(Protocol::XNET),
            16 => Ok(Protocol::CHAOS),
            17 => Ok(Protocol::UDP),
            18 => Ok(Protocol::MUX),
            19 => Ok(Protocol::DCN_MEAS),
            20 => Ok(Protocol::HMP),
            21 => Ok(Protocol::PRM),
            22 => Ok(Protocol::XNS_IDP),
            23 => Ok(Protocol::TRUNK_1),
            24 => Ok(Protocol::TRUNK_2),
            25 => Ok(Protocol::LEAF_1),
            26 => Ok(Protocol::LEAF_2),
            27 => Ok(Protocol::RDP),
            28 => Ok(Protocol::IRTP),
            29 => Ok(Protocol::ISO_TP4),
            30 => Ok(Protocol::NETBLT),
            31 => Ok(Protocol::MFE_NSP),
            32 => Ok(Protocol::MERIT_INP),
            33 => Ok(Protocol::SEP),
            34 => Ok(Protocol::_3PC),
            35 => Ok(Protocol::IDPR),
            _ => Err(Error::Parse(ParseError::InvalidProtocol(val))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ipv4_header_parsing_no_panic(header_bytes in prop::collection::vec(any::<u8>(), 0..Ipv4Header::MAX_HEADER_LEN as usize)) {
            if let Ok(header) = Ipv4Header::try_from(&header_bytes[..]) {
                let bytes = header.to_be_bytes();
                if let Ok(header_parsed) = Ipv4Header::try_from(&bytes[..]) {
                    prop_assert_eq!(header, header_parsed);
                }
            }
        }
    }

    #[test]
    fn ipv4_header_basic_valid() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let mut header_bytes = &header_bytes[..];

        let header = Ipv4Header::read(&mut header_bytes);
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.tos(), 0);
        assert_eq!(header.total_len(), 60);
        assert_eq!(header.id(), 48890);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), Protocol::TCP);
        assert_eq!(header.header_checksum(), 0xFA43);
        assert_eq!(header.src(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst(), [192u8, 168u8, 0u8, 44u8]);
    }

    #[test]
    fn ipv4_header_round_trip_parsing_valid() {
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
        assert_eq!(header.total_len(), 60);
        assert_eq!(header.id(), 48890);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), Protocol::TCP);
        assert_eq!(header.header_checksum(), 0xFA43);
        assert_eq!(header.src(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst(), [192u8, 168u8, 0u8, 44u8]);

        let header_be_bytes = header.to_be_bytes();

        let header = Ipv4Header::try_from(&header_be_bytes[..]);
        assert!(header.is_ok());
        let header = header.unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.tos(), 0);
        assert_eq!(header.total_len(), 60);
        assert_eq!(header.id(), 48890);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), Protocol::TCP);
        assert_eq!(header.header_checksum(), 0xFA43);
        assert_eq!(header.src(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst(), [192u8, 168u8, 0u8, 44u8]);
    }

    #[test]
    fn ipv4_header_checksum_validation_valid() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        assert_eq!(header.header_checksum(), header.compute_header_checksum());

        // Invalidate checksum.
        header.set_payload_len(22).unwrap();

        assert_ne!(header.header_checksum(), header.compute_header_checksum());
    }

    #[test]
    fn ipv4_header_flags_bit_isolation_valid() {
        // Check if all permutations of DF and MF bits can be parsed.
        for flags in 0..=0b111 {
            let mut header_bytes: [u8; 20] = [
                0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
            ];

            header_bytes[6] = flags;

            let header = Ipv4Header::try_from(&header_bytes[..]);
            assert!(header.is_ok(),);
            let header = header.unwrap();

            assert_eq!(
                header.dont_fragment(),
                (flags & 0b01000000) != 0,
                "DF failed for {:06b}",
                flags
            );
            assert_eq!(
                header.more_fragments(),
                (flags & 0b00100000) != 0,
                "MF failed for {:06b}",
                flags
            );
        }
    }

    #[test]
    fn ipv4_header_fragment_offset_maximum_valid() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x5F, 0xFF, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_ok());

        assert_eq!(header.unwrap().fragment_offset(), 8191);
    }

    #[test]
    fn ipv4_header_buffer_length_invalid() {
        let header_bytes: [u8; 14] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_err());
    }

    #[test]
    fn ipv4_header_version_invalid() {
        let header_bytes: [u8; 20] = [
            0x65, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_err());
    }

    #[test]
    fn ipv4_header_ihl_invalid() {
        let header_bytes: [u8; 20] = [
            0x43, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_err());
    }

    #[test]
    fn ipv4_header_total_len_invalid() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x00, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_err());
    }
}
