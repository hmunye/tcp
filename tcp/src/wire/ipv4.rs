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
/// [(RFC 791, Section 3.1)]: https://www.rfc-editor.org/rfc/rfc791#section-3.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// `Version` of the IP header (should be 4 for IPv4).
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
}

impl Ipv4Header {
    /// Minimum length of an IPv4 header in bytes (`IHL` = 5 words).
    pub const MIN_HEADER_LEN: u16 = 20;

    /// Maximum length of an IPv4 header in bytes.
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
    pub const MAX_HEADER_LEN: u16 = 60;

    /// Maximum IPv4 payload length in bytes, accounting for the header length.
    ///
    /// Since IPv4 options are not supported, header length is always
    /// [`Ipv4Header::MIN_HEADER_LEN`].
    pub const MAX_PAYLOAD_LEN: u16 = u16::MAX - Self::MIN_HEADER_LEN;

    /// Creates a new IPv4 header with the given source and destination
    /// addresses, payload length, `TTL`, and protocol. Other fields are set to
    /// their defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if `payload_len` exceeds [`Ipv4Header::MAX_PAYLOAD_LEN`].
    pub fn new(
        src: [u8; 4],
        dst: [u8; 4],
        payload_len: u16,
        ttl: u8,
        protocol: Protocol,
    ) -> Result<Self> {
        Ok(Self {
            // Version = 4, IHL = 5
            version_ihl: 0b0100_0101,
            tos: 0,
            total_length: Self::compute_total_length(payload_len)?,
            id: 0,
            //                   DF Fragment Offset
            //                   |        |
            //                   v        v
            flags_and_offset: 0b010_0000000000000,
            ttl,
            protocol,
            header_checksum: 0,
            src_addr: src,
            dst_addr: dst,
        })
    }

    /// Returns the `Version` field of the IPv4 header.
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Returns the `IHL` field of the IPv4 header, in 32-bit words.
    ///
    /// To get the header length in bytes, use [`Ipv4Header::header_len`].
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0xF
    }

    /// Returns the `Type of Service` field of the IPv4 header.
    pub fn tos(&self) -> u8 {
        self.tos
    }

    /// Returns the `Total Length` field of the IPv4 header.
    pub fn total_length(&self) -> u16 {
        self.total_length
    }

    /// Returns the `Identification` field of the IPv4 header.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns `true` if the IPv4 header's `DF` (Don't Fragment) flag is set.
    pub fn dont_fragment(&self) -> bool {
        (self.flags_and_offset >> 14) & 1 == 1
    }

    /// Returns `true` if the IPv4 header's `MF` (More Fragments) flag is set.
    pub fn more_fragments(&self) -> bool {
        (self.flags_and_offset >> 13) & 1 == 1
    }

    /// Returns the `Fragment Offset` field of the IPv4 header.
    pub fn fragment_offset(&self) -> u16 {
        self.flags_and_offset & 0x1FFF
    }

    /// Returns the `Time to Live` field of the IPv4 header.
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Returns the `Protocol` field of the IPv4 header.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the `Header Checksum` field of the IPv4 header.
    pub fn header_checksum(&self) -> u16 {
        self.header_checksum
    }

    /// Returns the `Source Address` field of the IPv4 header.
    pub fn src(&self) -> [u8; 4] {
        self.src_addr
    }

    /// Returns the `Destination Address` field of the IPv4 header.
    pub fn dst(&self) -> [u8; 4] {
        self.dst_addr
    }

    /// Sets the `Total Length` field of the IPv4 header given a payload length.
    ///
    /// # Errors
    ///
    /// Returns an error if `payload_len` exceeds [`Ipv4Header::MAX_PAYLOAD_LEN`].
    pub fn set_payload_len(&mut self, payload_len: u16) -> Result<()> {
        self.total_length = Self::compute_total_length(payload_len)?;
        Ok(())
    }

    /// Computes and sets the IPv4 `Header Checksum` field.
    pub fn set_header_checksum(&mut self) {
        self.header_checksum = self.compute_header_checksum();
    }

    /// Returns `true` if the IPv4 `Header Checksum` field is valid.
    pub fn is_valid_checksum(&self) -> bool {
        self.header_checksum == self.compute_header_checksum()
    }

    /// Returns the length of the IPv4 header in bytes (excluding payload).
    pub fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN as usize
    }

    /// Returns the payload length (excluding the IPv4 header).
    pub fn payload_len(&self) -> u16 {
        debug_assert!(
            self.total_length >= Self::MIN_HEADER_LEN,
            "total_length: {}, less than the minimum IPv4 header length: {}",
            self.total_length,
            Self::MIN_HEADER_LEN
        );

        self.total_length - Self::MIN_HEADER_LEN
    }

    /// Computes the IPv4 header checksum.
    ///
    /// The checksum is the 16-bit one's complement of the one's complement sum
    /// of all 16-bit words in the header. The checksum field itself is treated
    /// as zero during computation.
    pub fn compute_header_checksum(&self) -> u16 {
        let mut header_bytes = self.to_bytes();

        // Zero-out checksum field, based on layout of IPv4 header.
        header_bytes[10] = 0x00;
        header_bytes[11] = 0x00;

        let mut sum = 0u32;

        for i in (0..header_bytes.len()).step_by(2) {
            let word = u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]]);

            sum += word as u32;

            // Handle potential overflow with carry folding.
            if sum > 0xFFFF {
                // Add the higher 16-bits to the lower 16-bits.
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        // Handle any remaining overflow with carry folding.
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Returns the memory representation of the IPv4 header as a byte array in
    /// big-endian (network) byte order.
    pub fn to_bytes(&self) -> [u8; Self::MIN_HEADER_LEN as usize] {
        let mut raw_header = [0u8; Self::MIN_HEADER_LEN as usize];

        raw_header[0] = self.version_ihl;
        raw_header[1] = self.tos;
        raw_header[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        raw_header[4..6].copy_from_slice(&self.id.to_be_bytes());
        raw_header[6..8].copy_from_slice(&self.flags_and_offset.to_be_bytes());
        raw_header[8] = self.ttl;
        raw_header[9] = self.protocol.into();
        raw_header[10..12].copy_from_slice(&self.header_checksum.to_be_bytes());
        raw_header[12..16].copy_from_slice(&self.src_addr);
        raw_header[16..20].copy_from_slice(&self.dst_addr);

        raw_header
    }

    /// Parses an IPv4 header from the given reader.
    ///
    /// Reads exactly [`Ipv4Header::MIN_HEADER_LEN`] bytes and attempts to
    /// construct an IPv4 header.
    pub fn read<T: std::io::Read>(r: &mut T) -> Result<Self> {
        let mut raw_header = [0u8; Self::MIN_HEADER_LEN as usize];

        r.read_exact(&mut raw_header[..])?;
        Ipv4Header::try_from(&raw_header[..])
    }

    /// Writes the IPv4 header to the given writer.
    ///
    /// It is the callers responsibility to ensure the header checksum is
    /// [`set`] before writing the header.
    ///
    /// [`set`]: Ipv4Header::set_header_checksum
    pub fn write<T: std::io::Write>(&self, w: &mut T) -> Result<()> {
        Ok(w.write_all(&self.to_bytes())?)
    }

    fn compute_total_length(payload_len: u16) -> Result<u16> {
        Self::MIN_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(Error::Header(HeaderError::PayloadTooLarge {
                provided: payload_len,
                max: Self::MAX_PAYLOAD_LEN,
            }))
    }
}

#[cfg(all(test, not(miri)))]
impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            // Version = 4, IHL = 5
            version_ihl: 0b0100_0101,
            tos: 0,
            total_length: Self::MIN_HEADER_LEN,
            id: 0,
            //                   DF Fragment Offset
            //                   |        |
            //                   v        v
            flags_and_offset: 0b010_0000000000000,
            ttl: 0,
            protocol: Protocol::TCP,
            header_checksum: 0,
            src_addr: [0u8; 4],
            dst_addr: [0u8; 4],
        }
    }
}

impl TryFrom<&[u8]> for Ipv4Header {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> core::result::Result<Self, Self::Error> {
        if bytes.len() < Self::MIN_HEADER_LEN as usize {
            return Err(Error::Parse(ParseError::InvalidBufferLength {
                provided: bytes.len(),
                min: Self::MIN_HEADER_LEN,
                max: Self::MAX_HEADER_LEN,
            }));
        }

        let version_ihl = bytes[0];

        if (version_ihl >> 4) != 4 {
            return Err(Error::Parse(ParseError::InvalidVersion {
                provided: version_ihl >> 4,
                expected: 4,
            }));
        }

        let ihl_words = version_ihl & 0xF;
        let ihl_min = (Ipv4Header::MIN_HEADER_LEN >> 2) as u8;
        let ihl_max = (Ipv4Header::MAX_HEADER_LEN >> 2) as u8;

        // Valid IPv4 headers may include options (`IHL` 6..=15), even though
        // the options are not parsed.
        if !(ihl_min..=ihl_max).contains(&ihl_words) {
            return Err(Error::Parse(ParseError::InvalidIhl {
                provided: ihl_words,
                min: ihl_min,
                max: ihl_max,
            }));
        }

        Ok(Self {
            version_ihl,
            tos: bytes[1],
            total_length: {
                let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
                let header_length = ihl_words << 2;

                if total_length < header_length as u16 {
                    return Err(Error::Parse(ParseError::InvalidTotalLength {
                        provided: total_length,
                        expected: header_length,
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
        })
    }
}

/// Assigned Internet Protocol Numbers [(RFC 1700)].
///
/// [(RFC 1700)]: https://www.rfc-editor.org/rfc/rfc1700
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
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
    /// XTP
    XTP = 36,
    /// Datagram Delivery Protocol
    DDP = 37,
    /// IDPR Control Message Transport Protocol
    IDPR_CMTP = 38,
    /// TP++ Transport Protocol
    TP_PLUS = 39,
    /// IL Transport Protocol
    IL = 40,
    /// Simple Internet Protocol
    SIP = 41,
    /// Source Demand Routing Protocol
    SDRP = 42,
    /// SIP Source Route
    SIP_SR = 43,
    /// SIP Fragment
    SIP_FRAG = 44,
    /// Inter-Domain Routing Protocol
    IDRP = 45,
    /// Reservation Protocol
    RSVP = 46,
    /// General Routing Encapsulation
    GRE = 47,
    /// Mobile Host Routing Protocol
    MHRP = 48,
    /// BNA
    BNA = 49,
    /// SIPP Encap Security Payload
    SIPP_ESP = 50,
    /// SIPP Authentication Header
    SIPP_AH = 51,
    /// Integrated Net Layer Security (TUBA)
    I_NLSP = 52,
    /// IP with Encryption (SWIPE)
    SWIPE = 53,
    /// NBMA Next Hop Resolution Protocol
    NHRP = 54,
    /// Any host internal protocol
    HOST = 61,
    /// CFTP
    CFTP = 62,
    /// Any local network
    LAN = 63,
    /// SATNET and Backroom EXPAK
    SAT_EXPAK = 64,
    /// Kryptolan
    KRYPTOLAN = 65,
    /// MIT Remote Virtual Disk Protocol
    RVD = 66,
    /// Internet Pluribus Packet Core
    IPPC = 67,
    /// Any distributed file system
    DIST_FS = 68,
    /// SATNET Monitoring
    SAT_MON = 69,
    /// VISA Protocol
    VISA = 70,
    /// Internet Packet Core Utility
    IPCV = 71,
    /// Computer Protocol Network Executive
    CPNX = 72,
    /// Computer Protocol Heart Beat
    CPHB = 73,
    /// Wang Span Network
    WSN = 74,
    /// Packet Video Protocol
    PVP = 75,
    /// Backroom SATNET Monitoring
    BR_SAT_MON = 76,
    /// SUN ND PROTOCOL-Temporary
    SUN_ND = 77,
    /// WIDEBAND Monitoring
    WB_MON = 78,
    /// WIDEBAND EXPAK
    WB_EXPAK = 79,
    /// ISO Internet Protocol
    ISO_IP = 80,
    /// VMTP
    VMTP = 81,
    /// SECURE-VMTP
    SECURE_VMTP = 82,
    /// VINES
    VINES = 83,
    /// TTP
    TTP = 84,
    /// NSFNET-IGP
    NSFNET_IGP = 85,
    /// Dissimilar Gateway Protocol
    DGP = 86,
    /// TCF
    TCF = 87,
    /// IGRP
    IGRP = 88,
    /// OSPFIGP
    OSPFIGP = 89,
    /// Sprite RPC Protocol
    SPRITE_RPC = 90,
    /// Locus Address Resolution Protocol
    LARP = 91,
    /// Multicast Transport Protocol
    MTP = 92,
    /// AX.25 Frames
    AX25 = 93,
    /// IP-within-IP Encapsulation Protocol
    IPIP = 94,
    /// Mobile Internetworking Control Protocol
    MICP = 95,
    /// Semaphore Communications Sec. Protocol
    SCC_SP = 96,
    /// Ethernet-within-IP Encapsulation
    ETHERIP = 97,
    /// Encapsulation Header
    ENCAP = 98,
    /// Any private encryption scheme
    PRIVATE_ENC = 99,
    /// GMTP
    GMTP = 100,

    Unassigned,
    Reserved,
}

impl From<Protocol> for u8 {
    fn from(proto: Protocol) -> u8 {
        proto as u8
    }
}

impl TryFrom<u8> for Protocol {
    type Error = Error;

    fn try_from(proto: u8) -> core::result::Result<Self, Self::Error> {
        use Protocol::*;

        let protocol = match proto {
            0 | 255 => Reserved,
            // SAFETY: `1..=54` and `61..=100` are defined as `#[repr(u8)]`
            // variants in `Protocol`.
            1..=54 | 61..=100 => unsafe { std::mem::transmute::<u8, Protocol>(proto) },
            55..=60 | 101..=254 => Unassigned,
        };

        match protocol {
            Unassigned | Reserved => Err(Error::Parse(ParseError::InvalidProtocol(protocol))),
            _ => Ok(protocol),
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
        fn ipv4_header_parsing_prop(header_bytes in prop::collection::vec(any::<u8>(), 0..Ipv4Header::MAX_HEADER_LEN as usize)) {
            if let Ok(header) = Ipv4Header::try_from(&header_bytes[..]) {
                let bytes = header.to_bytes();
                if let Ok(header_parsed) = Ipv4Header::try_from(&bytes[..]) {
                    prop_assert_eq!(header, header_parsed);
                }
            }
        }
    }

    #[test]
    fn ipv4_header_valid() {
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
        assert_eq!(header.total_length(), 60);
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
    fn ipv4_header_round_trip_parsing() {
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
        assert_eq!(header.src(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst(), [192u8, 168u8, 0u8, 44u8]);

        let header_be_bytes = header.to_bytes();

        let header = Ipv4Header::try_from(&header_be_bytes[..]);
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
        assert_eq!(header.src(), [192u8, 168u8, 0u8, 1u8]);
        assert_eq!(header.dst(), [192u8, 168u8, 0u8, 44u8]);
    }

    #[test]
    fn ipv4_header_checksum_validation() {
        let header_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0xbe, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xfa, 0x43, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0x2c,
        ];

        let header = Ipv4Header::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        assert_eq!(header.header_checksum(), header.compute_header_checksum());

        // Invalidate header checksum.
        header.set_payload_len(22).unwrap();

        assert_ne!(header.header_checksum(), header.compute_header_checksum());
    }

    #[test]
    fn ipv4_header_flags_bit_isolation() {
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
    fn ipv4_header_fragment_offset_maximum() {
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
