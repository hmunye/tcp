use std::io;

/// Representation of an IPv4 datagram header (RFC 791 3.1).
///
/// ```text
///   0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |Version|  IHL  |Type of Service|          Total Length         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         Identification        |Flags|      Fragment Offset    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  Time to Live |    Protocol   |         Header Checksum       |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       Source Address                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Destination Address                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Options                    |    Padding    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///                               Figure 4.
/// ```
///
/// This implementation omits options (IHL is always 5).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IPv4Header {
    /// The Version field indicates the format of the internet header.
    ///
    /// Internet Header Length is the length of the internet header in 32 bit
    /// words, and thus points to the beginning of the data. Note that the
    /// minimum value for a correct header is 5.
    version_ihl: u8,
    /// The Type of Service provides an indication of the abstract parameters
    /// of the quality of service desired. These parameters are to be used to
    /// guide the selection of the actual service parameters when transmitting a
    /// datagram through a particular network. Several networks offer service
    /// precedence, which somehow treats high precedence traffic as more
    /// important than other traffic (generally by accepting only traffic above
    /// a certain precedence at time of high load). The major choice is a three
    /// way tradeoff between low-delay, high-reliability, and high-throughput.
    ///
    /// ```text
    ///      Bits 0-2:  Precedence.
    ///      Bit    3:  0 = Normal Delay,      1 = Low Delay.
    ///      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
    ///      Bits   5:  0 = Normal Reliability, 1 = High Reliability.
    ///      Bit  6-7:  Reserved for Future Use.
    ///
    ///         0     1     2     3     4     5     6     7
    ///      +-----+-----+-----+-----+-----+-----+-----+-----+
    ///      |                 |     |     |     |     |     |
    ///      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
    ///      |                 |     |     |     |     |     |
    ///      +-----+-----+-----+-----+-----+-----+-----+-----+
    ///
    ///        Precedence
    ///
    ///          111 - Network Control
    ///          110 - Internetwork Control
    ///          101 - CRITIC/ECP
    ///          100 - Flash Override
    ///          011 - Flash
    ///          010 - Immediate
    ///          001 - Priority
    ///          000 - Routine
    /// ```
    tos: u8,
    /// Total Length is the length of the datagram, measured in octets,
    /// including internet header and data. This field allows the length of a
    /// datagram to be up to 65,535 octets [u16::MAX].
    total_len: u16,
    /// An identifying value assigned by the sender to aid in assembling the
    /// fragments of a datagram.
    id: u16,
    /// Various Control Flags.
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
    /// Fragment offset indicates where in the datagram this fragment belongs.
    /// The fragment offset is measured in units of 8 octets (64 bits). The
    /// first fragment has offset zero.
    flags_and_offset: u16,
    /// This field indicates the maximum time the datagram is allowed to remain
    /// in the internet system.  If this field contains the value zero, then the
    /// datagram must be destroyed.  This field is modified in internet header
    /// processing.  The time is measured in units of seconds, but since every
    /// module that processes a datagram must decrease the TTL by at least one
    /// even if it process the datagram in less than a second, the TTL must be
    /// thought of only as an upper bound on the time a datagram may exist.
    ttl: u8,
    /// This field indicates the next level protocol used in the data portion of
    /// the internet datagram.
    protocol: Protocol,
    /// A checksum on the header only. Since some header fields change
    /// (e.g., time to live), this is recomputed and verified at each point that
    /// the internet header is processed.
    pub(crate) header_checksum: u16,
    /// The source address.
    src_addr: [u8; 4],
    /// The destination address.
    dst_addr: [u8; 4],
}

impl IPv4Header {
    /// Minimum length of an IPv4 header in bytes.
    pub const MIN_HEADER_LEN: u16 = 20;

    /// Maximum length of an IPv4 header in bytes.
    ///
    /// The IHL (Internet Header Length) has a minimum value of 5 (20 bytes).
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
    /// which when converted to decimal, is 15 (60 bytes).
    pub const MAX_HEADER_LEN: u16 = 60;

    /// Maximum payload length in bytes.
    pub const MAX_PAYLOAD_LEN: u16 = u16::MAX - Self::MIN_HEADER_LEN;

    /// Creates a new [IPv4Header] with the specified source and destination
    /// IPs, payload length, TTL, and protocol, while setting default values
    /// for other fields.
    ///
    /// # Errors
    ///
    /// Returns an error if the `payload_len` exceeds [IPv4Header::MAX_PAYLOAD_LEN].
    pub fn new(
        src: [u8; 4],
        dst: [u8; 4],
        payload_len: u16,
        ttl: u8,
        protocol: Protocol,
    ) -> Result<Self, String> {
        if payload_len > Self::MAX_PAYLOAD_LEN {
            return Err(format!(
                "failed to create IPv4 header. provided payload length: {} maximum allowed payload length: {}",
                payload_len,
                Self::MAX_PAYLOAD_LEN
            ));
        }

        Ok(Self {
            total_len: payload_len + Self::MIN_HEADER_LEN,
            ttl,
            protocol,
            src_addr: src,
            dst_addr: dst,
            ..Default::default()
        })
    }

    /// Returns the Version field from the [IPv4Header].
    pub fn version(&self) -> u8 {
        // Stored in the higher 4 bits.
        self.version_ihl >> 4
    }

    /// Returns the IHL (Internet Header Length) field from the [IPv4Header].
    ///
    /// The IHL specifies the header length in 32-bit (4-byte) words.
    pub fn ihl(&self) -> u8 {
        // Stored in the lower 4 bits.
        self.version_ihl & 0xF
    }

    /// Returns the Type of Service field from the [IPv4Header].
    pub fn tos(&self) -> u8 {
        self.tos
    }

    /// Returns the Total Length field from the [IPv4Header].
    pub fn total_len(&self) -> u16 {
        self.total_len
    }

    /// Returns the Identification field from the [IPv4Header].
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Checks if the DF (Don't Fragment) bit is set in the [IPv4Header].
    pub fn dont_fragment(&self) -> bool {
        // Stored as the second bit (counting from the MSB).
        (self.flags_and_offset >> 14) & 1 == 1
    }

    /// Checks if the MF (More Fragment) bit is set in the [IPv4Header].
    pub fn more_fragments(&self) -> bool {
        // Stored as the third bit (counting from the MSB).
        (self.flags_and_offset >> 13) & 1 == 1
    }

    /// Returns the Fragment Offset field from the [IPv4Header].
    pub fn fragment_offset(&self) -> u16 {
        // Stored in the lower 13 bits.
        self.flags_and_offset & 0x1FFF
    }

    /// Returns the Time to Live field from the [IPv4Header].
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Returns the Protocol field from the [IPv4Header].
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the Header Checksum field from the [IPv4Header].
    pub fn header_checksum(&self) -> u16 {
        self.header_checksum
    }

    /// Returns the Source Address field from the [IPv4Header].
    pub fn src(&self) -> [u8; 4] {
        self.src_addr
    }

    /// Returns the Destination Address field from the [IPv4Header].
    pub fn dst(&self) -> [u8; 4] {
        self.dst_addr
    }

    /// Returns the length of the [IPv4Header], not including the payload.
    pub fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN as usize
    }

    /// Determine the payload length of the [IPv4Header].
    ///
    /// # Errors
    ///
    /// Returns an error if `total_len` is smaller than [IPv4Header::MIN_HEADER_LEN].
    pub fn payload_len(&self) -> Result<u16, String> {
        if self.total_len < Self::MIN_HEADER_LEN {
            return Err(format!(
                "failed to determine payload length of IPv4 header: total length: {} minimum header length: {}",
                self.total_len,
                Self::MIN_HEADER_LEN
            ));
        }

        Ok(self.total_len - Self::MIN_HEADER_LEN)
    }

    /// Updates the [IPv4Header::total_len] field given the new payload length.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the `payload_len` exceeds [IPv4Header::MAX_PAYLOAD_LEN].
    pub fn set_payload_len(&mut self, payload_len: u16) -> Result<(), String> {
        if payload_len > Self::MAX_PAYLOAD_LEN {
            return Err(format!(
                "failed to update total_len field for IPv4 header. new payload length: {} maximum allowed payload length: {}",
                payload_len,
                Self::MAX_PAYLOAD_LEN
            ));
        }

        self.total_len = Self::MIN_HEADER_LEN + payload_len;

        Ok(())
    }

    /// Computes the header checksum for the [IPv4Header].
    ///
    /// The checksum algorithm is:
    ///
    /// The checksum field is the 16 bit one's complement of the one's
    /// complement sum of all 16 bit words in the header. For purposes of
    /// computing the checksum, the value of the checksum field is zero.
    pub fn compute_header_checksum(&self) -> u16 {
        // Only copying 20 bytes...
        let mut header = *self;

        // Checksum field must be 0 for computation.
        header.header_checksum = 0;
        // Must be in big-endian byte order.
        let header_bytes = header.to_be_bytes();

        let mut sum = 0u32;

        // The IPv4 header structure is already compile-time to be the minimum
        // IHL (20 bytes).
        for i in (0..header_bytes.len()).step_by(2) {
            let word = u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]]);

            sum += word as u32;

            // Handle potential overflow for each add operation with carry
            // folding.
            if sum > 0xFFFF {
                // Adds the higher 16-bits to the lower 16-bits.
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        // Handle any remaining overflow with carry folding.
        while sum > 0xFFFF {
            // Adds the higher 16-bits to the lower 16-bits.
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Returns the memory representation of the [IPv4Header] as a byte array in
    /// big-endian (network) byte order.
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

    /// Reads the [IPv4Header] from the given input stream.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the input stream fails or invalid data
    /// is provided.
    pub fn read<T: io::Read>(input: &mut T) -> Result<Self, String> {
        let mut raw_header = [0u8; Self::MIN_HEADER_LEN as usize];
        input
            .read_exact(&mut raw_header[..])
            .map_err(|err| format!("failed to parse IPv4 header from input: {err}"))?;

        IPv4Header::try_from(&raw_header[..])
    }

    /// Writes the [IPv4Header] to the given output stream.
    ///
    /// # Notes
    ///
    /// The checksum is NOT automatically computed. It is the callers
    /// responsibility to ensure the checksum is computed before writing to an
    /// output stream.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the output stream fails.
    pub fn write<T: io::Write>(&self, output: &mut T) -> Result<(), String> {
        output
            .write_all(&self.to_be_bytes())
            .map_err(|err| format!("failed to write IPv4 header to output: {err}"))?;

        Ok(())
    }
}

impl TryFrom<&[u8]> for IPv4Header {
    type Error = String;

    fn try_from(header_raw: &[u8]) -> Result<Self, Self::Error> {
        if header_raw.len() < Self::MIN_HEADER_LEN as usize {
            return Err(format!(
                "failed to parse IPv4 header from input: expected header length: {} provided header length: {}",
                Self::MIN_HEADER_LEN,
                header_raw.len()
            ));
        }

        let version_ihl = header_raw[0];

        if (version_ihl >> 4) != 4 {
            return Err(format!(
                "failed to parse into IPv4 header from input: expected version number: 4 provided version number: {}",
                version_ihl >> 4
            ));
        }

        if (version_ihl & 0xF) != 5 {
            return Err(format!(
                "failed to parse into IPv4 header from input: expected ihl value: 5 provided ihl value: {}",
                version_ihl & 0xF
            ));
        }

        Ok(Self {
            version_ihl,
            tos: header_raw[1],
            total_len: u16::from_be_bytes([header_raw[2], header_raw[3]]),
            id: u16::from_be_bytes([header_raw[4], header_raw[5]]),
            flags_and_offset: u16::from_be_bytes([header_raw[6], header_raw[7]]),
            ttl: header_raw[8],
            protocol: Protocol::try_from(header_raw[9])
                .map_err(|err| format!("failed to parse into IPv4 header from input: {err}"))?,
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

impl Default for IPv4Header {
    fn default() -> Self {
        Self {
            version_ihl: 0b01000101, // Version = 4, IHL = 5
            tos: 0,
            id: 0,
            // Bit 0 = 0 (Reserved)
            // Bit 1 = 1 (Don't Fragment)
            // Bit 2 = 0 (Last Fragment)
            //
            // Fragment Offset = 0
            flags_and_offset: 0b0100000000000000,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
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
    type Error = String;

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
            _ => Err(format!("provided invalid protocol number: {val}")),
        }
    }
}
