use std::io;

use crate::parse::IPv4Header;

/// Representation of a TCP segment header (RFC 793 3.1).
///
/// ```text
///   0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |          Source Port          |       Destination Port        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                        Sequence Number                        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                    Acknowledgment Number                      |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |  Data |           |U|A|P|R|S|F|                               |
///    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
///    |       |           |G|K|H|T|N|N|                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |           Checksum            |         Urgent Pointer        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                    Options                    |    Padding    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                             data                              |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   
///                                Figure 3.
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TCPHeader {
    /// The source port number.
    src_port: u16,
    /// The destination port number.
    dst_port: u16,
    /// The sequence number of the first data octet in this segment
    /// (except when SYN is present). If SYN is present the sequence number is
    /// the initial sequence number (ISN) and the first data octet is ISN+1.
    seq_number: u32,
    /// If the ACK control bit is set this field contains the value of the next
    /// sequence number the sender of the segment is expecting to receive. Once
    /// a connection is established this is always sent.
    ack_number: u32,
    /// Data Offset: 4 bits
    ///
    /// The number of 32 bit words in the TCP Header. This indicates where the
    /// data begins. The TCP header (even one including options) is an integral
    /// number of 32 bits long.
    ///
    /// Reserved:  6 bits
    ///
    /// Reserved for future use.  Must be zero.
    ///
    /// Control Bits:  6 bits (from left to right):
    ///
    /// ```text
    ///    URG:  Urgent Pointer field significant
    ///    ACK:  Acknowledgment field significant
    ///    PSH:  Push Function
    ///    RST:  Reset the connection
    ///    SYN:  Synchronize sequence numbers
    ///    FIN:  No more data from sender
    /// ```
    offset_and_control_bits: u16,
    /// The number of data octets beginning with the one indicated in the
    /// acknowledgment field which the sender of this segment is willing to
    /// accept.
    window: u16,
    /// The checksum field is the 16 bit one's complement of the one's complement
    /// sum of all 16 bit words in the header and text. If a segment contains an
    /// odd number of header and text octets to be checksummed, the last octet is
    /// padded on the right with zeros to form a 16 bit word for checksum purposes.  
    /// The pad is not transmitted as part of the segment. While computing the
    /// checksum, the checksum field itself is replaced with zeros.
    ///
    /// The checksum also covers a 96 bit pseudo header conceptually prefixed to
    /// the TCP header. This pseudo header contains the Source Address, the
    /// Destination Address, the Protocol, and TCP length. This gives the TCP
    /// protection against misrouted segments. This information is carried in
    /// the Internet Protocol and is transferred across the TCP/Network interface
    /// in the arguments or results of calls by the TCP on the IP.
    ///
    /// ```text
    ///        +--------+--------+--------+--------+
    ///        |           Source Address          |
    ///        +--------+--------+--------+--------+
    ///        |         Destination Address       |
    ///        +--------+--------+--------+--------+
    ///        |  zero  |  PTCL  |    TCP Length   |
    ///        +--------+--------+--------+--------+
    /// ```
    ///
    /// The TCP Length is the TCP header length plus the data length in octets
    /// (this is not an explicitly transmitted quantity, but is computed), and
    /// it does not count the 12 octets of the pseudo header.
    checksum: u16,
    /// This field communicates the current value of the urgent pointer as a
    /// positive offset from the sequence number in this segment. The urgent
    /// pointer points to the sequence number of the octet following the urgent
    /// data. This field is only be interpreted in segments with the URG control
    /// bit set.
    urgent_pointer: u16,
    /// Options may occupy space at the end of the TCP header and are a
    /// multiple of 8 bits in length. All options are included in the checksum.
    ///
    /// Currently defined options include (kind indicated in octal):
    ///
    /// ```text
    ///      Kind     Length    Meaning
    ///      ----     ------    -------
    ///       0         -       End of option list.
    ///       1         -       No-Operation.
    ///       2         4       Maximum Segment Size.
    /// ```
    options: TCPOptions,
}

impl TCPHeader {
    /// Minimum length of an TCP header in bytes.
    pub const MIN_HEADER_LEN: u16 = 20;

    /// Minimum data offset of a TCP header.
    pub const MIN_DATA_OFFSET: u16 = 5;

    /// Maximum length of an TCP header in bytes.
    ///
    /// The Data Offset has a minimum value of 5 (20 bytes).
    ///
    /// Given its 4-bit representation:
    ///
    /// ```text
    ///     1001
    /// ```
    /// the maximum possible size for an TCP header is:
    ///
    /// ```text
    ///     1111
    /// ```
    ///
    /// which when converted to decimal, is 15 (60 bytes).
    pub const MAX_HEADER_LEN: u16 = 60;

    /// Maximum data offset of a TCP header.
    pub const MAX_DATA_OFFSET: u16 = 15;

    /// Length of the pseudo header, in bytes. Used in computing checksum.
    pub const PSEUDO_HEADER_LEN: usize = 12;

    /// Creates a new [TCPHeader] with the specified source and destination
    /// ports, initial sequence number (ISN), and window size, while setting
    /// default values for other fields.
    pub fn new(src_port: u16, dst_port: u16, seq_number: u32, window: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq_number,
            window,
            ..Default::default()
        }
    }

    /// Returns the Source Port field from the [TCPHeader].
    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    /// Returns the Destination Port field from the [TCPHeader].
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    /// Returns the Sequence Number field from the [TCPHeader].
    pub fn seq_number(&self) -> u32 {
        self.seq_number
    }

    /// Returns the Acknowledgment Number field from the [TCPHeader].
    pub fn ack_number(&self) -> u32 {
        self.ack_number
    }

    /// Sets the Acknowledgment Number field of the [TCPHeader] with the
    /// provided value.
    pub fn set_ack_number(&mut self, ack: u32) {
        self.ack_number = ack;
    }

    /// Returns the Data Offset field from the [TCPHeader].
    pub fn data_offset(&self) -> u8 {
        // Stored in the higher 4 bits.
        (self.offset_and_control_bits >> 12) as u8
    }

    /// Checks if the URG (Urgent) control bit is set in the [TCPHeader].
    pub fn urg(&self) -> bool {
        // Stored as the 5th bit from the LSB (counting from 0).
        (self.offset_and_control_bits >> 5) & 1 == 1
    }

    /// Sets the URG (Urgent) control bit in the [TCPHeader] if not already set.
    pub fn set_urg(&mut self) {
        // Sets the 5th bit from the LSB (counting from 0).
        self.offset_and_control_bits |= 1 << 5;
    }

    /// Checks if the ACK (Acknowledgment) control bit is set in the [TCPHeader].
    pub fn ack(&self) -> bool {
        // Stored as the 4th bit from the LSB (counting from 0).
        (self.offset_and_control_bits >> 4) & 1 == 1
    }

    /// Sets the ACK (Acknowledgment) control bit in the [TCPHeader] if not
    /// already set.
    pub fn set_ack(&mut self) {
        // Sets the 4th bit from the LSB (counting from 0).
        self.offset_and_control_bits |= 1 << 4;
    }

    /// Checks if the PSH (Push) control bit is set in the [TCPHeader].
    pub fn psh(&self) -> bool {
        // Stored as the 3rd bit from the LSB (counting from 0).
        (self.offset_and_control_bits >> 3) & 1 == 1
    }

    /// Sets the PSH (Push) control bit in the [TCPHeader] if not already set.
    pub fn set_psh(&mut self) {
        // Sets the 3rd bit from the LSB (counting from 0).
        self.offset_and_control_bits |= 1 << 3;
    }

    /// Checks if the RST (Reset) control bit is set in the [TCPHeader].
    pub fn rst(&self) -> bool {
        // Stored as the 2nd bit from the LSB (counting from 0).
        (self.offset_and_control_bits >> 2) & 1 == 1
    }

    /// Sets the RST (Reset) control bit in the [TCPHeader] if not already set.
    pub fn set_rst(&mut self) {
        // Sets the 2nd bit from the LSB (counting from 0).
        self.offset_and_control_bits |= 1 << 2;
    }

    /// Checks if the SYN (Synchronize) control bit is set in the [TCPHeader].
    pub fn syn(&self) -> bool {
        // Stored as the 1st bit from the LSB (counting from 0).
        (self.offset_and_control_bits >> 1) & 1 == 1
    }

    /// Sets the SYN (Synchronize) control bit in the [TCPHeader] if not already
    /// set.
    pub fn set_syn(&mut self) {
        // Sets the 1st bit from the LSB (counting from 0).
        self.offset_and_control_bits |= 1 << 1;
    }

    /// Checks if the FIN (Finish) control bit is set in the [TCPHeader].
    pub fn fin(&self) -> bool {
        // Stored as the LSB.
        self.offset_and_control_bits & 1 == 1
    }

    /// Sets the FIN (Finish) control bit in the [TCPHeader] if not already set.
    pub fn set_fin(&mut self) {
        // Sets the LSB.
        self.offset_and_control_bits |= 1;
    }

    /// Returns the Window field from the [TCPHeader].
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Returns the Checksum field from the [TCPHeader].
    pub fn checksum(&self) -> u16 {
        self.checksum
    }

    /// Computes and sets the Checksum field of the [TCPHeader] with the
    /// provided [IPv4Header] and payload.
    pub fn set_checksum(&mut self, ip_header: &IPv4Header, payload: &[u8]) {
        self.checksum = self.compute_checksum(ip_header, payload);
    }

    /// Returns the Urgent Pointer field from the [TCPHeader].
    pub fn urgent_pointer(&self) -> u16 {
        self.urgent_pointer
    }

    /// Returns the Options field from the [TCPHeader].
    pub fn options(&self) -> TCPOptions {
        self.options
    }

    /// Sets the Maximum Segment Size (MSS) value for the [TCPHeader].
    ///
    /// # Errors
    ///
    /// Returns an error if there is not enough space in the option buffer to
    /// append the MSS option.
    pub fn set_option_mss(&mut self, mss: u16) -> Result<(), String> {
        self.options.set_mss(mss)?;

        // Convert options length to the number of 32-bit words it represents,
        // and add it to the previous data offset.
        let new_data_offset = ((self.options.len() >> 2) as u8 + self.data_offset()) as u16;

        // Clear the higher 4-bits (clear previous data offset).
        self.offset_and_control_bits &= 0x0FFF;

        // Clear the higher 12-bits of the options length and shift the new
        // offset into the higher 4-bits, then combine with the previously
        // cleared offset.
        self.offset_and_control_bits |= (new_data_offset & 0x000F) << 12;

        Ok(())
    }

    /// Returns the length of the [TCPHeader] in bytes, including options.
    pub fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN as usize + self.options.len()
    }

    /// Computes the checksum for the [TCPHeader].
    ///
    /// The checksum algorithm is:
    ///
    /// The checksum field is the 16 bit one's complement of the one's
    /// complement sum of all 16 bit words in the pseudo header, TCP header,
    /// and payload. For purposes of computing the checksum, the value of the
    /// checksum field is zero.
    pub fn compute_checksum(&self, ip_header: &IPv4Header, payload: &[u8]) -> u16 {
        // Only copying 20 bytes...
        let mut tcp_header = *self;

        let mut pseudo_header = [0u8; Self::PSEUDO_HEADER_LEN];

        // RFC 793 (3.1)
        //
        // ```text
        //        +--------+--------+--------+--------+
        //        |           Source Address          |
        //        +--------+--------+--------+--------+
        //        |         Destination Address       |
        //        +--------+--------+--------+--------+
        //        |  zero  |  PTCL  |    TCP Length   |
        //        +--------+--------+--------+--------+
        // ```
        pseudo_header[0..4].copy_from_slice(&ip_header.src());
        pseudo_header[4..8].copy_from_slice(&ip_header.dst());
        pseudo_header[8] = 0;
        pseudo_header[9] = ip_header.protocol().into();

        let tcp_len: u16 = (tcp_header.header_len() + payload.len()) as u16;
        pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

        // Checksum field must be 0 for computation.
        tcp_header.checksum = 0;
        let tcp_header_bytes = tcp_header.to_be_bytes();
        let tcp_header_bytes = &tcp_header_bytes[..tcp_header.header_len()];

        // Chain together each byte slice so all word-sized values can be
        // summed.
        let mut checksum_iter = pseudo_header
            .iter()
            .chain(tcp_header_bytes.iter())
            .chain(payload.iter());

        let mut sum = 0u32;

        loop {
            match (checksum_iter.next(), checksum_iter.next()) {
                (Some(h), Some(l)) => {
                    let word = u16::from_be_bytes([*h, *l]);

                    sum += word as u32;

                    // Handle potential overflow for each add operation with carry
                    // folding.
                    if sum > 0xFFFF {
                        // Adds the higher 16-bits to the lower 16-bits.
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                (Some(h), None) => {
                    // If a segment contains an odd number of header and text
                    // octets to be checksummed, the last octet is padded on the
                    // right with zeros to form a 16 bit word for checksum purposes.
                    let word = u16::from_be_bytes([*h, 0x00]);

                    sum += word as u32;

                    // Handle potential overflow for each add operation with carry
                    // folding.
                    if sum > 0xFFFF {
                        // Adds the higher 16-bits to the lower 16-bits.
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                // Covers (None, Some(l)) and (None, None) cases.
                _ => {
                    break;
                }
            }
        }

        // Handle any remaining overflow with carry folding.
        while sum > 0xFFFF {
            // Adds the higher 16-bits to the lower 16-bits.
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Returns the memory representation of the [TCPHeader] as a byte array in
    /// big-endian (network) byte order.
    pub fn to_be_bytes(&self) -> [u8; Self::MAX_HEADER_LEN as usize] {
        let mut raw_header = [0u8; Self::MAX_HEADER_LEN as usize];

        raw_header[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        raw_header[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        raw_header[4..8].copy_from_slice(&self.seq_number.to_be_bytes());
        raw_header[8..12].copy_from_slice(&self.ack_number.to_be_bytes());
        raw_header[12..14].copy_from_slice(&self.offset_and_control_bits.to_be_bytes());
        raw_header[14..16].copy_from_slice(&self.window.to_be_bytes());
        raw_header[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        raw_header[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());

        raw_header[20..self.header_len()].copy_from_slice(self.options.as_slice());

        raw_header
    }

    /// Reads the [TCPHeader] from the given input stream.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the input stream fails or invalid data
    /// is provided.
    pub fn read<T: io::Read>(input: &mut T) -> Result<Self, String> {
        let mut raw_header = [0u8; Self::MAX_HEADER_LEN as usize];
        input
            .read_exact(&mut raw_header[..])
            .map_err(|err| format!("failed to parse TCP header from input: {err}"))?;

        TCPHeader::try_from(&raw_header[..])
    }

    /// Writes the [TCPHeader] to the given output stream.
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
            .write_all(&self.to_be_bytes()[..self.header_len()])
            .map_err(|err| format!("failed to write TCP header to output: {err}"))?;

        Ok(())
    }
}

impl TryFrom<&[u8]> for TCPHeader {
    type Error = String;

    fn try_from(header_raw: &[u8]) -> Result<Self, Self::Error> {
        if header_raw.len() < Self::MIN_HEADER_LEN as usize {
            return Err(format!(
                "failed to parse TCP header from input: expected header length to be greater than: {} provided header length: {}",
                Self::MIN_HEADER_LEN,
                header_raw.len()
            ));
        }

        let offset_and_control_bits = u16::from_be_bytes([header_raw[12], header_raw[13]]);

        let data_offset = offset_and_control_bits >> 12;
        if data_offset < Self::MIN_DATA_OFFSET {
            return Err(format!(
                "failed to parse TCP header from input: expected data offset to be greater than: {} provided data offset: {}",
                Self::MIN_DATA_OFFSET,
                data_offset
            ));
        }

        Ok(Self {
            src_port: u16::from_be_bytes([header_raw[0], header_raw[1]]),
            dst_port: u16::from_be_bytes([header_raw[2], header_raw[3]]),
            seq_number: u32::from_be_bytes([
                header_raw[4],
                header_raw[5],
                header_raw[6],
                header_raw[7],
            ]),
            ack_number: u32::from_be_bytes([
                header_raw[8],
                header_raw[9],
                header_raw[10],
                header_raw[11],
            ]),
            offset_and_control_bits,
            window: u16::from_be_bytes([header_raw[14], header_raw[15]]),
            checksum: u16::from_be_bytes([header_raw[16], header_raw[17]]),
            urgent_pointer: u16::from_be_bytes([header_raw[18], header_raw[19]]),
            options: {
                if data_offset > Self::MIN_DATA_OFFSET {
                    TCPOptions::try_from(&header_raw[20..(data_offset << 2) as usize])
                        .map_err(|err| format!("failed to parse TCP header from input: {err}"))?
                } else {
                    TCPOptions::new()
                }
            },
        })
    }
}

impl Default for TCPHeader {
    fn default() -> Self {
        Self {
            ack_number: 0,
            // Bits 0..4 (Data Offset) = 5
            //
            // Bits 4..10 (Reserved) = 0
            //
            // Bit 10 = 0 (URG)
            // Bit 11 = 0 (ACK)
            // Bit 12 = 0 (PSH)
            // Bit 13 = 0 (RST)
            // Bit 14 = 0 (SYN)
            // Bit 15 = 0 (FIN)
            offset_and_control_bits: 0b0101000000000000,
            checksum: 0,
            urgent_pointer: 0,
            options: Default::default(),

            src_port: 0,
            dst_port: 0,
            seq_number: 0,
            window: 0,
        }
    }
}

/// Representation of a TCP Options field in a [TCPHeader].
#[derive(Debug, Clone, Copy)]
pub struct TCPOptions {
    len: usize,
    buf: [u8; 40],
}

impl TCPOptions {
    /// Maximum length of TCP options in bytes.
    pub const MAX_OPTIONS_LEN: u16 = 40;

    /// Creates a new empty [TCPOptions].
    pub fn new() -> Self {
        Self {
            len: 0,
            buf: [0u8; 40],
        }
    }

    /// Returns the Maximum Segment Size (MSS) value from the [TCPOptions], if
    /// present.
    pub fn mss(&self) -> Option<u16> {
        let opts_slice = self.as_slice();

        for (i, byte) in opts_slice.iter().enumerate() {
            match (*byte).into() {
                OptionKind::EOL => {
                    return None;
                }
                OptionKind::NOP => {
                    continue;
                }
                OptionKind::MSS => {
                    // Read the actual MSS value.
                    //
                    // ```text
                    //          1        2        3         4
                    //        +--------+--------+---------+--------+
                    //        |00000010|00000100|   max seg size   |
                    //        +--------+--------+---------+--------+
                    //         ^                 ^^^^^^^^^^^^^^^^^^
                    //         |-- Here           Want these bytes
                    // ```
                    return Some(u16::from_be_bytes([opts_slice[i + 2], opts_slice[i + 3]]));
                }
            }
        }

        None
    }

    /// Sets the Maximum Segment Size (MSS) value for the [TCPOptions], appending
    /// it to the current options buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if there is not enough space in the option buffer to
    /// append the MSS option.
    pub fn set_mss(&mut self, mss: u16) -> Result<(), String> {
        let opts_len = self.len();

        if (opts_len + 4) as u16 > Self::MAX_OPTIONS_LEN {
            return Err(format!(
                "failed to append MSS option to buffer: buffer length if appended {}, maximum allowed buffer length: {}",
                opts_len + 4,
                Self::MAX_OPTIONS_LEN
            ));
        }

        let mut mss_option = [0u8; 4];

        mss_option[0] = OptionKind::MSS as u8;
        mss_option[1] = 0x04;
        mss_option[2..4].copy_from_slice(&mss.to_be_bytes());

        self.buf[opts_len..opts_len + 4].copy_from_slice(&mss_option);
        self.len += 4;

        Ok(())
    }

    /// Returns the length of the [TCPOptions] in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the [TCPOptions] contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns an immutable slice containing the [TCPOptions].
    pub fn as_slice(&self) -> &[u8] {
        debug_assert!(self.len <= 40);

        // SAFETY: Already verify self.len to be less then 40
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr(), self.len()) }
    }
}

impl TryFrom<&[u8]> for TCPOptions {
    type Error = String;

    fn try_from(byte_slice: &[u8]) -> Result<Self, Self::Error> {
        if byte_slice.len() > Self::MAX_OPTIONS_LEN as usize {
            return Err(format!(
                "expected options length to be less than: {} provided options length: {}",
                Self::MAX_OPTIONS_LEN,
                byte_slice.len()
            ));
        }

        let len = byte_slice.len();

        // Ensure options present are aligned to a 4-byte boundary.
        let padding = if len & 0b11 != 0 { 4 } else { 0 };

        Ok(Self {
            len: ((len >> 2) << 2) + padding,
            buf: {
                let mut buf = [0; 40];
                buf[..len].copy_from_slice(byte_slice);
                buf
            },
        })
    }
}

impl Default for TCPOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents the kinds of TCP options.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum OptionKind {
    /// End of Option List
    ///
    /// ```text
    ///        +--------+
    ///        |00000000|
    ///        +--------+
    ///         Kind=0
    /// ```
    ///
    /// This option code indicates the end of the option list. This might not
    /// coincide with the end of the TCP header according to the Data Offset
    /// field. This is used at the end of all options, not the end of each
    /// option, and need only be used if the end of the options would not
    /// otherwise coincide with the end of the TCP header.
    EOL = 0o00,
    /// No-Operation
    ///
    /// ```text
    ///        +--------+
    ///        |00000001|
    ///        +--------+
    ///         Kind=1
    /// ```
    ///
    /// This option code may be used between options, for example, to align the
    /// beginning of a subsequent option on a word boundary. There is no
    /// guarantee that senders will use this option, so receivers must be
    /// prepared to process options even if they do not begin on a word boundary.
    NOP = 0o01,
    /// Maximum Segment Size
    ///
    /// ```text
    ///        +--------+--------+---------+--------+
    ///        |00000010|00000100|   max seg size   |
    ///        +--------+--------+---------+--------+
    ///         Kind=2   Length=4
    /// ```
    ///
    /// Maximum Segment Size Option Data:  16 bits
    ///
    /// If this option is present, then it communicates the maximum receive
    /// segment size at the TCP which sends this segment. This field must only
    /// be sent in the initial connection request (i.e., in segments with the SYN control bit set).
    /// If this option is not used, any segment size is allowed.
    MSS = 0o02,
}

impl From<u8> for OptionKind {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::NOP,
            2 => Self::MSS,
            _ => Self::EOL,
        }
    }
}
