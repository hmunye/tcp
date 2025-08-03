use std::io;

use super::Ipv4Header;

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
/// ```
#[repr(C)]
#[derive(Debug)]
pub struct TcpHeader {
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
    /// The checksum field is the 16 bit one's complement of the one's
    /// complement sum of all 16 bit words in the header and text. If a segment
    /// contains an odd number of header and text octets to be checksummed, the
    /// last octet is padded on the right with zeros to form a 16 bit word for
    /// checksum purposes. The pad is not transmitted as part of the segment.
    /// While computing the checksum, the checksum field itself is replaced with
    /// zeros.
    ///
    /// The checksum also covers a 96 bit pseudo header conceptually prefixed to
    /// the TCP header. This pseudo header contains the Source Address, the
    /// Destination Address, the Protocol, and TCP length. This gives the TCP
    /// protection against misrouted segments. This information is carried in
    /// the Internet Protocol and is transferred across the TCP/Network
    /// interface in the arguments or results of calls by the TCP on the IP.
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
    options: TcpOptions,
}

impl TcpHeader {
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

    /// Creates a new TCP header with the specified source and destination
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

    /// Returns the Source Port field from the TCP header.
    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    /// Returns the Destination Port field from the TCP header.
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    /// Returns the Sequence Number field from the TCP header.
    pub fn seq_number(&self) -> u32 {
        self.seq_number
    }

    /// Returns the Acknowledgment Number field from the TCP header.
    pub fn ack_number(&self) -> u32 {
        self.ack_number
    }

    /// Sets the Acknowledgment Number field of the TCP header with the provided
    /// value.
    pub fn set_ack_number(&mut self, ack: u32) {
        self.ack_number = ack;
    }

    /// Returns the Data Offset field from the TCP header.
    pub fn data_offset(&self) -> u8 {
        // Stored in the higher 4 bits.
        (self.offset_and_control_bits >> 12) as u8
    }

    /// Returns `true` if the URG (Urgent) control bit is set in the TCP header.
    pub fn urg(&self) -> bool {
        // Stored as the 5th bit from the LSB.
        (self.offset_and_control_bits >> 5) & 1 == 1
    }

    /// Sets the URG (Urgent) control bit in the TCP header, if not already set.
    pub fn set_urg(&mut self) {
        // Sets the 5th bit from the LSB.
        self.offset_and_control_bits |= 1 << 5;
    }

    /// Returns `true` if the ACK (Acknowledgment) control bit is set in the TCP
    /// header.
    pub fn ack(&self) -> bool {
        // Stored as the 4th bit from the LSB.
        (self.offset_and_control_bits >> 4) & 1 == 1
    }

    /// Sets the ACK (Acknowledgment) control bit in the TCP header, if not
    /// already set.
    pub fn set_ack(&mut self) {
        // Sets the 4th bit from the LSB.
        self.offset_and_control_bits |= 1 << 4;
    }

    /// Returns `true` if the PSH (Push) control bit is set in the TCP header.
    pub fn psh(&self) -> bool {
        // Stored as the 3rd bit from the LSB.
        (self.offset_and_control_bits >> 3) & 1 == 1
    }

    /// Sets the PSH (Push) control bit in the TCP header, if not already set.
    pub fn set_psh(&mut self) {
        // Sets the 3rd bit from the LSB.
        self.offset_and_control_bits |= 1 << 3;
    }

    /// Returns `true` if the RST (Reset) control bit is set in the TCP header.
    pub fn rst(&self) -> bool {
        // Stored as the 2nd bit from the LSB.
        (self.offset_and_control_bits >> 2) & 1 == 1
    }

    /// Sets the RST (Reset) control bit in the TCP header, if not already set.
    pub fn set_rst(&mut self) {
        // Sets the 2nd bit from the LSB.
        self.offset_and_control_bits |= 1 << 2;
    }

    /// Returns `true` if the SYN (Synchronize) control bit is set in the TCP
    /// header.
    pub fn syn(&self) -> bool {
        // Stored as the 1st bit from the LSB.
        (self.offset_and_control_bits >> 1) & 1 == 1
    }

    /// Sets the SYN (Synchronize) control bit in the TCP header, if not already
    /// set.
    pub fn set_syn(&mut self) {
        // Sets the 1st bit from the LSB.
        self.offset_and_control_bits |= 1 << 1;
    }

    /// Returns `true` if the FIN (Finish) control bit is set in the TCP header.
    pub fn fin(&self) -> bool {
        // Stored as the LSB.
        self.offset_and_control_bits & 1 == 1
    }

    /// Sets the FIN (Finish) control bit in the TCP header, if not already set.
    pub fn set_fin(&mut self) {
        // Sets the LSB.
        self.offset_and_control_bits |= 1;
    }

    /// Returns the Window field from the TCP header.
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Returns the Checksum field from the TCP header.
    pub fn checksum(&self) -> u16 {
        self.checksum
    }

    /// Computes and sets the Checksum field of the TCP header with the provided
    /// IPv4 header and payload.
    pub fn set_checksum(&mut self, ip_header: &Ipv4Header, payload: &[u8]) {
        self.checksum = self.compute_checksum(ip_header, payload);
    }

    /// Returns the Urgent Pointer field from the TCP header.
    pub fn urgent_pointer(&self) -> u16 {
        self.urgent_pointer
    }

    /// Returns the Options field from the TCP header.
    pub fn options(&self) -> TcpOptions {
        self.options
    }

    /// Sets the Maximum Segment Size (MSS) option for the TCP header.
    ///
    /// # Errors
    ///
    /// Returns an error if the options buffer lacks sufficient space to append
    /// the MSS, or if the provided MSS value is invalid.
    pub fn set_option_mss(&mut self, mss: u16) -> Result<(), String> {
        self.options.set_mss(mss)?;

        // Convert options length to representation of total bytes and add to
        // the previous data offset.
        let new_data_offset = ((self.options.len() >> 2) as u8 + self.data_offset()) as u16;

        // Clear previous data offset value.
        self.offset_and_control_bits &= 0x0FFF;

        // Clear the higher 12-bits of the new data offset and shift the new
        // offset into the higher 4-bits, then combine with the previously
        // cleared offset.
        self.offset_and_control_bits |= (new_data_offset & 0x000F) << 12;

        Ok(())
    }

    /// Returns the length of the TCP header in bytes, including options.
    pub fn header_len(&self) -> usize {
        Self::MIN_HEADER_LEN as usize + self.options.len()
    }

    /// Returns the computed checksum for the TCP header with the provided IPv4
    /// header and payload.
    ///
    /// The checksum algorithm is:
    ///
    /// The checksum field is the 16 bit one's complement of the one's
    /// complement sum of all 16 bit words in the pseudo header, TCP header,
    /// and payload. For purposes of computing the checksum, the value of the
    /// checksum field is zero.
    pub fn compute_checksum(&self, ip_header: &Ipv4Header, payload: &[u8]) -> u16 {
        // RFC 793 (3.1):
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
        let mut pseudo_header = [0u8; 12];

        pseudo_header[0..4].copy_from_slice(&ip_header.src());
        pseudo_header[4..8].copy_from_slice(&ip_header.dst());
        pseudo_header[8] = 0;
        pseudo_header[9] = ip_header.protocol().into();

        let tcp_len: u16 = (self.header_len() + payload.len()) as u16;
        pseudo_header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

        let (mut raw_header, nbytes) = self.to_be_bytes();

        // Checksum field must be 0 for computation.
        raw_header[16] = 0x00;
        raw_header[17] = 0x00;

        let tcp_header_bytes = &raw_header[..nbytes];

        // Chain together byte slices so each can be processed together.
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

                    // Handle potential overflow with carry folding.
                    if sum > 0xFFFF {
                        // Adds the higher 16-bits to the lower 16-bits.
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                (Some(h), None) => {
                    // If a segment contains an odd number of header and text
                    // octets to be checksummed, the last octet is padded on the
                    // right with zeros to form a 16 bit word for checksum
                    // purposes.
                    let word = u16::from_be_bytes([*h, 0x00]);

                    sum += word as u32;

                    // Handle potential overflow with carry folding.
                    if sum > 0xFFFF {
                        // Adds the higher 16-bits to the lower 16-bits.
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                _ => {
                    break;
                }
            }
        }

        // Handle potential remaining overflow with carry folding.
        while sum > 0xFFFF {
            // Adds the higher 16-bits to the lower 16-bits.
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Returns the memory representation of the TCP header as a byte array in
    /// big-endian (network) byte order and the number of bytes written.
    pub fn to_be_bytes(&self) -> ([u8; Self::MAX_HEADER_LEN as usize], usize) {
        let mut raw_header = [0u8; Self::MAX_HEADER_LEN as usize];
        let size = self.header_len();

        raw_header[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        raw_header[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        raw_header[4..8].copy_from_slice(&self.seq_number.to_be_bytes());
        raw_header[8..12].copy_from_slice(&self.ack_number.to_be_bytes());
        raw_header[12..14].copy_from_slice(&self.offset_and_control_bits.to_be_bytes());
        raw_header[14..16].copy_from_slice(&self.window.to_be_bytes());
        raw_header[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        raw_header[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());

        raw_header[20..size].copy_from_slice(self.options.as_slice());

        (raw_header, size)
    }

    /// Reads a TCP header from the given input stream.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the input stream fails or a TCP header
    /// could not be parsed.
    pub fn read<T: io::Read>(input: &mut T) -> Result<Self, String> {
        let mut raw_header = [0u8; Self::MAX_HEADER_LEN as usize];

        let nbytes = input
            .read(&mut raw_header[..])
            .map_err(|err| format!("failed to read TCP header from input: {err}"))?;

        TcpHeader::try_from(&raw_header[..nbytes])
    }

    /// Writes the TCP header to the given output stream.
    ///
    /// # Notes
    ///
    /// Checksum is NOT automatically computed. It is the callers responsibility
    /// to ensure the checksum is computed before writing.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the output stream fails.
    pub fn write<T: io::Write>(&self, output: &mut T) -> Result<(), String> {
        let (raw_header, nbytes) = self.to_be_bytes();

        output
            .write_all(&raw_header[..nbytes])
            .map_err(|err| format!("failed to write TCP header to output: {err}"))?;

        Ok(())
    }
}

impl TryFrom<&[u8]> for TcpHeader {
    type Error = String;

    fn try_from(header_raw: &[u8]) -> Result<Self, Self::Error> {
        if header_raw.len() < Self::MIN_HEADER_LEN as usize {
            return Err(format!(
                "failed to read TCP header from input: provided header length: {}, minimum header length: {}",
                header_raw.len(),
                Self::MIN_HEADER_LEN
            ));
        }

        let offset_and_control_bits = u16::from_be_bytes([header_raw[12], header_raw[13]]);
        let data_offset = offset_and_control_bits >> 12;

        if data_offset < Self::MIN_DATA_OFFSET {
            return Err(format!(
                "failed to read TCP header from input: provided data offset: {}, minimum data offset: {}",
                data_offset,
                Self::MIN_DATA_OFFSET
            ));
        }

        // There are less bytes in the buffer than advertised by data offset.
        if (data_offset << 2) > header_raw.len() as u16 {
            return Err(format!(
                "failed to read TCP header from input: provied header length: {}, indicated header length: {}",
                header_raw.len(),
                data_offset >> 2
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
                // There are advertised options present in the header.
                if data_offset > Self::MIN_DATA_OFFSET {
                    let rest_len = header_raw[20..].len();

                    // SAFETY: Checked data offset >= Self::MIN_DATA_OFFSET.
                    if ((data_offset - Self::MIN_DATA_OFFSET) << 2) as usize != rest_len {
                        return Err(format!(
                            "failed to read TCP header from input: provided options length: {}, indicated options length: {}",
                            rest_len,
                            (data_offset - Self::MIN_DATA_OFFSET) << 2
                        ));
                    }

                    // Limit range so payload bytes are not accidentally read as
                    // options.
                    TcpOptions::try_from(&header_raw[20..(data_offset << 2) as usize])
                        .map_err(|err| format!("failed to read TCP header from input: {err}"))?
                } else {
                    TcpOptions::new()
                }
            },
        })
    }
}

impl Default for TcpHeader {
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
            offset_and_control_bits: 0b0101_000000_000000,
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

/// Representation of a TCP Options field in a TCP header.
#[derive(Debug, Clone, Copy)]
pub struct TcpOptions {
    len: usize,
    buf: [u8; 40],
}

impl TcpOptions {
    /// Maximum length of TCP options in bytes.
    pub const MAX_OPTIONS_LEN: u16 = 40;

    /// Creates a new empty TCP options.
    pub fn new() -> Self {
        Self {
            len: 0,
            buf: [0u8; 40],
        }
    }

    /// Returns the Maximum Segment Size (MSS) value from the TCP options, if
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
                    // RFC 793 (3.1):
                    //
                    // ```text
                    //          1        2        3         4
                    //        +--------+--------+---------+--------+
                    //        |00000010|00000100|   max seg size   |
                    //        +--------+--------+---------+--------+
                    //           ^               ^^^^^^^^^^^^^^^^^^
                    //           |-- Here         Want these bytes
                    // ```

                    // Length for MSS option must be 0x04.
                    if opts_slice[i + 1] != 0x04 {
                        break;
                    }

                    return Some(u16::from_be_bytes([opts_slice[i + 2], opts_slice[i + 3]]));
                }
            }
        }

        None
    }

    /// Sets the Maximum Segment Size (MSS) value for the TCP options, appending
    /// it to the current options buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the options buffer lacks sufficient space to append
    /// the MSS, or if the provided MSS value is invalid.
    pub fn set_mss(&mut self, mss: u16) -> Result<(), String> {
        if self.mss().is_some() {
            // Skip setting MSS option is it already exists...
        } else {
            const MSS_LEN: usize = 4;

            if mss == 0 {
                return Err(
                    "failed to append MSS option to TCP options: invalid MSS value: 0".into(),
                );
            }

            let opts_len = self.len();

            if (opts_len + MSS_LEN) as u16 > Self::MAX_OPTIONS_LEN {
                return Err(format!(
                    "failed to append MSS option to TCP options: options length if appended {}, maximum allowed buffer length: {}",
                    opts_len + MSS_LEN,
                    Self::MAX_OPTIONS_LEN
                ));
            }

            let mut mss_option = [0u8; MSS_LEN];

            mss_option[0] = OptionKind::MSS as u8;
            mss_option[1] = 0x04;
            mss_option[2..4].copy_from_slice(&mss.to_be_bytes());

            self.buf[opts_len..opts_len + MSS_LEN].copy_from_slice(&mss_option);
            self.len += MSS_LEN;
        }

        Ok(())
    }

    /// Returns the length of the TCP options in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the TCP options contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns an immutable slice containing the TCP options.
    pub fn as_slice(&self) -> &[u8] {
        debug_assert!(self.len <= 40);

        // SAFETY: Verified that self.len is less then 40 bytes.
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr(), self.len) }
    }
}

impl TryFrom<&[u8]> for TcpOptions {
    type Error = String;

    fn try_from(opts_slice: &[u8]) -> Result<Self, Self::Error> {
        if opts_slice.len() > Self::MAX_OPTIONS_LEN as usize {
            return Err(format!(
                "provided options length: {}, maximum allowed options length: {}",
                opts_slice.len(),
                Self::MAX_OPTIONS_LEN
            ));
        }

        let len = opts_slice.len();

        // Ensure options present are aligned to a 4-byte boundary, adding
        // padding if necessary.
        let padding = if len & 0b11 != 0 { 4 } else { 0 };

        Ok(Self {
            // Truncate len to the nearest multiple of 4 before adding padding.
            len: ((len >> 2) << 2) + padding,
            buf: {
                let mut buf = [0; 40];
                buf[..len].copy_from_slice(opts_slice);
                buf
            },
        })
    }
}

impl Default for TcpOptions {
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
    /// prepared to process options even if they do not begin on a word
    /// boundary.
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
    /// Maximum Segment" Size Option Data:  16 bits
    ///
    /// If this option is present, then it communicates the maximum receive
    /// segment size at the TCP which sends this segment. This field must only
    /// be sent in the initial connection request
    /// (i.e., in segments with the SYN control bit set). If this option is not
    /// used, any segment size is allowed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_header_basic_valid() {
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
    fn tcp_header_round_trip_parsing_valid() {
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

        let (buf, nbytes) = header.to_be_bytes();

        let header = TcpHeader::try_from(&buf[..nbytes]);
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
    fn tcp_header_checksum_validation_valid() {
        let header_bytes: [u8; 40] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        let iph = Ipv4Header::new(
            [192, 168, 0, 1],
            [192, 168, 0, 44],
            header.header_len() as u16,
            64,
            crate::parse::Protocol::TCP,
        )
        .unwrap();

        assert_eq!(header.checksum(), header.compute_checksum(&iph, &[]));

        // Invalidate checksum.
        header.set_ack_number(22);

        assert_ne!(header.checksum(), header.compute_checksum(&iph, &[]));
    }

    #[test]
    fn tcp_header_flags_bit_isolation_valid() {
        // Check if all permutations of URG, ACK, PSH, RST, SYN, and FIN bits
        // can be parsed.
        for flags in 0u8..=0b00111111 {
            let mut header_bytes: [u8; 40] = [
                0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00,
                0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
                0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
            ];

            header_bytes[13] = flags;

            let header = TcpHeader::try_from(&header_bytes[..]);
            assert!(header.is_ok(),);
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
    fn tcp_header_data_offset_maximum_valid() {
        let header_bytes: [u8; 60] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_ok());

        assert_eq!(header.unwrap().data_offset(), 15);
    }

    #[test]
    fn tcp_header_set_mss_valid() {
        let header_bytes: [u8; 20] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xfa, 0xf0, 0x80, 0x3e, 0x00, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_ok());
        let mut header = header.unwrap();

        assert_eq!(header.data_offset(), 5);
        assert_eq!(header.options.mss(), None);

        assert!(header.set_option_mss(1460).is_ok());

        assert_eq!(header.data_offset(), 6);
        assert_eq!(header.options.mss(), Some(1460));

        let (buf, nbytes) = header.to_be_bytes();

        assert!(TcpHeader::try_from(&buf[..nbytes]).is_ok());
    }

    #[test]
    fn tcp_header_options_length_invalid() {
        // Data offset of 6 means 4 bytes of options present.
        //
        // Provided 40 bytes of options instead.
        let header_bytes: [u8; 60] = [
            0xa0, 0x16, 0x01, 0xbb, 0xbc, 0xbb, 0x54, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
            0xfa, 0xf0, 0xbb, 0x4c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
            0x78, 0x27, 0xe4, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let header = TcpHeader::try_from(&header_bytes[..]);
        assert!(header.is_err());
    }
}
