use std::mem;

use crate::{Error, ParseError};

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
    #[inline]
    fn from(proto: Protocol) -> u8 {
        proto as u8
    }
}

impl TryFrom<u8> for Protocol {
    type Error = Error;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let protocol = match value {
            0 | 255 => Protocol::Reserved,
            // SAFETY: `1..=54` and `61..=100` are all defined variants. `u8`
            // and `Protocol` have the same memory layout.
            1..=54 | 61..=100 => unsafe { mem::transmute::<u8, Protocol>(value) },
            55..=60 | 101..=254 => Protocol::Unassigned,
        };

        match protocol {
            Protocol::Unassigned | Protocol::Reserved => {
                Err(Error::Parse(ParseError::InvalidProtocol {
                    protocol,
                    value,
                }))
            }
            _ => Ok(protocol),
        }
    }
}
