//! Minimal implementation of the Transmission Control Protocol (TCP).

use std::net::Ipv4Addr;

use crate::parse::{IPv4Header, Protocol, TCPHeader};
use crate::tun_tap::{MTU_SIZE, Tun};
use crate::{info, warn};

/// Maximum Segment Size Option (RFC 1122 4.2.2.6).
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40) [TCP:4].
const DEFAULT_MSS: u16 = 536;

/// Representation of a unique TCP connection.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Socket {
    /// Source Address and Port.
    src: (Ipv4Addr, u16),
    /// Destination Address and Port.
    dst: (Ipv4Addr, u16),
}

impl Socket {
    /// Creates a new [Socket] using provided (source address, source port) and
    /// (destination address, destination port) pairs.
    pub fn new(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16)) -> Self {
        Self { src, dst }
    }
}

/// Transmission Control Block (TCB) which stores information about the state
/// and control data for managing a TCP connection.
#[derive(Debug)]
pub struct TCB {
    /// Current state of the TCP connection.
    state: ConnectionState,
    /// Send Sequence Space for the TCP connection.
    send_seq_sp: SendSeqSpace,
    /// Receive Sequence Space for the TCP connection.
    recv_seq_sp: RecvSeqSpace,
    /// Maximum Segment Size (MSS).
    #[allow(dead_code)]
    peer_mss: u16,
}

/// Send Sequence Space (RFC 793 3.2).
///
/// ```text
///
///                   1         2          3          4
///              ----------|----------|----------|----------
///                     SND.UNA    SND.NXT    SND.UNA
///                                          +SND.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers of unacknowledged data
///        3 - sequence numbers allowed for new data transmission
///        4 - future sequence numbers which are not yet allowed
///
///                               Figure 4.
/// ```
#[derive(Debug)]
#[allow(dead_code)]
pub struct SendSeqSpace {
    /// SND.UNA - send unacknowledged
    una: u32,
    /// SND.NXT - send next
    nxt: u32,
    /// SND.WND - send window
    wnd: u16,
    /// SND.UP  - send urgent pointer
    up: u16,
    /// SND.WL1 - segment sequence number used for last window update
    wl1: u32,
    /// SND.WL2 - segment acknowledgment number used for last window update
    wl2: u32,
    /// ISS     - initial send sequence number
    iss: u32,
}

/// Receive Sequence Space (RFC 793 3.2).
///
/// ```text
///
///
///                       1          2          3
///                   ----------|----------|----------
///                          RCV.NXT    RCV.NXT
///                                    +RCV.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers allowed for new reception
///        3 - future sequence numbers which are not yet allowed
///
///                               Figure 5.
/// ```
#[derive(Debug)]
#[allow(dead_code)]
pub struct RecvSeqSpace {
    /// RCV.NXT - receive next
    nxt: u32,
    /// RCV.WND - receive window
    wnd: u16,
    /// RCV.UP  - receive urgent pointer
    up: u16,
    /// IRS     - initial receive sequence number
    irs: u32,
}

/// Representation of a TCP connection state.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum ConnectionState {
    /// Represents waiting for a connection request from any remote TCP and port.
    LISTEN,
    /// Represents waiting for a matching connection request after having sent a
    /// connection request.
    SYN_SENT,
    /// Represents waiting for a confirming connection request acknowledgment
    /// after having both received and sent a connection request.
    SYN_RECEIVED,
    /// Represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection.
    ESTABLISHED,
    /// Represents waiting for a connection termination request from the remote
    /// TCP, or an acknowledgment of the connection termination request
    /// previously sent.
    FIN_WAIT_1,
    /// Represents waiting for a connection termination request from the remote
    /// TCP.
    FIN_WAIT_2,
    /// Represents waiting for a connection termination request from the local
    /// user.
    CLOSE_WAIT,
    /// Represents waiting for a connection termination request acknowledgment
    /// from the remote TCP.
    CLOSING,
    /// Represents waiting for an acknowledgment of the connection termination
    /// request previously sent to the remote TCP (which includes an acknowledgment
    /// of its connection termination request).
    LAST_ACK,
    /// Represents waiting for enough time to pass to be sure the remote TCP
    /// received the acknowledgment of its connection termination request.
    TIME_WAIT,
    /// Represents no connection state at all.
    CLOSED,
}

impl TCB {
    /// Processes any incoming TCP segment when no connection state exists.
    ///
    /// This function is responsible for processing incoming TCP segments that
    /// do not have an existing connection state. When a TCP segment with the
    /// `SYN` flag set is received, it will create a new connection state and
    /// send a `SYN-ACK` response segment to acknowledge the connection request.
    ///
    /// # Errors
    ///
    /// Returns an error if the incoming segment does not have the SYN control
    /// bit set or if the constructed SYN_ACK segment could not be written to
    /// the client.
    pub fn on_conn_req(nic: &mut Tun, iph: &IPv4Header, tcph: &TCPHeader) -> Result<Self, String> {
        TCB::log_packet(iph, tcph, &[]);

        if !tcph.syn() || tcph.ack() {
            return Err("did not receive a SYN packet to begin three-way handshake".into());
        }

        let mut buf = [0u8; MTU_SIZE];

        // Initial Send Sequence Number
        let iss = 0;
        // Window Size
        let wnd = 1024;
        // Time-to-Live
        let ttl = 64;

        let conn = TCB {
            state: ConnectionState::SYN_RECEIVED,
            send_seq_sp: SendSeqSpace {
                // Since no segments have been acknowledged yet, set to `iss`.
                una: iss,
                // The next sequence number to be sent.
                nxt: iss + 1,
                wnd,
                up: 0,
                // Since the send window has not been updated yet, their is no
                // previous sequence or acknowledgment numbers.
                wl1: iss,
                wl2: 0,
                // What sequence number we choose to start from.
                iss,
            },
            recv_seq_sp: RecvSeqSpace {
                // The next sequence number we expect from the client.
                nxt: tcph.seq_number() + 1,
                wnd: tcph.window(),
                up: tcph.urgent_pointer(),
                // What sequence number the client chooses to start from.
                irs: tcph.seq_number(),
            },
            // Keep track of the MSS the client may have included in TCP options.
            peer_mss: tcph.options().mss().unwrap_or(DEFAULT_MSS),
        };

        let mut syn_ack =
            TCPHeader::new(tcph.dst_port(), tcph.src_port(), conn.send_seq_sp.iss, wnd);

        // Acknowledge the client's SYN.
        syn_ack.set_ack_number(conn.recv_seq_sp.nxt);
        syn_ack.set_syn();
        syn_ack.set_ack();

        let mut ip = IPv4Header::new(
            iph.dst(),
            iph.src(),
            syn_ack.header_len() as u16,
            ttl,
            Protocol::TCP,
        )?;

        // Checksum must be computed and set before sending to client.
        ip.set_header_checksum();
        syn_ack.set_checksum(&ip, &[]);

        let nbytes = {
            let mut unwritten = &mut buf[..];

            ip.write(&mut unwritten)
                .map_err(|err| format!("failed to write SYN_ACK response: {err}"))?;
            syn_ack
                .write(&mut unwritten)
                .map_err(|err| format!("failed to write SYN_ACK response: {err}"))?;

            MTU_SIZE - unwritten.len()
        };

        nic.send(&buf[..nbytes])
            .map_err(|err| format!("failed to write SYN_ACK response: {err}"))?;

        Ok(conn)
    }

    /// Processes any incoming TCP segment for the given connection.
    ///
    /// This function implements the core TCP state machine, accepting an
    /// [IPv4Header], [TCPHeader], and payload as arguments, and processes the
    /// segment according to the current state of the connection.
    ///
    /// TCP Connection State Diagram (RFC 793 3.2)
    ///
    /// ```text
    ///
    ///                              +---------+ ---------\      active OPEN
    ///                              |  CLOSED |            \    -----------
    ///                              +---------+<---------\   \   create TCB
    ///                                |     ^              \   \  snd SYN
    ///                   passive OPEN |     |   CLOSE        \   \
    ///                   ------------ |     | ----------       \   \
    ///                    create TCB  |     | delete TCB         \   \
    ///                                V     |                      \   \
    ///                              +---------+            CLOSE    |    \
    ///                              |  LISTEN |          ---------- |     |
    ///                              +---------+          delete TCB |     |
    ///                   rcv SYN      |     |     SEND              |     |
    ///                  -----------   |     |    -------            |     V
    /// +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
    /// |         |<-----------------           ------------------>|         |
    /// |   SYN   |                    rcv SYN                     |   SYN   |
    /// |   RCVD  |<-----------------------------------------------|   SENT  |
    /// |         |                    snd ACK                     |         |
    /// |         |------------------           -------------------|         |
    /// +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
    ///   |           --------------   |     |   -----------
    ///   |                  x         |     |     snd ACK
    ///   |                            V     V
    ///   |  CLOSE                   +---------+
    ///   | -------                  |  ESTAB  |
    ///   | snd FIN                  +---------+
    ///   |                   CLOSE    |     |    rcv FIN
    ///   V                  -------   |     |    -------
    /// +---------+          snd FIN  /       \   snd ACK          +---------+
    /// |  FIN    |<-----------------           ------------------>|  CLOSE  |
    /// | WAIT-1  |------------------                              |   WAIT  |
    /// +---------+          rcv FIN  \                            +---------+
    ///   | rcv ACK of FIN   -------   |                            CLOSE  |
    ///   | --------------   snd ACK   |                           ------- |
    ///   V        x                   V                           snd FIN V
    /// +---------+                  +---------+                   +---------+
    /// |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
    /// +---------+                  +---------+                   +---------+
    ///   |                rcv ACK of FIN |                 rcv ACK of FIN |
    ///   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
    ///   |  -------              x       V    ------------        x       V
    ///    \ snd ACK                 +---------+delete TCB         +---------+
    ///     ------------------------>|TIME WAIT|------------------>| CLOSED  |
    ///                              +---------+                   +---------+
    ///
    ///                               Figure 6.
    ///
    /// ```
    pub fn on_packet(
        &mut self,
        _nic: &mut Tun,
        iph: &IPv4Header,
        tcph: &TCPHeader,
        payload: &[u8],
    ) -> Result<(), String> {
        TCB::log_packet(iph, tcph, payload);

        match self.state {
            ConnectionState::SYN_RECEIVED => {
                return Ok(());
            }
            _ => {
                warn!(
                    "connection state {:?} is not currently being handled",
                    self.state
                );
            }
        }

        Ok(())
    }

    /// Logs the details of an incoming TCP segment.
    fn log_packet(iph: &IPv4Header, tcph: &TCPHeader, payload: &[u8]) {
        info!(
            "ipv4 datagram | src: {:?}, dst: {:?}, chksum: 0x{:04x} (valid: {}), payload: {} bytes",
            iph.src(),
            iph.dst(),
            iph.header_checksum(),
            iph.compute_header_checksum() == iph.header_checksum(),
            iph.payload_len().unwrap_or(u16::MAX)
        );

        info!(
            "tcp segment | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), mss: {:?}",
            tcph.src_port(),
            tcph.dst_port(),
            tcph.seq_number(),
            tcph.ack_number(),
            tcph.data_offset(),
            tcph.urg(),
            tcph.ack(),
            tcph.psh(),
            tcph.rst(),
            tcph.syn(),
            tcph.fin(),
            tcph.window(),
            tcph.checksum(),
            tcph.compute_checksum(iph, payload) == tcph.checksum(),
            tcph.options().mss(),
        );

        info!("read {} bytes of payload: {:x?}", payload.len(), payload);
    }
}
