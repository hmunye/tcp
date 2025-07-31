//! Very minimal implementation of the Transmission Control Protocol (TCP).

use crate::parse::{IPv4Header, Protocol, TCPHeader};
use crate::tun_tap::{MTU_SIZE, Tun};
use crate::{info, warn};

/// Maximum Segment Size Option (RFC 1122 4.2.2.6).
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40).
const DEFAULT_MSS: u16 = 536;

/// The advertised window size to the peer of the TCP connection.
const RECV_WND_SIZE: usize = 4096;

/// Representation of a unique TCP connection.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Socket {
    /// Source Address and Port.
    src: ([u8; 4], u16),
    /// Destination Address and Port.
    dst: ([u8; 4], u16),
}

impl Socket {
    /// Creates a new [Socket] using provided (source address, source port) and
    /// (destination address, destination port) pairs.
    pub fn new(src: ([u8; 4], u16), dst: ([u8; 4], u16)) -> Self {
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
    snd: SendSeqSpace,
    /// Receive Sequence Space for the TCP connection.
    rcv: RecvSeqSpace,
    /// Maximum Segment Size (MSS) of peer.
    #[allow(dead_code)]
    peer_mss: u16,
}

/// Send Sequence Space (RFC 793 3.2).
///
/// ```text
///                   1         2          3          4
///              ----------|----------|----------|----------
///                     SND.UNA    SND.NXT    SND.UNA
///                                          +SND.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers of unacknowledged data
///        3 - sequence numbers allowed for new data transmission
///        4 - future sequence numbers which are not yet allowed
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
///                       1          2          3
///                   ----------|----------|----------
///                          RCV.NXT    RCV.NXT
///                                    +RCV.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers allowed for new reception
///        3 - future sequence numbers which are not yet allowed
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

#[allow(dead_code)]
impl ConnectionState {
    /// Returns `true` if the current [ConnectionState] is in a "synchronized"
    /// state.
    pub fn is_synchronized(&self) -> bool {
        !matches!(
            self,
            Self::CLOSED | Self::LISTEN | Self::SYN_SENT | Self::SYN_RECEIVED
        )
    }
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
    /// the peer.
    pub fn on_conn_req(nic: &mut Tun, iph: &IPv4Header, tcph: &TCPHeader) -> Result<Self, String> {
        TCB::log_packet(iph, tcph, &[]);

        // Ensure we are only processing a SYN segment.
        if !tcph.syn() || tcph.ack() {
            return Err("expected to receive a SYN segment to begin three-way handshake".into());
        }

        let mut buf = [0u8; MTU_SIZE];

        // Initial Send Sequence Number (should be initialized with a random value).
        let iss = 0;

        let conn = TCB {
            state: ConnectionState::SYN_RECEIVED,
            snd: SendSeqSpace {
                // Should be the value of the last ACK received. Since we have
                // not sent any bytes yet, it is set to the ISS.
                una: iss,
                // The next sequence number we will transmit to the peer.
                nxt: iss + 1,
                // The window size that was advertised by the peer.
                wnd: tcph.window(),
                up: 0,
                // The peer's sequence number used for last window update.
                // Initially set to the received sequence number.
                wl1: tcph.seq_number(),
                // The peer's acknowledgment number used for last window update.
                // Set to 0 since no ACK has been received.
                wl2: 0,
                // What sequence number we choose to start from.
                iss,
            },
            rcv: RecvSeqSpace {
                // The next sequence number we expect from the peer.
                nxt: tcph.seq_number() + 1,
                // The window size we advertise to the peer.
                wnd: RECV_WND_SIZE as u16,
                up: tcph.urgent_pointer(),
                // What sequence number the peer chooses to start from.
                irs: tcph.seq_number(),
            },
            // Keep track of the peer's MSS that may have included in TCP
            // options.
            peer_mss: tcph.options().mss().unwrap_or(DEFAULT_MSS),
        };

        let mut syn_ack =
            TCPHeader::new(tcph.dst_port(), tcph.src_port(), conn.snd.iss, conn.rcv.wnd);

        // Acknowledge the peer's SYN.
        syn_ack.set_ack_number(conn.rcv.nxt);

        // Set our MSS option value for the peer to adhere to.
        syn_ack.set_option_mss(1460)?;
        syn_ack.set_syn();
        syn_ack.set_ack();

        let mut ip = IPv4Header::new(
            iph.dst(),
            iph.src(),
            syn_ack.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        // Checksum must be computed and set before sending to peer.
        ip.set_header_checksum();
        syn_ack.set_checksum(&ip, &[]);

        let nbytes = {
            let mut unwritten = &mut buf[..];

            ip.write(&mut unwritten)
                .map_err(|err| format!("failed to write SYN_ACK segment: {err}"))?;
            syn_ack
                .write(&mut unwritten)
                .map_err(|err| format!("failed to write SYN_ACK segment: {err}"))?;

            MTU_SIZE - unwritten.len()
        };

        nic.send(&buf[..nbytes])
            .map_err(|err| format!("failed to write SYN_ACK segment: {err}"))?;

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

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();

        // RFC 793 (3.3)
        //
        // When data is received the following comparisons are needed:
        //
        // ```text
        //    Segment Receive  Test
        //    Length  Window
        //    ------- -------  -------------------------------------------
        //
        //       0       0     SEG.SEQ = RCV.NXT
        //
        //       0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //
        //      >0       0     not acceptable
        //
        //      >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //                  or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        // ```

        // The number of octets occupied by the data in the segment (counting SYN and FIN).
        let seg_len =
            payload.len() as u32 + if tcph.syn() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

        let nxt_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

        match seg_len {
            0 => match self.rcv.wnd {
                0 => {
                    // Case 1: SEG.SEQ = RCV.NXT
                    if seqn != self.rcv.nxt {
                        return Err(format!(
                            "invalid SEQ number {}: expected SEQ number {}",
                            seqn, self.rcv.nxt
                        ));
                    }
                }
                _ => {
                    // Case 2: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                    if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd) {
                        return Err(format!(
                            "invalid SEQ number {}: expected SEQ number between {} and {} (exclusive of {})",
                            seqn,
                            self.rcv.nxt.wrapping_sub(1),
                            nxt_wnd,
                            nxt_wnd
                        ));
                    }
                }
            },
            len => match self.rcv.wnd {
                0 => {
                    // Case 3: not acceptable (we have received bytes when we are
                    // advertising that we are not accepting any at the moment).
                    return Err(format!(
                        "received {len} bytes of data from peer with current receive window value: 0",
                    ));
                }
                _ => {
                    // Case 4: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                    //      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
                    if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd)
                        && !is_between_wrapped(
                            self.rcv.nxt.wrapping_sub(1),
                            seqn + len - 1,
                            nxt_wnd,
                        )
                    {
                        return Err(format!(
                            "invalid SEQ number {}: expected first or last SEQ number occupied by the segment between {} and {} (exclusive of {})",
                            seqn,
                            self.rcv.nxt.wrapping_sub(1),
                            nxt_wnd,
                            nxt_wnd
                        ));
                    }
                }
            },
        }

        match self.state {
            ConnectionState::SYN_RECEIVED => {
                if !tcph.ack() {
                    return Err(format!(
                        "expected ACK segement while in {:?} state",
                        self.state
                    ));
                }

                // RFC 793 (3.3)
                //
                // A new acknowledgment (called an "acceptable ack"), is one for
                // which the inequality below holds:
                //
                // ```text
                //    SND.UNA < SEG.ACK =< SND.NXT
                // ```
                if !is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                    return Err(format!(
                        "invalid ACK number {}: expected ACK number between {} and {} (exclusive of {})",
                        ackn,
                        self.snd.una,
                        self.snd.nxt.wrapping_add(1),
                        self.snd.una
                    ));
                }

                self.state = ConnectionState::ESTABLISHED;
                // Send window slides to the right since the SYN segment sent
                // was ACKed.
                self.snd.una = ackn;
            }
            ConnectionState::LISTEN | ConnectionState::CLOSED => unreachable!(),
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
            "ipv4 datagram | version: {}, ihl: {}, tos: {}, total_len: {}, id: {}, DF: {}, MF: {}, frag_offset: {}, ttl: {}, protocol: {:?}, chksum: 0x{:04x} (valid: {}), src: {:?}, dst: {:?}",
            iph.version(),
            iph.ihl(),
            iph.tos(),
            iph.total_len(),
            iph.id(),
            iph.dont_fragment(),
            iph.more_fragments(),
            iph.fragment_offset(),
            iph.ttl(),
            iph.protocol(),
            iph.header_checksum(),
            iph.compute_header_checksum() == iph.header_checksum(),
            iph.src(),
            iph.dst(),
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

        info!(
            "read {} bytes of segment payload: {:x?}",
            payload.len(),
            payload
        );
    }
}

#[inline]
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // RFC 1323 (2.2):
    //
    // TCP determines if a data segment is "old" or "new" by testing whether
    // its sequence number is within 2**31 bytes of the left edge of the window,
    // and if it is not, discarding the data as "old". To insure that new data
    // is never mistakenly considered old and vice-versa, the left edge of the
    // sender's window has to be at most 2**31 away from the right edge of the
    // receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// Returns `true` is the value `x` is in between the values `start` and `end`,
/// accounting for wrapping arithmetic.
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
