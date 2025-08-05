use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::net::headers::{Ipv4Header, Protocol, TcpHeader};
use crate::tun_tap::{MTU_SIZE, Tun};
use crate::{Error, Result};
use crate::{debug, warn};

/// Retransmission Timeout (RTO) in seconds.
pub const RTO: u64 = 1;

/// Maximum Segment Lifetime (MSL) in seconds.
///
/// The MSL represents the maximum time a segment can exist within the network
/// before being discarded. Typically has a value of 2 minutes (120 seconds).
pub const MSL: u64 = 120;

/// The maximum number of retransmission attempts for a segment before giving up
/// on the connection.
const MAX_RETRANSMIT_ATTEMPTS: usize = 8;

/// RFC 1122 (4.2.2.6):
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40).
const DEFAULT_MSS: u16 = 536;

/// The window size advertised to the peer.
const RCV_WND_SIZE: u16 = 4096;

/// Represents a unique TCP connection.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Socket {
    /// Source address and port.
    pub(crate) src: ([u8; 4], u16),
    /// Destination address and port.
    pub(crate) dst: ([u8; 4], u16),
}

/// Represents a fully constructed TCP segment queued for retransmission.
#[derive(Debug)]
struct Segment {
    /// Stored here because of borrow checker issues with mutability.
    una: u32,
    /// The IPv4 header of the segment.
    ip: Ipv4Header,
    /// The TCP header of the segment.
    tcp: TcpHeader,
    /// The data payload of the segment.
    payload: Vec<u8>,
    /// The timer used in determining whether the segment should be
    /// retransmitted.
    timer: Instant,
    /// The amount of times this segment has been retransmitted. Used to apply
    /// exponential backoff and determine when to give up on the connection.
    transmit_count: usize,
}

/// Represents the Transmission Control Block (TCB), which stores information
/// about the state and control data for managing a TCP connection.
#[derive(Debug)]
pub struct TCB {
    /// Current state of the TCP connection.
    state: ConnectionState,
    /// Connection details of the host and remote TCPs.
    sock: Socket,
    /// Send Sequence Space for the TCP connection.
    snd: SendSeqSpace,
    /// Receive Sequence Space for the TCP connection.
    rcv: RecvSeqSpace,
    /// Buffer to store data received from peer.
    ///
    /// Using a BTreeMap so out of order segments can be retrieved in-order by
    /// sequence number.
    recv_buf: BTreeMap<u32, Vec<u8>>,
    /// Buffer to store acknowledgeable segments sent to the peer.
    ///
    /// Any segments in this buffer which have been unACKed will be
    /// retransmitted based on a per-segment timer.
    send_buf: BTreeMap<u32, Segment>,
    /// Timer used to determine when to close a TCP connection in the TIME_WAIT
    /// state.
    time_wait: Instant,
    /// Maximum Segment Size (MSS) received from peer.
    peer_mss: u16,
    /// State the current TCP connection was opened in.
    open_kind: OpenKind,
}

/// Represents the different TCP connection states.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum ConnectionState {
    /// Represents waiting for a connection request from any remote TCP and
    /// port.
    LISTEN,
    /// Represents waiting for a matching connection request after having sent a
    /// connection request.
    SYN_SENT,
    /// Represents waiting for a confirming connection request acknowledgment
    /// after having both received and sent a connection request.
    SYN_RECEIVED,
    /// Represents an open connection, data received can be delivered to the
    /// user. The normal state for the data transfer phase of the connection.
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
    /// request previously sent to the remote TCP (which includes an
    /// acknowledgment of its connection termination request).
    LAST_ACK,
    /// Represents waiting for enough time to pass to be sure the remote TCP
    /// received the acknowledgment of its connection termination request.
    TIME_WAIT,
    /// Represents no connection state at all.
    CLOSED,
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
pub struct SendSeqSpace {
    /// SND.UNA - send unacknowledged
    una: u32,
    /// SND.NXT - send next
    nxt: u32,
    /// SND.WND - send window
    wnd: u16,
    /// SND.UP  - send urgent pointer
    #[allow(dead_code)]
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

/// Represents the state a TCP connection was opened in.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum OpenKind {
    /// TCP connection was opened in a "passive" state (LISTEN -> SYN_RECEIVED).
    PASSIVE_OPEN,
    /// TCP connection was opened in an "active" state (CLOSED -> SYN_SENT).
    ACTIVE_OPEN,
}

impl TCB {
    /// Initiates a new TCP connection with the provided socket information.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be constructed or if
    /// writing to the peer fails.
    pub fn on_conn_init(nic: &mut Tun, socket: Socket) -> Result<Self> {
        // Initial Send Sequence Number.
        let iss = 0;

        let mut conn = TCB {
            state: ConnectionState::SYN_SENT,
            sock: socket,
            snd: SendSeqSpace {
                // Should be the value of the last ACK received. Set to ISS
                // since there have been no sequence numbers ACKed yet.
                una: iss,
                // The next sequence number we will transmit to the peer.
                // Incremented to account for the SYN being transmitted.
                nxt: iss + 1,
                // The window size that was advertised by the peer. Will be
                // updated when peer responds.
                wnd: 0,
                up: 0,
                // The peer's sequence number used for last window update.
                // Initialized with 0 since we have not performed a window
                // update yet.
                wl1: 0,
                // The peer's acknowledgment number used for last window update.
                // Initialized with 0 since we have not performed a window
                // update yet.
                wl2: 0,
                // What sequence number we choose to start from.
                iss,
            },
            rcv: RecvSeqSpace {
                // The next sequence number we expect from the peer. Will be
                // updated when peer responds.
                nxt: 0,
                // The window size we advertise to the peer.
                wnd: RCV_WND_SIZE,
                // Will be updated when peer responds.
                up: 0,
                // What sequence number the peer chooses to start from. Will be
                // updated when peer responds.
                irs: 0,
            },
            recv_buf: Default::default(),
            send_buf: Default::default(),
            time_wait: Instant::now(),
            // Peer's MSS value that may have been received. Will be updated
            // when peer responds.
            peer_mss: 0,
            open_kind: OpenKind::ACTIVE_OPEN,
        };

        conn.send_syn(nic)?;
        debug!(
            "[{:?}:{} -> {:?}:{}] (ACTIVE_OPEN) sent SYN: ACTIVE_OPEN -> SYN_SENT",
            conn.sock.src.0, conn.sock.src.1, conn.sock.dst.0, conn.sock.dst.1
        );

        Ok(conn)
    }

    /// Processes an incoming TCP connection request for which no connection
    /// state exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the incoming segment is invalid, if the TCP segment
    /// could not be constructed, or if writing to the peer fails.
    pub fn on_conn_req(nic: &mut Tun, iph: &Ipv4Header, tcph: &TcpHeader) -> Result<Option<Self>> {
        log_packet(iph, tcph, &[]);

        // An incoming RST should be ignored.
        if tcph.rst() {
            warn!("(LISTEN) received RST: ignoring");
            return Ok(None);
        }

        // Any acknowledgment is bad if it arrives on a connection still in the
        // LISTEN state.
        if tcph.ack() {
            warn!("(LISTEN) received ACK: sending RST");

            let mut rst = TcpHeader::new(tcph.dst_port(), tcph.src_port(), tcph.ack_number(), 0);
            rst.set_rst();

            let mut ip = Ipv4Header::new(
                iph.dst(),
                iph.src(),
                rst.header_len() as u16,
                64,
                Protocol::TCP,
            )?;

            ip.set_header_checksum();
            rst.set_checksum(&ip, &[]);

            TCB::write(nic, &ip, &rst, &[])?;

            return Ok(None);
        }

        if !tcph.syn() {
            warn!("(LISTEN) did not receive SYN: ignoring");
            return Ok(None);
        }

        // Initial Send Sequence Number.
        let iss = 0;

        let mut conn = TCB {
            state: ConnectionState::SYN_RECEIVED,
            // Stored in reverse order of peer's perspective.
            sock: Socket {
                src: (iph.dst(), tcph.dst_port()),
                dst: (iph.src(), tcph.src_port()),
            },
            snd: SendSeqSpace {
                // Should be the value of the last ACK received. Set to ISS
                // since there have been no sequence numbers ACKed yet.
                una: iss,
                // The next sequence number we will transmit to the peer.
                // Incremented to account for the SYN being transmitted.
                nxt: iss + 1,
                // The window size that was advertised by the peer.
                wnd: tcph.window(),
                up: 0,
                // The peer's sequence number used for last window update.
                // Initialized with 0 since we have not performed a window
                // update yet.
                wl1: 0,
                // The peer's acknowledgment number used for last window update.
                // Initialized with 0 since we have not performed a window
                // update yet.
                wl2: 0,
                // What sequence number we choose to start from.
                iss,
            },
            rcv: RecvSeqSpace {
                // The next sequence number we expect from the peer.
                nxt: tcph.seq_number().wrapping_add(1),
                // The window size we advertise to the peer.
                wnd: RCV_WND_SIZE,
                up: tcph.urgent_pointer(),
                // What sequence number the peer chooses to start from.
                irs: tcph.seq_number(),
            },
            recv_buf: Default::default(),
            send_buf: Default::default(),
            time_wait: Instant::now(),
            // Peer's MSS value that may have been received.
            peer_mss: tcph.options().mss().unwrap_or(DEFAULT_MSS),
            open_kind: OpenKind::PASSIVE_OPEN,
        };

        conn.send_syn_ack(nic)?;
        debug!(
            "[{:?}:{} -> {:?}:{}] (LISTEN) sent SYN_ACK: LISTEN -> SYN_RECEIVED",
            conn.sock.src.0, conn.sock.src.1, conn.sock.dst.0, conn.sock.dst.1
        );

        Ok(Some(conn))
    }

    /// Processes an existing connection's retransmission queue for expired
    /// timers or acknowledged segments. Determines whether segments should be
    /// retransmitted to the peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the function fails to retransmit a queued segment.
    pub fn on_conn_tick(&mut self, nic: &mut Tun) -> Result<()> {
        if !self.send_buf.is_empty() {
            // Keep track of segments to remove from the retransmission queue.
            let mut key_rm = Vec::new();

            for seg in self.send_buf.values_mut() {
                let seg_len = seg.payload.len() as u32
                    + if seg.tcp.syn() { 1 } else { 0 }
                    + if seg.tcp.fin() { 1 } else { 0 };

                // A segment on the retransmission queue is fully acknowledged
                // if the sum of its sequence number and length is less or equal
                // than the acknowledgment value in the incoming segment.
                if seg.tcp.seq_number().wrapping_add(seg_len) <= self.snd.una {
                    key_rm.push(seg.una);
                } else if seg.timer.elapsed() >= Duration::from_secs(RTO) {
                    if seg.transmit_count >= MAX_RETRANSMIT_ATTEMPTS {
                        // Need to close the connection.
                        self.state = ConnectionState::CLOSED;
                        debug!(
                            "[{:?}:{} -> {:?}:{}] ({state:?}) max retransmit attempts reached: {state:?} -> CLOSED",
                            self.sock.src.0,
                            self.sock.src.1,
                            self.sock.dst.0,
                            self.sock.dst.1,
                            state = self.state,
                        );

                        // Can't borrow `self` so manually creating RST segment.
                        let mut rst =
                            TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.nxt, 0);
                        rst.set_rst();

                        let mut ip = Ipv4Header::new(
                            self.sock.src.0,
                            self.sock.dst.0,
                            rst.header_len() as u16,
                            64,
                            Protocol::TCP,
                        )?;

                        ip.set_header_checksum();
                        rst.set_checksum(&ip, &[]);

                        TCB::write(nic, &ip, &rst, &[])?;

                        return Err(Error::Io(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "connection reset",
                        )));
                    }

                    let timer = {
                        if seg.transmit_count == 0 {
                            Instant::now()
                        } else {
                            // Apply exponential backoff to avoid excessive
                            // retransmissions.
                            Instant::now() + Duration::from_nanos(RTO * (1 << seg.transmit_count))
                        }
                    };

                    seg.timer = timer;
                    seg.transmit_count += 1;

                    TCB::write(nic, &seg.ip, &seg.tcp, &seg.payload)?;
                } else {
                    // Peer still has time to ACK the segment...
                }
            }

            // Remove any segments that have been ACKed.
            for key in key_rm.into_iter() {
                let _ = self.send_buf.remove_entry(&key);
            }
        }

        Ok(())
    }

    /// Processes an incoming TCP segment for an existing connection.
    ///
    /// RFC 793 (3.2):
    ///
    /// ```text
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
    /// ```
    pub fn on_conn_packet(
        &mut self,
        nic: &mut Tun,
        iph: &Ipv4Header,
        tcph: &TcpHeader,
        payload: &[u8],
    ) -> Result<()> {
        // This should never happen, but just in case...
        if let ConnectionState::CLOSED | ConnectionState::LISTEN = self.state {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection aborted",
            )));
        }

        log_packet(iph, tcph, payload);

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();

        if let ConnectionState::SYN_SENT = self.state {
            // Do not process an incoming FIN since the SEG.SEQ cannot be
            // validated.
            if tcph.fin() {
                warn!(
                    "[{:?}:{} -> {:?}:{}] (SYN_SENT) received FIN: ignoring",
                    self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1
                );
                return Ok(());
            }

            let mut validate_ack = || {
                // Peer did not correctly ACK our SYN.
                if ackn <= self.snd.iss || ackn > self.snd.nxt {
                    if tcph.rst() {
                        return Err(Error::Io(io::Error::other(
                            "invalid acknowledgment number with RST",
                        )));
                    }

                    self.state = ConnectionState::CLOSED;

                    self.send_rst(nic, ackn, 0)?;
                    debug!(
                        "[{:?}:{} -> {:?}:{}] (SYN_SENT) connection reset: SYN_SENT -> CLOSED",
                        self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                    );

                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connection refused",
                    )));
                }

                // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                //
                // If not, return and continue to wait for an acceptable ACK.
                if !is_between_wrapped(
                    self.snd.una.wrapping_sub(1),
                    ackn,
                    self.snd.nxt.wrapping_add(1),
                ) {
                    warn!(
                        "[{:?}:{} -> {:?}:{}] (SYN_SENT) unacceptable ACK number {}: expected ACK number between {} and {} (inclusive of both)",
                        self.sock.src.0,
                        self.sock.src.1,
                        self.sock.dst.0,
                        self.sock.dst.1,
                        ackn,
                        self.snd.una.wrapping_sub(1),
                        self.snd.nxt.wrapping_add(1),
                    );

                    return Err(Error::Io(io::Error::other(
                        "unacceptable acknowledgment number",
                    )));
                }

                if tcph.rst() {
                    self.state = ConnectionState::CLOSED;
                    debug!(
                        "[{:?}:{} -> {:?}:{}] (SYN_SENT) connection reset: SYN_SENT -> CLOSED",
                        self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                    );

                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }

                Ok(())
            };

            match (tcph.syn(), tcph.ack()) {
                (true, true) => {
                    // Case 1: SYN and ACK received (send ACK).
                    validate_ack()?;

                    // Previously unknown values can now be updated using
                    // incoming segment.
                    self.rcv.nxt = seqn.wrapping_add(1);
                    self.rcv.up = tcph.urgent_pointer();
                    self.rcv.irs = seqn;
                    self.snd.wnd = tcph.window();
                    self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_MSS);

                    self.snd.una = ackn;
                    self.state = ConnectionState::ESTABLISHED;

                    self.send_ack(nic, &[])?;
                    debug!(
                        "[{:?}:{} -> {:?}:{}] (SYN_SENT) sent ACK: SYN_SENT -> ESTABLISHED",
                        self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                    );
                }
                (true, false) => {
                    // Case 2: Only SYN received (send SYN_ACK).
                    if tcph.rst() {
                        return Ok(());
                    }

                    // Previously unknown values can now be updated using
                    // incoming segment.
                    self.rcv.nxt = seqn.wrapping_add(1);
                    self.rcv.up = tcph.urgent_pointer();
                    self.rcv.irs = seqn;
                    self.snd.wnd = tcph.window();
                    self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_MSS);

                    self.state = ConnectionState::SYN_RECEIVED;

                    self.send_syn_ack(nic)?;
                    debug!(
                        "[{:?}:{} -> {:?}:{}] (SYN_SENT) sent SYN_ACK: SYN_SENT -> SYN_RECEIVED",
                        self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                    );

                    // Accounting for the SYN.
                    self.snd.nxt = self.snd.nxt.wrapping_add(1);
                }
                (false, true) => {
                    // Case 3: Only ACK received (validate ACK).

                    // If the ACK number received is valid, we continue to wait
                    // in the SYN_SENT state for a valid segment.
                    validate_ack()?;
                    self.snd.una = ackn;
                }
                (false, false) => {
                    // Case 4: Neither SYN or ACK received (return).
                    warn!(
                        "[{:?}:{} -> {:?}:{}] (SYN_SENT) received neither SYN or ACK: ignoring",
                        self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                    );
                }
            }

            return Ok(());
        }

        // RFC 793 (3.3):
        //
        // There are four cases for the acceptability test for an incoming
        // segment:
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

        // TODO: If the RCV.WND is zero, no segments will be acceptable, but
        // special allowance should be made to accept valid ACKs, URGs and RSTs.

        // The number of octets occupied by the data in the segment (counting
        // SYN and FIN).
        let seg_len =
            payload.len() as u32 + if tcph.syn() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

        let nxt_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

        match seg_len {
            0 => match self.rcv.wnd {
                0 => {
                    // Case 1: SEG.SEQ = RCV.NXT
                    if seqn != self.rcv.nxt {
                        warn!(
                            "[{:?}:{} -> {:?}:{}] ({:?}) invalid SEQ number {}: expected SEQ number: {}",
                            self.sock.src.0,
                            self.sock.src.1,
                            self.sock.dst.0,
                            self.sock.dst.1,
                            self.state,
                            seqn,
                            self.rcv.nxt
                        );

                        if !tcph.rst() {
                            self.send_ack(nic, &[])?;
                        }

                        return Ok(());
                    }
                }
                _ => {
                    // Case 2: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                    if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd) {
                        warn!(
                            "[{:?}:{} -> {:?}:{}] ({:?}) invalid SEQ number {}: expected SEQ number between {} and {} (exclusive of {})",
                            self.sock.src.0,
                            self.sock.src.1,
                            self.sock.dst.0,
                            self.sock.dst.1,
                            self.state,
                            seqn,
                            self.rcv.nxt.wrapping_sub(1),
                            nxt_wnd,
                            nxt_wnd
                        );

                        if !tcph.rst() {
                            self.send_ack(nic, &[])?;
                        }

                        return Ok(());
                    }
                }
            },
            len => match self.rcv.wnd {
                0 => {
                    // Case 3: not acceptable (we have received bytes when we
                    // are advertising a window size of 0).
                    warn!(
                        "[{:?}:{} -> {:?}:{}] ({:?}) received {len} bytes of data from peer with current receive window size: 0",
                        self.sock.src.0,
                        self.sock.src.1,
                        self.sock.dst.0,
                        self.sock.dst.1,
                        self.state
                    );

                    if !tcph.rst() {
                        self.send_ack(nic, &[])?;
                    }

                    return Ok(());
                }
                _ => {
                    // Case 4: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                    //      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
                    if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd)
                        && !is_between_wrapped(
                            self.rcv.nxt.wrapping_sub(1),
                            seqn.wrapping_add(len - 1),
                            nxt_wnd,
                        )
                    {
                        warn!(
                            "[{:?}:{} -> {:?}:{}] ({:?}) invalid SEQ number {}: expected first or last SEQ number occupied by the segment between {} and {wnd} (exclusive of {wnd})",
                            self.sock.src.0,
                            self.sock.src.1,
                            self.sock.dst.0,
                            self.sock.dst.1,
                            self.state,
                            seqn,
                            self.rcv.nxt.wrapping_sub(1),
                            wnd = nxt_wnd,
                        );

                        if !tcph.rst() {
                            self.send_ack(nic, &[])?;
                        }

                        return Ok(());
                    }
                }
            },
        }

        if tcph.rst() {
            debug!(
                "[{:?}:{} -> {:?}:{}] ({state:?}) connection reset: {state:?} -> CLOSED",
                self.sock.src.0,
                self.sock.src.1,
                self.sock.dst.0,
                self.sock.dst.1,
                state = self.state,
            );

            self.state = ConnectionState::CLOSED;

            match self.state {
                ConnectionState::SYN_RECEIVED => match self.open_kind {
                    OpenKind::PASSIVE_OPEN => {
                        return Err(Error::Io(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "connection reset",
                        )));
                    }
                    OpenKind::ACTIVE_OPEN => {
                        return Err(Error::Io(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "connection refused",
                        )));
                    }
                },
                ConnectionState::ESTABLISHED
                | ConnectionState::FIN_WAIT_1
                | ConnectionState::FIN_WAIT_2
                | ConnectionState::CLOSE_WAIT => {
                    // TODO: Any outstanding RECEIVEs and SEND should receive
                    // "reset" responses. All segment queues should be flushed.
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }
                ConnectionState::CLOSING
                | ConnectionState::LAST_ACK
                | ConnectionState::TIME_WAIT
                | ConnectionState::CLOSED => {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }
                _ => unreachable!(),
            }
        }

        if tcph.syn() {
            debug!(
                "[{:?}:{} -> {:?}:{}] ({state:?}) received SYN: {state:?} -> CLOSED",
                self.sock.src.0,
                self.sock.src.1,
                self.sock.dst.0,
                self.sock.dst.1,
                state = self.state,
            );

            // TODO: Any outstanding RECEIVEs and SEND should receive "reset"
            // responses. All segment queues should be flushed.
            self.state = ConnectionState::CLOSED;

            if tcph.ack() {
                self.send_rst(nic, ackn, 0)?;
            } else {
                self.send_rst(nic, 0, seqn.wrapping_add(seg_len))?;
            }

            return Err(Error::Io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection reset",
            )));
        }

        if !tcph.ack() {
            debug!(
                "[{:?}:{} -> {:?}:{}] ({:?}) did not receive ACK",
                self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1, self.state,
            );
            return Ok(());
        } else {
            if let ConnectionState::SYN_RECEIVED = self.state {
                // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                if !is_between_wrapped(
                    self.snd.una.wrapping_sub(1),
                    ackn,
                    self.snd.nxt.wrapping_add(1),
                ) {
                    warn!(
                        "[{:?}:{} -> {:?}:{}] (SYN_RECEIVED) unacceptable ACK number {}: expected ACK number between {} and {} (inclusive of both)",
                        self.sock.src.0,
                        self.sock.src.1,
                        self.sock.dst.0,
                        self.sock.dst.1,
                        ackn,
                        self.snd.una.wrapping_sub(1),
                        self.snd.nxt.wrapping_add(1),
                    );

                    self.state = ConnectionState::CLOSED;

                    self.send_rst(nic, ackn, 0)?;
                    debug!(
                        "[{:?}:{} -> {:?}:{}] (SYN_RECEIVED) connection reset: SYN_RECEIVED -> CLOSED",
                        self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                    );

                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }

                self.state = ConnectionState::ESTABLISHED;
                debug!(
                    "[{:?}:{} -> {:?}:{}] (SYN_RECEIVED) received valid ACK: SYN_RECEIVED -> ESTABLISHED",
                    self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                );
            }

            if let ConnectionState::ESTABLISHED
            | ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2
            | ConnectionState::CLOSE_WAIT
            | ConnectionState::CLOSING
            | ConnectionState::LAST_ACK = self.state
            {
                if ackn < self.snd.una {
                    warn!(
                        "[{:?}:{} -> {:?}:{}] ({:?}) received duplicate ACK: {}",
                        self.sock.src.0,
                        self.sock.src.1,
                        self.sock.dst.0,
                        self.sock.dst.1,
                        self.state,
                        ackn
                    );

                    return Ok(());
                } else if ackn > self.snd.nxt {
                    warn!(
                        "[{:?}:{} -> {:?}:{}] ({:?}) received ACK for untransmitted data: {}",
                        self.sock.src.0,
                        self.sock.src.1,
                        self.sock.dst.0,
                        self.sock.dst.1,
                        self.state,
                        ackn
                    );

                    self.send_ack(nic, &[])?;
                    return Ok(());
                } else {
                    // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
                    //
                    // If SND.UNA < SEG.ACK =< SND.NXT, the send window should
                    // be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ
                    // and SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
                    // SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
                    if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                        self.snd.una = ackn;

                        if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn) {
                            self.snd.wnd = tcph.window();
                            self.snd.wl1 = seqn;
                            self.snd.wl2 = ackn;
                        }
                    }
                }

                match self.state {
                    // Our FIN was acknowledged.
                    ConnectionState::FIN_WAIT_1 => {
                        if tcph.fin() {
                            self.time_wait = Instant::now();
                            self.state = ConnectionState::TIME_WAIT;
                            debug!(
                                "[{:?}:{} -> {:?}:{}] (FIN_WAIT_1) received FIN and FIN was acknowledged: FIN_WAIT_1 -> TIME_WAIT",
                                self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                            );
                        } else {
                            self.state = ConnectionState::FIN_WAIT_2;
                            debug!(
                                "[{:?}:{} -> {:?}:{}] (FIN_WAIT_1) FIN was acknowledged: FIN_WAIT_1 -> FIN_WAIT_2",
                                self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                            );
                        }
                    }
                    ConnectionState::FIN_WAIT_2 => {
                        // TODO:
                    }
                    ConnectionState::CLOSE_WAIT => {
                        // TODO: For now the FIN is immediately sent in response but
                        // it should instead be triggered by user code. The peer
                        // indicated they are done sending data, but the user can
                        // continue to send data.
                        self.state = ConnectionState::LAST_ACK;
                        debug!(
                            "[{:?}:{} -> {:?}:{}] (CLOSE_WAIT) sent FIN_ACK: CLOSE_WAIT -> LAST_ACK",
                            self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                        );

                        self.send_fin_ack(nic, &[])?;

                        // Account for the FIN.
                        self.snd.nxt = self.snd.nxt.wrapping_add(1);
                    }
                    // Our FIN was acknowledged.
                    ConnectionState::CLOSING => {
                        self.time_wait = Instant::now();
                        self.state = ConnectionState::TIME_WAIT;
                        debug!(
                            "[{:?}:{} -> {:?}:{}] (CLOSING) FIN was acknowledged: CLOSING -> FIN_WAIT_2",
                            self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                        );
                    }
                    // Our FIN was acknowledged.
                    ConnectionState::LAST_ACK => {
                        self.state = ConnectionState::CLOSED;
                        debug!(
                            "[{:?}:{} -> {:?}:{}] (LASK_ACK) FIN was acknowledged: LAST_ACK -> CLOSED",
                            self.sock.src.0, self.sock.src.1, self.sock.dst.0, self.sock.dst.1,
                        );

                        return Err(Error::Io(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "connection reset",
                        )));
                    }
                    _ => {}
                }
            }

            if let ConnectionState::ESTABLISHED
            | ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2 = self.state
            {
                if seg_len > 0 {
                    if !payload.is_empty() {
                        match seqn.cmp(&self.rcv.nxt) {
                            // We received the data we were expecting.
                            Ordering::Equal => {
                                self.recv_buf.insert(seqn, payload.into());
                                self.rcv.nxt = self.rcv.nxt.wrapping_add(payload.len() as u32);
                                self.rcv.wnd = self.rcv.wnd.saturating_sub(payload.len() as u16);
                            }
                            // Received data we were not expecting yet. Buffer
                            // but keep RCV.NXT the same.
                            Ordering::Greater => {
                                self.recv_buf.insert(seqn, payload.into());
                                self.rcv.wnd = self.rcv.wnd.saturating_sub(payload.len() as u16);
                            }
                            // Part of the segment overlaps data we have already
                            // received.
                            Ordering::Less => {
                                // The entire payload is old/duplicate data.
                                if payload.len() <= (self.rcv.nxt - seqn) as usize {
                                } else {
                                    let payload = &payload[(self.rcv.nxt - seqn) as usize..];

                                    // Keyed by RCV.NXT instead of SEG.SEQ.
                                    self.recv_buf.insert(self.rcv.nxt, payload.into());
                                    self.rcv.wnd =
                                        self.rcv.wnd.saturating_sub(payload.len() as u16);
                                }
                            }
                        }
                    }

                    if tcph.fin() {
                        self.rcv.nxt = self.rcv.nxt.wrapping_add(1);

                        match self.state {
                            ConnectionState::ESTABLISHED => {
                                self.state = ConnectionState::CLOSE_WAIT;
                                debug!(
                                    "[{:?}:{} -> {:?}:{}] (ESTABLISHED) received FIN: ESTABLISHED -> CLOSE_WAIT",
                                    self.sock.src.0,
                                    self.sock.src.1,
                                    self.sock.dst.0,
                                    self.sock.dst.1,
                                );
                            }
                            ConnectionState::FIN_WAIT_1 => {
                                self.state = ConnectionState::CLOSING;
                                debug!(
                                    "[{:?}:{} -> {:?}:{}] (FIN_WAIT_1) received FIN: FIN_WAIT_1 -> CLOSING",
                                    self.sock.src.0,
                                    self.sock.src.1,
                                    self.sock.dst.0,
                                    self.sock.dst.1,
                                );
                            }
                            ConnectionState::FIN_WAIT_2 => {
                                self.time_wait = Instant::now();
                                self.state = ConnectionState::TIME_WAIT;
                                debug!(
                                    "[{:?}:{} -> {:?}:{}] (FIN_WAIT_2) received FIN: FIN_WAIT_2 -> TIME_WAIT",
                                    self.sock.src.0,
                                    self.sock.src.1,
                                    self.sock.dst.0,
                                    self.sock.dst.1,
                                );
                            }
                            _ => unreachable!(),
                        }
                    }

                    self.send_ack(nic, &[])?;
                }
            }

            if let ConnectionState::TIME_WAIT = self.state {
                // The only thing that can arrive in this state is a
                // retransmission of the remote FIN. Acknowledge it, and restart
                // the 2 MSL timeout.
                if tcph.fin() {
                    self.time_wait = Instant::now();
                    self.send_ack(nic, &[])?;
                }
            }
        }

        Ok(())
    }

    /// Returns the current state of the TCP connection.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Sets the state of the TCP connection to the connection state provided.
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Returns the current value of the TIME_WAIT timer for the TCP connection.
    pub fn time_wait(&self) -> Instant {
        self.time_wait
    }

    /// Transmits a TCP SYN packet to initiate a connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_syn(&mut self, nic: &mut Tun) -> Result<()> {
        let mut syn = TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.iss, self.rcv.wnd);

        syn.set_syn();
        syn.set_option_mss(1460)?;

        let mut ip = Ipv4Header::new(
            self.sock.src.0,
            self.sock.dst.0,
            syn.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        ip.set_header_checksum();
        syn.set_checksum(&ip, &[]);

        // Queue this segment on the send buffer so it can be retransmitted if
        // needed.
        self.send_buf.insert(
            self.snd.una,
            Segment {
                una: self.snd.una,
                ip,
                tcp: syn,
                payload: Default::default(),
                timer: Instant::now(),
                transmit_count: 0,
            },
        );

        TCB::write(nic, &ip, &syn, &[])?;

        Ok(())
    }

    /// Transmits a TCP SYN_ACK packet in response to a connection request.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_syn_ack(&mut self, nic: &mut Tun) -> Result<()> {
        let mut syn_ack =
            TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.iss, self.rcv.wnd);

        // Acknowledge the peer's SYN.
        syn_ack.set_ack_number(self.rcv.nxt);

        syn_ack.set_syn();
        syn_ack.set_ack();
        syn_ack.set_option_mss(1460)?;

        let mut ip = Ipv4Header::new(
            self.sock.src.0,
            self.sock.dst.0,
            syn_ack.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        ip.set_header_checksum();
        syn_ack.set_checksum(&ip, &[]);

        // Queue this segment on the send buffer so it can be retransmitted if
        // needed.
        self.send_buf.insert(
            self.snd.una,
            Segment {
                una: self.snd.una,
                ip,
                tcp: syn_ack,
                payload: Default::default(),
                timer: Instant::now(),
                transmit_count: 0,
            },
        );

        TCB::write(nic, &ip, &syn_ack, &[])?;

        Ok(())
    }

    /// Transmits a TCP ACK packet in response to a peer's TCP segment.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_ack(&mut self, nic: &mut Tun, payload: &[u8]) -> Result<()> {
        let mut ack = TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.nxt, self.rcv.wnd);

        ack.set_ack_number(self.rcv.nxt);
        ack.set_ack();

        let mut ip = Ipv4Header::new(self.sock.src.0, self.sock.dst.0, 0, 64, Protocol::TCP)?;

        ip.set_payload_len((ack.header_len() + payload.len()) as u16)?;

        ip.set_header_checksum();
        ack.set_checksum(&ip, payload);

        if !payload.is_empty() {
            // Queue this segment on the send buffer so it can be retransmitted if
            // needed.
            self.send_buf.insert(
                self.snd.una,
                Segment {
                    una: self.snd.una,
                    ip,
                    tcp: ack,
                    payload: payload.into(),
                    timer: Instant::now(),
                    transmit_count: 0,
                },
            );
        }

        TCB::write(nic, &ip, &ack, payload)?;

        Ok(())
    }

    /// Transmits a TCP FIN_ACK packet for graceful connection termination.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_fin_ack(&mut self, nic: &mut Tun, payload: &[u8]) -> Result<()> {
        let mut fin_ack =
            TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.nxt, self.rcv.wnd);

        fin_ack.set_ack_number(self.rcv.nxt);
        fin_ack.set_fin();
        fin_ack.set_ack();

        let mut ip = Ipv4Header::new(self.sock.src.0, self.sock.dst.0, 0, 64, Protocol::TCP)?;

        ip.set_payload_len((fin_ack.header_len() + payload.len()) as u16)?;

        ip.set_header_checksum();
        fin_ack.set_checksum(&ip, payload);

        // Queue this segment on the send buffer so it can be retransmitted if
        // needed.
        self.send_buf.insert(
            self.snd.una,
            Segment {
                una: self.snd.una,
                ip,
                tcp: fin_ack,
                payload: payload.into(),
                timer: Instant::now(),
                transmit_count: 0,
            },
        );

        TCB::write(nic, &ip, &fin_ack, payload)?;

        Ok(())
    }

    /// Transmits a TCP RST packet to terminate the current connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_rst(&self, nic: &mut Tun, seq: u32, ack: u32) -> Result<()> {
        let mut rst = TcpHeader::new(self.sock.src.1, self.sock.dst.1, seq, 0);

        rst.set_ack_number(ack);
        rst.set_rst();

        if ack != 0 {
            rst.set_ack();
        }

        let mut ip = Ipv4Header::new(
            self.sock.src.0,
            self.sock.dst.0,
            rst.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        ip.set_header_checksum();
        rst.set_checksum(&ip, &[]);

        TCB::write(nic, &ip, &rst, &[])?;

        Ok(())
    }

    /// Writes the IP and TCP headers, along with a payload, to the TUN device.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn write(nic: &mut Tun, ip: &Ipv4Header, tcp: &TcpHeader, payload: &[u8]) -> Result<usize> {
        let mut buf = [0u8; MTU_SIZE];

        let nbytes = {
            let mut unwritten = &mut buf[..];

            ip.write(&mut unwritten)?;
            tcp.write(&mut unwritten)?;

            unwritten.write_all(payload)?;

            MTU_SIZE - unwritten.len()
        };

        nic.send(&buf[..nbytes])
    }
}

/// Logs the details of an incoming TCP segment.
#[inline]
fn log_packet(iph: &Ipv4Header, tcph: &TcpHeader, payload: &[u8]) {
    debug!(
        "received ipv4 datagram | version: {}, ihl: {}, tos: {}, total_len: {}, id: {}, DF: {}, MF: {}, frag_offset: {}, ttl: {}, protocol: {:?}, chksum: 0x{:04x} (valid: {}), src: {:?}, dst: {:?}",
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
        iph.is_valid_checksum(),
        iph.src(),
        iph.dst(),
    );

    debug!(
        "received tcp segment   | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), mss: {:?}",
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
        tcph.is_valid_checksum(iph, payload),
        tcph.options().mss(),
    );

    debug!(
        "received {} bytes of payload: {:x?}",
        payload.len(),
        payload
    );
}

#[inline]
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // RFC 1323 (2.3):
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
/// using wrapping arithmetic.
#[inline]
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
