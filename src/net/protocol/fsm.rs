//! TCP Finite State Machine (FSM), as specified in [RFC 793].
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Write};
use std::time::{Duration, Instant};
use std::{fmt, mem};

use crate::net::headers::{Ipv4Header, Protocol, TcpHeader};
use crate::tun_tap::tun::{MTU_SIZE, Tun};
use crate::{Error, Result};
use crate::{debug, error, warn};

/// Retransmission Timeout (`RTO`) in seconds.
pub const RTO: u64 = 1;

/// Maximum Segment Lifetime (`MSL`) in seconds.
///
/// The MSL represents the maximum time a segment can exist within the network
/// before being discarded.
pub const MSL: u64 = 60;

/// The maximum number of retransmission attempts for a segment before giving up
/// on the connection.
pub const MAX_RETRANSMIT_ATTEMPTS: usize = 5;

/// RFC 1122 (4.2.2.6):
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40).
const DEFAULT_MSS: u16 = 536;

/// Our window size advertised to the peer.
const RCV_WND_SIZE: u16 = 4096;

/// An IPv4 address and a port number.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct SocketAddr {
    /// IPv4 address.
    pub addr: [u8; 4],
    /// Port number.
    pub port: u16,
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.port,
        )
    }
}

/// Unique TCP connection, identified by both the source and destination
/// socket addresses.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Socket {
    /// The source socket address (local IP and port).
    pub src: SocketAddr,
    /// The destination socket address (remote IP and port).
    pub dst: SocketAddr,
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

/// Fully constructed TCP segment queued for retransmission.
#[derive(Debug)]
struct Segment {
    /// IPv4 header of the segment.
    ip: Ipv4Header,
    /// TCP header of the segment.
    tcp: TcpHeader,
    /// Data payload of the segment.
    payload: Vec<u8>,
    /// Timer used in determining whether the segment should be retransmitted.
    timer: Instant,
    /// The number of times the segment has been retransmitted. Used to apply
    /// exponential backoff and determine when to give up on the connection.
    transmit_count: usize,
}

/// Transmission Control Block (TCB).
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct TCB {
    /// Current state of the TCP connection.
    pub state: ConnectionState,
    /// Socket addresses of the host and remote TCPs.
    sock: Socket,
    /// Send Sequence Space for the TCP connection.
    snd: SendSeqSpace,
    /// Receive Sequence Space for the TCP connection.
    rcv: RecvSeqSpace,
    /// Buffer to store in-order data received from peer.
    ///
    /// Stored separately so user buffer can easily be transmitted to user.
    pub usr_buf: VecDeque<u8>,
    /// Buffer to store out-of-order data received from peer.
    ///
    /// BTreeMap used so out of order segments can be retrieved in-order by
    /// sequence number when merging with `usr_buf`.
    rcv_buf: BTreeMap<u32, Vec<u8>>,
    /// Buffer to store acknowledgeable segments sent to the peer.
    ///
    /// Any segments in this buffer which have been unacknowledged will be
    /// retransmitted based on a per-segment timer.
    send_buf: BTreeMap<u32, Segment>,
    /// Timer used to determine when to close a TCP connection in the TIME_WAIT
    /// state.
    pub time_wait: Instant,
    /// Maximum Segment Size (MSS) received from peer.
    peer_mss: u16,
    /// State the current TCP connection was opened in.
    open_kind: OpenKind,
}

/// Different TCP connection states.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
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

/// States a TCP connection could be opened from.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum OpenKind {
    /// TCP connection was opened in a "passive" state (`LISTEN` -> `SYN_RECEIVED`).
    PASSIVE_OPEN,
    /// TCP connection was opened in an "active" state (`CLOSED` -> `SYN_SENT`).
    ACTIVE_OPEN,
}

impl TCB {
    /// Initiates a new TCP connection with the provided socket information.
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
            usr_buf: Default::default(),
            rcv_buf: Default::default(),
            send_buf: Default::default(),
            time_wait: Instant::now(),
            // Will be updated when peer responds.
            peer_mss: 0,
            open_kind: OpenKind::ACTIVE_OPEN,
        };

        debug!(
            "[{}] (ACTIVE_OPEN) sending SYN: ACTIVE_OPEN -> SYN_SENT",
            conn.sock
        );

        conn.send_syn(nic)?;

        Ok(conn)
    }

    /// Processes an incoming TCP connection request for which no connection
    /// state exists.
    pub fn on_conn_req(nic: &mut Tun, iph: &Ipv4Header, tcph: &TcpHeader) -> Result<Option<Self>> {
        log_segment(iph, tcph, &[]);

        // An incoming RST should be ignored.
        if tcph.rst() {
            debug!("(LISTEN) received RST: ignoring");
            return Ok(None);
        }

        // Any acknowledgment is bad if it arrives on a connection still in the
        // LISTEN state.
        if tcph.ack() {
            debug!("(LISTEN) received ACK: sending RST");

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
            debug!("(LISTEN) did not receive SYN: ignoring");
            return Ok(None);
        }

        // Initial Send Sequence Number.
        let iss = 0;

        let mut conn = TCB {
            state: ConnectionState::SYN_RECEIVED,
            // Stored in reverse order of peer's perspective.
            sock: Socket {
                src: SocketAddr {
                    addr: iph.dst(),
                    port: tcph.dst_port(),
                },
                dst: SocketAddr {
                    addr: iph.src(),
                    port: tcph.src_port(),
                },
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
            usr_buf: Default::default(),
            rcv_buf: Default::default(),
            send_buf: Default::default(),
            time_wait: Instant::now(),
            peer_mss: tcph.options().mss().unwrap_or(DEFAULT_MSS),
            open_kind: OpenKind::PASSIVE_OPEN,
        };

        debug!(
            "[{}] (LISTEN) received SYN, sending SYN_ACK: LISTEN/PASSIVE_OPEN -> SYN_RECEIVED",
            conn.sock
        );

        conn.send_syn_ack(nic)?;

        Ok(Some(conn))
    }

    /// Processes an existing connection's retransmission queue for expired
    /// timers or acknowledged segments. Determines whether segments should be
    /// retransmitted to the peer, returning the [Duration] of when the next
    /// segment will expire.
    pub fn on_conn_tick(&mut self, nic: &mut Tun) -> Result<Duration> {
        if !self.send_buf.is_empty() {
            // Track the segment with the closest time to expire.
            let mut nearest_timer = Duration::MAX;

            // Remove segments that have been acknowledged fully or have been
            // retransmitted `MAX_RETRANSMIT_ATTEMPTS` times.
            self.send_buf.retain(|_, seg| {
                let seg_len = seg.payload.len() as u32
                    + if seg.tcp.syn() { 1 } else { 0 }
                    + if seg.tcp.fin() { 1 } else { 0 };

                // Apply exponential backoff to avoid excessive retransmissions.
                let effective_rto = Duration::from_secs(RTO * (1 << seg.transmit_count));

                // A segment on the retransmission queue is fully acknowledged
                // if the sum of its sequence number and length is less or equal
                // than the acknowledgment value in the incoming segment.
                if seg.tcp.seq_number().wrapping_add(seg_len) <= self.snd.una {
                    false
                } else if seg.timer.elapsed() >= effective_rto {
                    // Need to close the connection.
                    if seg.transmit_count >= MAX_RETRANSMIT_ATTEMPTS {
                        warn!(
                            "[{}] ({state:?}) max retransmit attempts reached, sending RST: {state:?} -> CLOSED",
                            self.sock,
                            state = self.state,
                        );

                        // Can't borrow `self` so manually creating RST segment.
                        let mut rst =
                            TcpHeader::new(self.sock.src.port, self.sock.dst.port, self.snd.nxt, 0);

                        rst.set_rst();

                        // SAFETY: The payload length is less than the maximum 
                        // payload length allowed.
                        let mut ip = Ipv4Header::new(
                            self.sock.src.addr,
                            self.sock.dst.addr,
                            rst.header_len() as u16,
                            64,
                            Protocol::TCP,
                        ).unwrap();

                        ip.set_header_checksum();
                        rst.set_checksum(&ip, &[]);

                        if let Err(err) = TCB::write(nic, &ip, &rst, &[]) {
                            error!("{err}");
                        }

                        // Used to indicate connection can be removed.
                        self.state = ConnectionState::CLOSED;

                        false
                    } else {
                        // Retransmit segment.
                        seg.timer = Instant::now();
                        seg.transmit_count += 1;

                        if let Err(err) = TCB::write(nic, &seg.ip, &seg.tcp, &seg.payload) {
                            error!("{err}");
                        }

                        debug!(
                            "[{}] ({:?}) segment retransmitted, updated transmit count: {}",
                            self.sock, self.state, seg.transmit_count
                        );

                        true
                    }
                } else {
                    // Peer still has time to ACK the segment...
                    //
                    // Track the nearest timer to expire.
                    let remaining = effective_rto - seg.timer.elapsed();

                    if remaining < nearest_timer {
                        nearest_timer = remaining;
                    }

                    true
                }
            });

            return Ok(nearest_timer);
        }

        // No segments on retransmission queue.
        Ok(Duration::MAX)
    }

    /// Processes an incoming TCP segment for an existing connection.
    ///
    /// TCP State Diagram (RFC 793 3.2):
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
                io::ErrorKind::ConnectionReset,
                "connection reset",
            )));
        }

        log_segment(iph, tcph, payload);

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();

        if let ConnectionState::SYN_SENT = self.state {
            // Do not process an incoming FIN since SEG.SEQ cannot be validated.
            if tcph.fin() {
                debug!("[{}] (SYN_SENT) received FIN: ignoring", self.sock);
                return Ok(());
            }

            let mut validate_ack = || {
                // Peer did not correctly ACK our SYN.
                if ackn <= self.snd.iss || ackn > self.snd.nxt {
                    if tcph.rst() {
                        return Err(Error::Io(io::Error::other(format!(
                            "[{}] (SYN_SENT) invalid ACK number with RST: ignoring",
                            self.sock
                        ))));
                    }

                    warn!(
                        "[{}] (SYN_SENT) connection refused, sending RST: SYN_SENT -> CLOSED",
                        self.sock
                    );

                    self.send_rst(nic, ackn, 0)?;

                    self.state = ConnectionState::CLOSED;

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
                    return Err(Error::Io(io::Error::other(format!(
                        "[{}] (SYN_SENT) unacceptable ACK number {}: ignoring",
                        self.sock, ackn,
                    ))));
                }

                if tcph.rst() {
                    warn!(
                        "[{}] (SYN_SENT) received RST, connection refused: SYN_SENT -> CLOSED",
                        self.sock
                    );

                    self.state = ConnectionState::CLOSED;

                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connection refused",
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

                    // Our SYN was ACKed.
                    self.snd.una = ackn;

                    debug!(
                        "[{}] (SYN_SENT) received SYN_ACK, sending ACK: SYN_SENT -> ESTABLISHED",
                        self.sock
                    );

                    self.send_ack(nic, &[])?;

                    self.state = ConnectionState::ESTABLISHED;
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

                    debug!(
                        "[{}] (SYN_SENT) received SYN, sending SYN_ACK: SYN_SENT -> SYN_RECEIVED",
                        self.sock
                    );

                    self.send_syn_ack(nic)?;

                    self.state = ConnectionState::SYN_RECEIVED;

                    // Accounting for the SYN sent.
                    self.snd.nxt = self.snd.nxt.wrapping_add(1);
                }
                (false, true) => {
                    // Case 3: Only ACK received (validate ACK).

                    // If the ACK number received is valid, we continue to wait
                    // in the SYN_SENT state for a valid segment.
                    validate_ack()?;

                    // Received an ACK for out SYN.
                    self.snd.una = ackn;

                    debug!(
                        "[{}] (SYN_SENT) received valid ACK: waiting for SYN",
                        self.sock
                    );
                }
                (false, false) => {
                    // Case 4: Neither SYN or ACK received (return).
                    debug!(
                        "[{}] (SYN_SENT) received neither SYN or ACK: ignoring",
                        self.sock
                    );
                }
            }

            return Ok(());
        }

        // The number of octets occupied by the data in the segment (counting
        // SYN and FIN).
        let seg_len =
            payload.len() as u32 + if tcph.syn() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

        let nxt_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

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
        let invalid_seg = match seg_len {
            0 => match self.rcv.wnd {
                0 => {
                    // Case 1: SEG.SEQ = RCV.NXT
                    seqn != self.rcv.nxt
                }
                _ => {
                    // Case 2: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                    !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd)
                }
            },
            len => match self.rcv.wnd {
                0 => {
                    // Case 3: not acceptable (we have received bytes when we
                    // are advertising a window size of 0).
                    //
                    // If the RCV.WND is zero, no segments will be acceptable, but special
                    // allowance should be made to accept valid ACKs, URGs and RSTs.
                    true
                }
                _ => {
                    // Case 4: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                    //      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
                    !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd)
                        && !is_between_wrapped(
                            self.rcv.nxt.wrapping_sub(1),
                            seqn.wrapping_add(len - 1),
                            nxt_wnd,
                        )
                }
            },
        };

        if invalid_seg {
            debug!(
                "[{}] ({:?}) received invalid SEQ number {}: ignoring",
                self.sock, self.state, seqn
            );

            if !tcph.rst() {
                self.send_ack(nic, &[])?;
            }

            return Ok(());
        }

        if tcph.rst() {
            warn!(
                "[{}] ({state:?}) received RST, connection reset: {state:?} -> CLOSED",
                self.sock,
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
                _ => {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }
            }
        }

        if tcph.syn() {
            warn!(
                "[{}] ({state:?}) received SYN: {state:?} -> CLOSED",
                self.sock,
                state = self.state,
            );

            if tcph.ack() {
                self.send_rst(nic, ackn, 0)?;
            } else {
                self.send_rst(nic, 0, seqn.wrapping_add(seg_len))?;
            }

            self.state = ConnectionState::CLOSED;

            return Err(Error::Io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection reset",
            )));
        }

        if !tcph.ack() {
            debug!(
                "[{}] ({:?}) did not receive ACK: ignoring",
                self.sock, self.state,
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
                        "[{}] (SYN_RECEIVED) received unacceptable ACK number {}, sending RST: SYN_RECEIVED -> CLOSED",
                        self.sock, ackn,
                    );

                    self.send_rst(nic, ackn, 0)?;

                    self.state = ConnectionState::CLOSED;

                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }

                debug!(
                    "[{}] (SYN_RECEIVED) received valid ACK: SYN_RECEIVED -> ESTABLISHED",
                    self.sock
                );

                self.state = ConnectionState::ESTABLISHED;
            }

            if let ConnectionState::ESTABLISHED
            | ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2
            | ConnectionState::CLOSE_WAIT
            | ConnectionState::CLOSING
            | ConnectionState::LAST_ACK = self.state
            {
                if ackn < self.snd.una {
                    debug!(
                        "[{}] ({:?}) received duplicate ACK number {}: ignoring",
                        self.sock, self.state, ackn
                    );

                    return Ok(());
                } else if ackn > self.snd.nxt {
                    debug!(
                        "[{}] ({:?}) received ACK number {} for untransmitted data: sending ACK",
                        self.sock, self.state, ackn
                    );

                    self.send_ack(nic, &[])?;

                    return Ok(());
                } else {
                    // If SND.UNA < SEG.ACK =< SND.NXT then, set
                    // SND.UNA <- SEG.ACK.
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

                            debug!(
                                "[{}] ({:?}) updated send window, new size: {}",
                                self.sock, self.state, self.snd.wnd
                            );
                        }
                    }
                }

                match self.state {
                    ConnectionState::ESTABLISHED => {
                        // Immediately reply with a FIN_ACK to simulate closing
                        // connection from the local side.
                        //                        debug!(
                        //                            "[{}] (ESTABLISHED) sending FIN_ACK: ESTABLISHED -> FIN_WAIT_1",
                        //                            self.sock
                        //                        );
                        //
                        //                        self.send_fin_ack(nic, &[])?;
                        //
                        //                        self.state = ConnectionState::FIN_WAIT_1;
                        //
                        //                        // Account for the FIN sent.
                        //                        self.snd.nxt = self.snd.nxt.wrapping_add(1);
                    }
                    ConnectionState::FIN_WAIT_1 => {
                        debug!(
                            "[{}] (FIN_WAIT_1) received ACK for FIN: FIN_WAIT_1 -> FIN_WAIT_2",
                            self.sock
                        );

                        self.state = ConnectionState::FIN_WAIT_2;
                    }
                    ConnectionState::FIN_WAIT_2 | ConnectionState::CLOSE_WAIT => {}
                    ConnectionState::CLOSING => {
                        debug!(
                            "[{}] (CLOSING) received ACK for FIN: CLOSING -> TIME_WAIT",
                            self.sock
                        );

                        self.time_wait = Instant::now();
                        self.state = ConnectionState::TIME_WAIT;
                    }
                    ConnectionState::LAST_ACK => {
                        warn!(
                            "[{}] (LASK_ACK) received ACK for FIN: LAST_ACK -> CLOSED",
                            self.sock
                        );

                        self.state = ConnectionState::CLOSED;

                        return Err(Error::Io(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "connection reset",
                        )));
                    }
                    _ => unreachable!(),
                }
            }

            if let ConnectionState::ESTABLISHED
            | ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2 = self.state
            {
                if seg_len > 0 {
                    if !payload.is_empty() {
                        match seqn.cmp(&self.rcv.nxt) {
                            // We received the next bytes we were expecting.
                            Ordering::Equal => {
                                self.usr_buf.extend(payload);

                                self.rcv.nxt = self.rcv.nxt.wrapping_add(payload.len() as u32);
                                self.rcv.wnd = self.rcv.wnd.saturating_sub(payload.len() as u16);

                                debug!(
                                    "[{}] ({:?}) received expected payload: buffering in-order",
                                    self.sock, self.state
                                );

                                // Check if out-of-order segments can now be
                                // merged.
                                self.rcv_buf.retain(|seq, data| {
                                    // Not the next bytes we expect.
                                    if *seq != self.rcv.nxt {
                                        true
                                    } else {
                                        let payload = mem::take(data);
                                        let len = payload.len();

                                        self.usr_buf.extend(payload);

                                        self.rcv.nxt = self.rcv.nxt.wrapping_add(len as u32);
                                        self.rcv.wnd = self.rcv.wnd.saturating_sub(len as u16);

                                        false
                                    }
                                });
                            }
                            // Received data we were not expecting yet. Data is
                            // buffered but RCV.NXT is kept the same.
                            Ordering::Greater => {
                                // Buffer as an out-of-order payload. Wait to
                                // merge with user buffer on receiving new
                                // in-order data.
                                debug!(
                                    "[{}] ({:?}) received out-of-order payload: buffering out-of-order",
                                    self.sock, self.state
                                );
                                self.rcv_buf.insert(seqn, payload.into());
                            }
                            // Part of the segment overlaps data we have already
                            // received.
                            Ordering::Less => {
                                // Don't need wrapping_sub() since RCV.NXT is
                                // determined to be greater.
                                let start = (self.rcv.nxt.wrapping_sub(seqn)) as usize;

                                if payload.len() <= start {
                                    // Entire payload is old/duplicate data...
                                    debug!(
                                        "[{}] ({:?}) received fully old/duplicate payload: ignoring",
                                        self.sock, self.state
                                    );
                                } else {
                                    // Discard old/duplicate portion.
                                    let payload = &payload[start..];

                                    self.usr_buf.extend(payload);

                                    self.rcv.nxt = self.rcv.nxt.wrapping_add(payload.len() as u32);
                                    self.rcv.wnd =
                                        self.rcv.wnd.saturating_sub(payload.len() as u16);

                                    debug!(
                                        "[{}] ({:?}) received partially old/duplicate payload: buffering expected portion in-order",
                                        self.sock, self.state
                                    );

                                    // Check if out-of-order segments can now be
                                    // merged.
                                    self.rcv_buf.retain(|seq, data| {
                                        // Not the next bytes we expect.
                                        if *seq != self.rcv.nxt {
                                            true
                                        } else {
                                            let payload = mem::take(data);
                                            let len = payload.len();

                                            self.usr_buf.extend(payload);

                                            self.rcv.nxt = self.rcv.nxt.wrapping_add(len as u32);
                                            self.rcv.wnd = self.rcv.wnd.saturating_sub(len as u16);

                                            false
                                        }
                                    });
                                }
                            }
                        }
                    }

                    if tcph.fin() {
                        // Accounting for the received FIN.
                        self.rcv.nxt = self.rcv.nxt.wrapping_add(1);

                        // Peer is done sending data, merge what we can.
                        self.rcv_buf.retain(|seq, data| {
                            // Not the next bytes we expect.
                            if *seq != self.rcv.nxt {
                                true
                            } else {
                                let payload = mem::take(data);
                                let len = payload.len();

                                self.usr_buf.extend(payload);

                                self.rcv.nxt = self.rcv.nxt.wrapping_add(len as u32);
                                self.rcv.wnd = self.rcv.wnd.saturating_sub(len as u16);

                                false
                            }
                        });

                        match self.state {
                            ConnectionState::ESTABLISHED => {
                                debug!(
                                    "[{}] (ESTABLISHED) received FIN: ESTABLISHED -> CLOSE_WAIT",
                                    self.sock
                                );

                                self.state = ConnectionState::CLOSE_WAIT;

                                // Immediately reply with a FIN_ACK for now.
                                debug!(
                                    "[{}] (CLOSE_WAIT) sending FIN_ACK: CLOSE_WAIT -> LAST_ACK",
                                    self.sock
                                );

                                self.send_fin_ack(nic, &[])?;

                                self.state = ConnectionState::LAST_ACK;

                                // Account for the FIN sent.
                                self.snd.nxt = self.snd.nxt.wrapping_add(1);
                            }
                            ConnectionState::FIN_WAIT_1 => {
                                debug!(
                                    "[{}] (FIN_WAIT_1) received FIN: FIN_WAIT_1 -> CLOSING",
                                    self.sock
                                );

                                self.state = ConnectionState::CLOSING;
                            }
                            ConnectionState::FIN_WAIT_2 => {
                                debug!(
                                    "[{}] (FIN_WAIT_2) received FIN: FIN_WAIT_2 -> TIME_WAIT",
                                    self.sock
                                );

                                // Timer is not set here since we will cascade
                                // down to the TIME_WAIT code block and set the
                                // timer as well as acknowledge the FIN.
                                self.state = ConnectionState::TIME_WAIT;
                            }
                            _ => unreachable!(),
                        }
                    }

                    // Since FIN_WAIT_2 -> TIME_WAIT will cascade down and
                    // respond with an ACK from there.
                    //
                    // LAST_ACK already sends an ACK with it's FIN.
                    if !matches!(
                        self.state,
                        ConnectionState::TIME_WAIT | ConnectionState::LAST_ACK
                    ) {
                        debug!(
                            "[{}] ({:?}) received data: sending ACK",
                            self.sock, self.state,
                        );

                        self.send_ack(nic, &[])?;
                    }
                }
            }

            if let ConnectionState::TIME_WAIT = self.state {
                // TIME-WAIT STATE
                //
                // The only thing that can arrive in this state is a
                // retransmission of the remote FIN. Acknowledge it, and restart
                // the 2 MSL timeout.
                if tcph.fin() {
                    debug!("[{}] (TIME_WAIT) received FIN: resetting timer", self.sock,);

                    self.time_wait = Instant::now();
                    self.send_ack(nic, &[])?;
                }
            }
        }

        Ok(())
    }

    /// Transmits a TCP SYN segment to initiate a connection.
    fn send_syn(&mut self, nic: &mut Tun) -> Result<()> {
        let mut syn = TcpHeader::new(
            self.sock.src.port,
            self.sock.dst.port,
            self.snd.iss,
            self.rcv.wnd,
        );

        syn.set_syn();
        syn.set_option_mss(1460)?;

        let mut ip = Ipv4Header::new(
            self.sock.src.addr,
            self.sock.dst.addr,
            syn.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        ip.set_header_checksum();
        syn.set_checksum(&ip, &[]);

        // Queue this segment on the retransmission buffer.
        self.send_buf.insert(
            self.snd.una,
            Segment {
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

    /// Transmits a TCP SYN_ACK segment in response to a connection request.
    fn send_syn_ack(&mut self, nic: &mut Tun) -> Result<()> {
        let mut syn_ack = TcpHeader::new(
            self.sock.src.port,
            self.sock.dst.port,
            self.snd.iss,
            self.rcv.wnd,
        );

        // Acknowledge the peer's SYN.
        syn_ack.set_ack_number(self.rcv.nxt);
        syn_ack.set_syn();
        syn_ack.set_ack();
        syn_ack.set_option_mss(1460)?;

        let mut ip = Ipv4Header::new(
            self.sock.src.addr,
            self.sock.dst.addr,
            syn_ack.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        ip.set_header_checksum();
        syn_ack.set_checksum(&ip, &[]);

        // Queue this segment on the retransmission buffer.
        self.send_buf.insert(
            self.snd.una,
            Segment {
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

    /// Transmits a TCP ACK segment in response to a peer's TCP segment.
    pub fn send_ack(&mut self, nic: &mut Tun, payload: &[u8]) -> Result<()> {
        let mut ack = TcpHeader::new(
            self.sock.src.port,
            self.sock.dst.port,
            self.snd.nxt,
            self.rcv.wnd,
        );

        ack.set_ack_number(self.rcv.nxt);
        ack.set_ack();

        if !payload.is_empty() {
            ack.set_psh();
        }

        let mut ip = Ipv4Header::new(self.sock.src.addr, self.sock.dst.addr, 0, 64, Protocol::TCP)?;

        ip.set_payload_len((ack.header_len() + payload.len()) as u16)?;

        ip.set_header_checksum();
        ack.set_checksum(&ip, payload);

        if !payload.is_empty() {
            // Queue this segment on the retransmission buffer.
            self.send_buf.insert(
                self.snd.una,
                Segment {
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

    /// Transmits a TCP FIN_ACK segment for graceful connection termination.
    fn send_fin_ack(&mut self, nic: &mut Tun, payload: &[u8]) -> Result<()> {
        let mut fin_ack = TcpHeader::new(
            self.sock.src.port,
            self.sock.dst.port,
            self.snd.nxt,
            self.rcv.wnd,
        );

        fin_ack.set_ack_number(self.rcv.nxt);
        fin_ack.set_fin();
        fin_ack.set_ack();

        let mut ip = Ipv4Header::new(self.sock.src.addr, self.sock.dst.addr, 0, 64, Protocol::TCP)?;

        ip.set_payload_len((fin_ack.header_len() + payload.len()) as u16)?;

        ip.set_header_checksum();
        fin_ack.set_checksum(&ip, payload);

        // Queue this segment on the retransmission buffer.
        self.send_buf.insert(
            self.snd.una,
            Segment {
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

    /// Transmits a TCP RST segment to terminate the current connection.
    fn send_rst(&self, nic: &mut Tun, seq: u32, ack: u32) -> Result<()> {
        let mut rst = TcpHeader::new(self.sock.src.port, self.sock.dst.port, seq, 0);

        rst.set_rst();

        if ack != 0 {
            rst.set_ack_number(ack);
            rst.set_ack();
        }

        let mut ip = Ipv4Header::new(
            self.sock.src.addr,
            self.sock.dst.addr,
            rst.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        ip.set_header_checksum();
        rst.set_checksum(&ip, &[]);

        TCB::write(nic, &ip, &rst, &[])?;

        Ok(())
    }

    /// Writes an IP packet, encapsulating a TCP segment, to the TUN device.
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
fn log_segment(iph: &Ipv4Header, tcph: &TcpHeader, payload: &[u8]) {
    debug!(
        "received ipv4 packet   | version: {}, ihl: {}, tos: {}, total_len: {}, id: {}, DF: {}, MF: {}, frag_offset: {}, ttl: {}, protocol: {:?}, chksum: 0x{:04x} (valid: {}), src: {:?}, dst: {:?}",
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
