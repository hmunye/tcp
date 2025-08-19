//! TCP finite state machine (FSM), as described in [RFC 793].
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};
use std::{io, mem};

use super::TcpSegment;
use super::headers::{Ipv4Header, Protocol, TcpHeader};
use super::{Socket, SocketAddr};
use crate::{Error, Result};
use crate::{debug, error, warn};

/// Initial Retransmission Timeout (`RTO`) in seconds.
pub const RTO: u64 = 1;

/// Maximum Segment Lifetime (`MSL`) in seconds.
///
/// Represents the maximum time a segment can exist within the network before
/// being discarded.
pub const MSL: u64 = 60;

/// The maximum retry limit for retransmissions before giving up on the
/// connection.
pub const MAX_RETRANSMIT_LIMIT: usize = 5;

/// RFC 1122 (4.2.2.6)
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40).
const DEFAULT_TCP_MSS: u16 = 536;

/// Our window size advertised to the peer.
const RCV_WND_SIZE: u16 = 4096;

/// TCP segment queued for retransmission.
#[derive(Debug)]
struct RetransmissionSegment {
    /// TCP segment to retransmit.
    segment: TcpSegment,
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
    /// Stored separately so user buffer can easily be transmitted to user
    /// in-order.
    usr_buf: Vec<u8>,
    /// Buffer to store out-of-order data received from peer.
    ///
    /// BTreeMap used so out of order segments can be retrieved in-order by
    /// sequence number when merging with `usr_buf`.
    rcv_buf: BTreeMap<u32, Vec<u8>>,
    /// Buffer to store in-order data sent by the application.
    ///
    /// Any data that could not be sent due to the peer window closing is
    /// buffered and attempted to be piggybacked on future ACK segments.
    snd_buf: VecDeque<Vec<u8>>,
    /// Buffer to store acknowledgeable segments sent to the peer.
    ///
    /// Any segments in this buffer which have been unacknowledged will be
    /// retransmitted based on a per-segment timer.
    retransmit_buf: BTreeMap<u32, RetransmissionSegment>,
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

/// Send Sequence Space.
///
/// (RFC 793 3.2)
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

/// Receive Sequence Space.
///
/// (RFC 793 3.2)
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
    /// Initiates a new TCP connection with the provided socket information,
    /// returning a newly created TCB and `SYN` segment pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SYN` segment could not be constructed.
    pub fn open_conn_active(socket: Socket) -> Result<(Self, TcpSegment)> {
        // Not a good initial send sequence number since to avoid  confusion
        // we must prevent segments from one incarnation of a connection from
        // being used while the same sequence numbers may still be present in
        // the network from an earlier incarnation.
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
            snd_buf: Default::default(),
            retransmit_buf: Default::default(),
            time_wait: Instant::now(),
            // Will be updated when peer responds.
            peer_mss: 0,
            open_kind: OpenKind::ACTIVE_OPEN,
        };

        // <SEQ=ISS><CTL=SYN>
        let syn = conn.create_syn()?;

        debug!(
            "[{}] (CLOSED) constructing SYN: CLOSED/ACTIVE_OPEN -> SYN_SENT",
            conn.sock
        );

        Ok((conn, syn))
    }

    /// Processes an incoming TCP connection request for which no connection
    /// state exists, returning a newly created TCB and `SYN_ACK` segment pair.
    ///
    /// - If the incoming segment contains an `RST` or no `SYN`, no TCB or TCP
    ///   segment is returned.
    ///
    /// - If the incoming segment contains an `ACK`, no TCB and an `RST` segment
    ///   is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if either the `SYN_ACK` or `RST` segments could not be
    /// constructed.
    pub fn open_conn_passive(
        iph: &Ipv4Header,
        tcph: &TcpHeader,
    ) -> Result<(Option<Self>, Option<TcpSegment>)> {
        log_segment(iph, tcph, &[]);

        // An incoming RST should be ignored.
        if tcph.rst() {
            debug!("(LISTEN) received RST: ignoring");
            return Ok((None, None));
        }

        // Any acknowledgment is bad if it arrives on a connection still in the
        // LISTEN state. An acceptable reset segment should be formed for any
        // arriving ACK-bearing segment.
        if tcph.ack() {
            // <SEQ=SEG.ACK><CTL=RST>
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

            debug!("(LISTEN) received ACK: constructing RST");

            return Ok((None, Some(TcpSegment::new(ip, rst, &[]))));
        }

        if !tcph.syn() {
            debug!("(LISTEN) did not receive SYN: ignoring");
            return Ok((None, None));
        }

        // Not a good initial send sequence number since to avoid  confusion
        // we must prevent segments from one incarnation of a connection from
        // being used while the same sequence numbers may still be present in
        // the network from an earlier incarnation.
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
            snd_buf: Default::default(),
            retransmit_buf: Default::default(),
            time_wait: Instant::now(),
            peer_mss: tcph.options().mss().unwrap_or(DEFAULT_TCP_MSS),
            open_kind: OpenKind::PASSIVE_OPEN,
        };

        // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        let syn_ack = conn.create_syn_ack()?;

        debug!(
            "[{}] (LISTEN) received SYN, constructing SYN_ACK: LISTEN/PASSIVE_OPEN -> SYN_RECEIVED",
            conn.sock
        );

        Ok((Some(conn), Some(syn_ack)))
    }

    /// Returns `PSH_ACK` segments derived from the data provided to transmit
    /// to the peer of the connection. If the peer's send window is 0, data is
    /// buffered and no segments are returned.
    ///
    /// No application data will be segmented until the connection is in a
    /// fully established state ready for sending data (`ESTABLISHED` or `CLOSE_WAIT`).
    ///
    /// # Errors
    ///
    /// Returns an error if any `PSH_ACK` segments could not be constructed or
    /// the connection is in an invalid state for sending data.
    pub fn conn_send(&mut self, buf: &[u8]) -> Result<VecDeque<TcpSegment>> {
        if !matches!(
            self.state,
            ConnectionState::ESTABLISHED | ConnectionState::CLOSE_WAIT,
        ) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "unable to send application data",
            )));
        }

        if self.snd.wnd == 0 {
            debug!(
                "[{}] ({:?}) buffering unsent data due to window size",
                self.sock, self.state
            );

            self.snd_buf.push_back(buf[..].to_vec());
            return Ok(Default::default());
        }

        // Respect the transmitted MSS and the SND.WND of the peer.
        let seg_size = u16::min(self.snd.wnd, self.peer_mss);

        let mut psh_acks = VecDeque::new();
        let mut pos = 0;

        while pos < buf.len() {
            let chunk_len = usize::min(seg_size as usize, buf.len() - pos);

            if self.snd.wnd as usize >= chunk_len {
                psh_acks.push_back(self.create_ack(&buf[pos..pos + chunk_len])?);

                pos += chunk_len;
                self.snd.wnd -= chunk_len as u16;
                self.snd.nxt = self.snd.nxt.wrapping_add(chunk_len as u32);
            } else {
                debug!(
                    "[{}] ({:?}) buffering unsent data due to window size",
                    self.sock, self.state
                );

                // Segment the rest of the buffer up to the peer's window size.
                psh_acks.push_back(self.create_ack(&buf[pos..pos + self.snd.wnd as usize])?);

                self.snd.wnd = 0;
                self.snd.nxt = self.snd.nxt.wrapping_add(self.snd.wnd as u32);

                pos += self.snd.wnd as usize;

                // Buffer unsent data for future piggybacking.
                self.snd_buf.push_back(buf[pos..].to_vec());

                break;
            }
        }

        Ok(psh_acks)
    }

    /// Writes to the provided buffer with in-order buffered data received from
    /// the peer of the connection, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is not in a valid state to receive
    /// data.
    pub fn conn_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !matches!(
            self.state,
            ConnectionState::ESTABLISHED
                | ConnectionState::FIN_WAIT_1
                | ConnectionState::FIN_WAIT_2
                | ConnectionState::CLOSE_WAIT,
        ) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "unable to receive connection data",
            )));
        }

        let min = usize::min(self.usr_buf.len(), buf.len());

        let drained = self.usr_buf.drain(..min);
        buf.copy_from_slice(drained.as_slice());

        self.rcv.wnd = self.rcv.wnd.saturating_add(min as u16);

        Ok(min)
    }

    /// Returns an optional `FIN_ACK` segment to initiate the process of a
    /// graceful connection termination.
    ///
    /// Connections in a state where a `FIN` segment has been transmitted will
    /// not construct a `FIN_ACK` segment.
    ///
    /// # Errors
    ///
    /// Returns an error if the `FIN_ACK` segment could not be constructed or
    /// the connection is in the `SYN_SENT` state, indicating the connection
    /// should be closed immediately.
    pub fn conn_close(&mut self) -> Result<Option<TcpSegment>> {
        match self.state {
            ConnectionState::SYN_SENT => {
                warn!(
                    "[{}] (SYN_SENT) close call received, closing connection: SYN_SENT -> CLOSED",
                    self.sock,
                );

                self.state = ConnectionState::CLOSED;

                Err(Error::Io(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection closing",
                )))
            }
            ConnectionState::SYN_RECEIVED | ConnectionState::ESTABLISHED => {
                let fin_ack = self.create_fin_ack(&[])?;
                self.state = ConnectionState::FIN_WAIT_1;

                debug!(
                    "[{}] ({state:?}) close call received, constructing FIN_ACK: {state:?} -> FIN_WAIT_1",
                    self.sock,
                    state = self.state
                );

                Ok(Some(fin_ack))
            }
            ConnectionState::CLOSE_WAIT => {
                let fin_ack = self.create_fin_ack(&[])?;

                // CLOSE-WAIT STATE
                //
                // Queue this request until all preceding SENDs have been
                // segmentized; then send a FIN segment, enter CLOSING state.
                self.state = ConnectionState::CLOSING;

                debug!(
                    "[{}] (CLOSE_WAIT) close call received, constructing FIN_ACK: CLOSE_WAIT -> CLOSING",
                    self.sock
                );

                Ok(Some(fin_ack))
            }
            ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2
            | ConnectionState::CLOSING
            | ConnectionState::LAST_ACK
            | ConnectionState::TIME_WAIT => {
                debug!(
                    "[{}] ({:?}) close call received: ignoring",
                    self.sock, self.state
                );

                Ok(None)
            }
            _ => unreachable!(),
        }
    }

    /// Processes an incoming TCP segment for an existing connection, returning
    /// an optional constructed segment to transmit depending on the current
    /// state.
    ///
    /// The caller can determine if a connection is ready to be closed if the
    /// connection state is transitioned to `CLOSED` or a [ConnectionReset] or
    /// [ConnectionRefused] error is returned. A `RST` segment returned should
    /// be transmitted to the peer.
    ///
    /// Errors of [ErrorKind::Other] returned indicate the peer transmitted an
    /// invalid segment but the connection remains open.
    ///
    /// [ConnectionReset]: std::io::ErrorKind::ConnectionReset
    /// [ConnectionRefused]: std::io::ErrorKind::ConnectionRefused
    /// [ErrorKind::Other]: std::io::ErrorKind::Other
    ///
    /// TCP State Diagram.
    ///
    /// (RFC 793 3.2)
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
    ///
    /// # Errors
    ///
    /// Returns an error if the connection's state is `LISTEN` or `CLOSED`, the
    /// connection was terminated by the peer, or any segments to transmit could
    /// not be constructed.
    pub fn on_conn_packet(
        &mut self,
        iph: &Ipv4Header,
        tcph: &TcpHeader,
        payload: &[u8],
    ) -> Result<Option<TcpSegment>> {
        // This should never happen, but just in case...
        if let ConnectionState::CLOSED | ConnectionState::LISTEN = self.state {
            error!(
                "[{}] ({:?}) existing connection should not be in CLOSED or LISTEN state",
                self.sock, self.state
            );

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
                return Ok(None);
            }

            let mut validate_ack = || {
                // Peer did not correctly ACK our SYN.
                if ackn <= self.snd.iss || ackn > self.snd.nxt {
                    if tcph.rst() {
                        debug!(
                            "[{}] (SYN_SENT) invalid ACK number {} with RST: ignoring",
                            self.sock, ackn,
                        );

                        return Err(Error::Io(io::Error::other(
                            "(SYN_SENT) invalid segment received",
                        )));
                    }

                    // <SEQ=SEG.ACK><CTL=RST>
                    let rst = self.create_rst(ackn, 0)?;

                    self.state = ConnectionState::CLOSED;
                    warn!(
                        "[{}] (SYN_SENT) received invalid ACK, constructing RST: SYN_SENT -> CLOSED",
                        self.sock
                    );

                    return Ok(Some(rst));
                }

                // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                //
                // If not, return and continue to wait for an acceptable ACK.
                if !is_between_wrapped(
                    self.snd.una.wrapping_sub(1),
                    ackn,
                    self.snd.nxt.wrapping_add(1),
                ) {
                    debug!(
                        "[{}] (SYN_SENT) unacceptable ACK number {}: ignoring",
                        self.sock, ackn,
                    );

                    return Err(Error::Io(io::Error::other(
                        "(SYN_SENT) invalid segment received",
                    )));
                }

                if tcph.rst() {
                    warn!(
                        "[{}] (SYN_SENT) received RST, connection reset: SYN_SENT -> CLOSED",
                        self.sock
                    );

                    self.state = ConnectionState::CLOSED;

                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )));
                }

                Ok(None)
            };

            match (tcph.syn(), tcph.ack()) {
                (true, true) => {
                    // Case 1: SYN and ACK received (send ACK).
                    if let Some(rst) = validate_ack()? {
                        return Ok(Some(rst));
                    }

                    // Previously unknown values can now be updated using
                    // incoming segment.
                    self.rcv.nxt = seqn.wrapping_add(1);
                    self.rcv.up = tcph.urgent_pointer();
                    self.rcv.irs = seqn;
                    self.snd.wnd = tcph.window();
                    self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_TCP_MSS);

                    // Our SYN was ACKed.
                    self.snd.una = ackn;

                    debug!(
                        "[{}] (SYN_SENT) received SYN_ACK, constructed ACK: SYN_SENT -> ESTABLISHED",
                        self.sock
                    );

                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                    let ack = self.create_ack(&[])?;

                    self.state = ConnectionState::ESTABLISHED;

                    return Ok(Some(ack));
                }
                (true, false) => {
                    // Case 2: Only SYN received (send SYN_ACK).
                    if tcph.rst() {
                        // Ignore RST without ACK.
                        return Ok(None);
                    }

                    // Previously unknown values can now be updated using
                    // incoming segment.
                    self.rcv.nxt = seqn.wrapping_add(1);
                    self.rcv.up = tcph.urgent_pointer();
                    self.rcv.irs = seqn;
                    self.snd.wnd = tcph.window();
                    self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_TCP_MSS);

                    // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                    let syn_ack = self.create_syn_ack()?;

                    debug!(
                        "[{}] (SYN_SENT) received SYN, constructed SYN_ACK: SYN_SENT -> SYN_RECEIVED",
                        self.sock
                    );

                    self.state = ConnectionState::SYN_RECEIVED;

                    // Accounting for the SYN sent.
                    self.snd.nxt = self.snd.nxt.wrapping_add(1);

                    return Ok(Some(syn_ack));
                }
                (false, true) => {
                    // Case 3: Only ACK received (validate ACK).

                    // If the ACK number received is valid, we continue to wait
                    // in the SYN_SENT state for a valid segment.
                    if let Some(rst) = validate_ack()? {
                        return Ok(Some(rst));
                    }

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

            return Ok(None);
        }

        // The number of octets occupied by the data in the segment (counting
        // SYN and FIN).
        let seg_len =
            payload.len() as u32 + if tcph.syn() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

        let nxt_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

        // RFC 793 (3.3)
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
                "[{}] ({:?}) received invalid SEQ number {}: constructing ACK",
                self.sock, self.state, seqn
            );

            let maybe_ack = if !tcph.rst() {
                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                Some(self.create_ack(&[])?)
            } else {
                None
            };

            return Ok(maybe_ack);
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
                "[{}] ({state:?}) received SYN, constructing RST: {state:?} -> CLOSED",
                self.sock,
                state = self.state,
            );

            let rst = if tcph.ack() {
                self.create_rst(ackn, 0)?
            } else {
                self.create_rst(0, seqn.wrapping_add(seg_len))?
            };

            self.state = ConnectionState::CLOSED;

            return Ok(Some(rst));
        }

        if !tcph.ack() {
            debug!(
                "[{}] ({:?}) did not receive ACK: ignoring",
                self.sock, self.state,
            );
            return Ok(None);
        } else {
            if let ConnectionState::SYN_RECEIVED = self.state {
                // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
                if !is_between_wrapped(
                    self.snd.una.wrapping_sub(1),
                    ackn,
                    self.snd.nxt.wrapping_add(1),
                ) {
                    // <SEQ=SEG.ACK><CTL=RST>
                    let rst = self.create_rst(ackn, 0)?;

                    warn!(
                        "[{}] (SYN_RECEIVED) received unacceptable ACK number {}, constructed RST: SYN_RECEIVED -> CLOSED",
                        self.sock, ackn,
                    );

                    self.state = ConnectionState::CLOSED;

                    return Ok(Some(rst));
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
            | ConnectionState::LAST_ACK
            | ConnectionState::TIME_WAIT = self.state
            {
                if ackn < self.snd.una {
                    debug!(
                        "[{}] ({:?}) received duplicate ACK number {}: ignoring",
                        self.sock, self.state, ackn
                    );

                    return Ok(None);
                } else if ackn > self.snd.nxt {
                    let ack = self.create_ack(&[])?;

                    debug!(
                        "[{}] ({:?}) received ACK number {} for untransmitted data: constructed ACK",
                        self.sock, self.state, ackn
                    );

                    return Ok(Some(ack));
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
                    ConnectionState::ESTABLISHED => {}
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

                        // Timer should be set here.
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
                    ConnectionState::TIME_WAIT => {}
                    _ => unreachable!(),
                }
            }

            if let ConnectionState::ESTABLISHED
            | ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2 = self.state
                && seg_len > 0
            {
                // If the RCV.WND is zero, no segments will be acceptable, but
                // special allowance should be made to accept valid ACKs, URGs
                // and RSTs.
                if !payload.is_empty() && self.rcv.wnd > 0 {
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
                            // Don't need `wrapping_sub()` since RCV.NXT is
                            // determined to be greater.
                            let start = (self.rcv.nxt - seqn) as usize;

                            if payload.len() <= start {
                                // Entire payload is old/duplicate data...
                                debug!(
                                    "[{}] ({:?}) received fully old/duplicate payload: ignoring",
                                    self.sock, self.state
                                );
                            } else {
                                // If a segment's contents straddle the boundary
                                // between old and new, only the new parts
                                // should be processed.
                                let payload = &payload[start..];

                                self.usr_buf.extend(payload);

                                self.rcv.nxt = self.rcv.nxt.wrapping_add(payload.len() as u32);
                                self.rcv.wnd = self.rcv.wnd.saturating_sub(payload.len() as u16);

                                debug!(
                                    "[{}] ({:?}) received partially old/duplicate payload: buffering valid portion in-order",
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

                    // Peer is done sending data, merge what we can from the
                    // remaining receive buffer.
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
                if !matches!(self.state, ConnectionState::TIME_WAIT) {
                    // TODO: handle buffered application data in `snd_buf`,
                    // should be piggybacked with ACKs sent to the peer but only
                    // in ESTABLISHED and CLOSE_WAIT states.
                    let ack = self.create_ack(&[])?;

                    debug!(
                        "[{}] ({:?}) received data: constructed ACK",
                        self.sock, self.state,
                    );

                    return Ok(Some(ack));
                }
            }

            if let ConnectionState::TIME_WAIT = self.state {
                // TIME-WAIT STATE
                //
                // The only thing that can arrive in this state is a
                // retransmission of the remote FIN. Acknowledge it, and restart
                // the 2 MSL timeout.
                if tcph.fin() {
                    debug!("[{}] (TIME_WAIT) received FIN: resetting timer", self.sock);

                    self.time_wait = Instant::now();
                    return Ok(Some(self.create_ack(&[])?));
                }
            }
        }

        Ok(None)
    }

    /// Processes an existing connection's retransmission queue for expired
    /// timers or acknowledged segments, returning a `Duration` (when the next
    /// segment will expire) and vector of segments pair.
    ///
    /// The caller can determine if a connection has constructed a `RST` and
    /// is terminating the connection if the connection state is transitioned to
    /// `CLOSED`. A `RST` segment returned should be transmitted to the peer.
    pub fn on_conn_tick(&mut self) -> (Duration, VecDeque<TcpSegment>) {
        if !self.retransmit_buf.is_empty() {
            // Track the segment with the closest time to expire.
            let mut nearest_timer = Duration::MAX;
            // Track all segments (either `RST` or retransmission segments).
            let mut segments: VecDeque<_> = Default::default();

            // Remove segments that have been acknowledged fully or have been
            // retransmitted `MAX_RETRANSMIT_LIMIT` times.
            self.retransmit_buf.retain(|_, seg| {
                let seg_len = seg.segment.payload.len() as u32
                    + if seg.segment.tcp.syn() { 1 } else { 0 }
                    + if seg.segment.tcp.fin() { 1 } else { 0 };

                // Apply exponential backoff to avoid excessive retransmissions.
                let effective_rto = Duration::from_secs(RTO * (1 << seg.transmit_count));

                // A segment on the retransmission queue is fully acknowledged
                // if the sum of its sequence number and length is less or equal
                // than the acknowledgment value in the incoming segment.
                if seg.segment.tcp.seq_number().wrapping_add(seg_len) <= self.snd.una {
                    false
                } else if seg.timer.elapsed() >= effective_rto {
                    if seg.transmit_count >= MAX_RETRANSMIT_LIMIT {
                        // Can't borrow `self` so manually construct RST 
                        // segment.
                        let mut rst =
                            TcpHeader::new(self.sock.src.port, self.sock.dst.port, self.snd.nxt, 0);
                        rst.set_rst();

                        // SAFETY: payload length does not exceed maximum 
                        // allowed.
                        let mut ip = Ipv4Header::new(
                            self.sock.src.addr,
                            self.sock.dst.addr,
                            rst.header_len() as u16,
                            64,
                            Protocol::TCP,
                        ).expect("payload length was exceeded for RST segment");

                        ip.set_header_checksum();
                        rst.set_checksum(&ip, &[]);

                        warn!(
                            "[{}] ({state:?}) max retransmit limit reached, constructing RST: {state:?} -> CLOSED",
                            self.sock,
                            state = self.state,
                        );

                        segments.push_back(TcpSegment::new(ip, rst, &[]));

                        // Used to indicate connection can be removed.
                        self.state = ConnectionState::CLOSED;

                        false
                    } else {
                        // Retransmit segment.
                        seg.timer = Instant::now();
                        seg.transmit_count += 1;

                        segments.push_back(TcpSegment::new(seg.segment.ip, seg.segment.tcp, &seg.segment.payload));

                        debug!(
                            "[{}] ({:?}) segment retransmission constructed, updated transmit count: {}",
                            self.sock, self.state, seg.transmit_count
                        );

                        true
                    }
                } else {
                    // Peer still has time to ACK the segment.
                    //
                    // Track the nearest timer to expire.
                    let remaining = effective_rto - seg.timer.elapsed();

                    if remaining < nearest_timer {
                        nearest_timer = remaining;
                    }

                    true
                }
            });

            return (nearest_timer, segments);
        }

        // No segments on retransmission queue.
        (Duration::MAX, Default::default())
    }

    /// Creates a `SYN` segment to initiate a connection request.
    fn create_syn(&mut self) -> Result<TcpSegment> {
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
        self.retransmit_buf.insert(
            self.snd.una,
            RetransmissionSegment {
                segment: TcpSegment::new(ip, syn, &[]),
                timer: Instant::now(),
                transmit_count: 0,
            },
        );

        Ok(TcpSegment::new(ip, syn, &[]))
    }

    /// Creates a `SYN_ACK` segment in response to a peer's connection
    /// request.
    fn create_syn_ack(&mut self) -> Result<TcpSegment> {
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
        self.retransmit_buf.insert(
            self.snd.una,
            RetransmissionSegment {
                segment: TcpSegment::new(ip, syn_ack, &[]),
                timer: Instant::now(),
                transmit_count: 0,
            },
        );

        Ok(TcpSegment::new(ip, syn_ack, &[]))
    }

    /// Creates an `ACK` segment in response to a peer's segment or when
    /// transmitting data.
    fn create_ack(&mut self, payload: &[u8]) -> Result<TcpSegment> {
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
            self.retransmit_buf.insert(
                self.snd.una,
                RetransmissionSegment {
                    segment: TcpSegment::new(ip, ack, payload),
                    timer: Instant::now(),
                    transmit_count: 0,
                },
            );
        }

        Ok(TcpSegment::new(ip, ack, payload))
    }

    /// Creates a `FIN_ACK` segment for responding to a graceful connection
    /// termination.
    fn create_fin_ack(&mut self, payload: &[u8]) -> Result<TcpSegment> {
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
        self.retransmit_buf.insert(
            self.snd.una,
            RetransmissionSegment {
                segment: TcpSegment::new(ip, fin_ack, payload),
                timer: Instant::now(),
                transmit_count: 0,
            },
        );

        Ok(TcpSegment::new(ip, fin_ack, payload))
    }

    /// Creates an `RST` segment to terminate the current connection.
    fn create_rst(&self, seq: u32, ack: u32) -> Result<TcpSegment> {
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

        Ok(TcpSegment::new(ip, rst, &[]))
    }
}

/// Logs an incoming TCP segment (debug builds only).
#[cfg(debug_assertions)]
fn log_segment(iph: &Ipv4Header, tcph: &TcpHeader, payload: &[u8]) {
    debug!(
        "received ipv4 packet   | version: {}, ihl: {}, tos: {}, total_len: {}, id: {}, DF: {}, MF: {}, frag_offset: {}, ttl: {}, protocol: {:?}, chksum: 0x{:04x} (valid: {}), src: {:?}, dst: {:?} \
         received tcp segment   | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), mss: {:?} \
         received {} bytes of payload: {:x?}",
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
        payload.len(),
        payload
    );
}

#[inline]
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // RFC 1323 (2.3)
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
