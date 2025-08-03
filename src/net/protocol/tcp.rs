use std::io::Write;

use crate::net::headers::{Ipv4Header, Protocol, TcpHeader};
use crate::tun_tap::{MTU_SIZE, Tun};
use crate::{info, warn};

/// RFC 1122 (4.2.2.6):
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40).
const DEFAULT_MSS: u16 = 536;

/// The window size advertised to the peer.
const RECV_WND_SIZE: usize = 4096;

/// Representation of a unique TCP connection.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Socket {
    /// Source address and port.
    pub src: ([u8; 4], u16),
    /// Destination address and port.
    pub dst: ([u8; 4], u16),
}

/// Transmission Control Block (TCB) which stores information about the state
/// and control data for managing a TCP connection.
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
    /// Maximum Segment Size (MSS) of peer.
    #[allow(dead_code)]
    peer_mss: u16,
    /// State the current TCP connection was opened in.
    open_kind: OpenKind,
}

/// Representation of a TCP connection state.
#[derive(Debug, Eq, PartialEq)]
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

#[allow(dead_code)]
impl ConnectionState {
    /// Returns `true` if the current state is "synchronized".
    pub fn is_synchronized(&self) -> bool {
        !matches!(
            self,
            Self::CLOSED | Self::LISTEN | Self::SYN_SENT | Self::SYN_RECEIVED
        )
    }
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

/// Representation of the state a TCP connection was opened in.
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
    /// writing to the TUN device fails.
    pub fn on_conn_init(nic: &mut Tun, socket: Socket) -> Result<Self, String> {
        // Initial Send Sequence Number.
        let iss = 0;

        let conn = TCB {
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
                wnd: RECV_WND_SIZE as u16,
                // Will be updated when peer responds.
                up: 0,
                // What sequence number the peer chooses to start from. Will be
                // updated when peer responds.
                irs: 0,
            },
            // Peer's MSS value that may have been received. Will be updated
            // when peer responds.
            peer_mss: 0,
            open_kind: OpenKind::ACTIVE_OPEN,
        };

        conn.send_syn(nic)?;

        info!("(ACTIVE_OPEN) transitioning to SYN_SENT");

        Ok(conn)
    }

    /// Processes an incoming TCP connection request for which no connection
    /// state exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the incoming segment is invalid for connection
    /// requests, if the TCP segment could not be constructed, or if writing to
    /// the TUN device fails.
    pub fn on_conn_req(
        nic: &mut Tun,
        iph: &Ipv4Header,
        tcph: &TcpHeader,
    ) -> Result<Option<Self>, String> {
        log_packet(iph, tcph, &[]);

        // An incoming RST should be ignored.
        if tcph.rst() {
            warn!("(LISTEN) received RST: ignoring");
            return Ok(None);
        }

        // Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
        // since the SEG.SEQ cannot be validated; drop the segment and return.
        if tcph.fin() {
            warn!("(LISTEN) received FIN: ignoring");
            return Ok(None);
        }

        // Initial Send Sequence Number.
        let iss = 0;

        let conn = TCB {
            state: ConnectionState::SYN_RECEIVED,
            // Stored in the reverse order of the peer's perspective.
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
                nxt: tcph.seq_number() + 1,
                // The window size we advertise to the peer.
                wnd: RECV_WND_SIZE as u16,
                up: tcph.urgent_pointer(),
                // What sequence number the peer chooses to start from.
                irs: tcph.seq_number(),
            },
            // Peer's MSS value that may have been received.
            peer_mss: tcph.options().mss().unwrap_or(DEFAULT_MSS),
            open_kind: OpenKind::PASSIVE_OPEN,
        };

        // Any acknowledgment is bad if it arrives on a connection still in the
        // LISTEN state.
        if tcph.ack() {
            warn!("(LISTEN) received ACK: sending RST");
            conn.send_rst(nic, tcph.ack_number(), 0)?;
            return Ok(None);
        }

        if !tcph.syn() {
            warn!("(LISTEN) did not receive SYN: ignoring");
            return Ok(None);
        }

        conn.send_syn_ack(nic)?;

        info!("(LISTEN) transitioning to SYN_RECEIVED");

        Ok(Some(conn))
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
    pub fn on_packet(
        &mut self,
        nic: &mut Tun,
        _iph: &Ipv4Header,
        tcph: &TcpHeader,
        payload: &[u8],
    ) -> Result<(), String> {
        // log_packet(iph, tcph, payload);

        // TODO: If the RCV.WND is zero, no segments will be acceptable, but
        // special allowance should be made to accept valid ACKs, URGs and RSTs.

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();
        // The number of octets occupied by the data in the segment
        // (counting SYN and FIN).
        let seg_len =
            payload.len() as u32 + if tcph.syn() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

        // RFC 793 (3.3):
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
        if !matches!(
            self.state,
            ConnectionState::CLOSED | ConnectionState::LISTEN | ConnectionState::SYN_SENT
        ) {
            let nxt_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

            match seg_len {
                0 => match self.rcv.wnd {
                    0 => {
                        // Case 1: SEG.SEQ = RCV.NXT
                        if seqn != self.rcv.nxt {
                            warn!(
                                "({:?}) invalid SEQ number {}: expected SEQ number: {}",
                                self.state, seqn, self.rcv.nxt
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
                                "({:?}) invalid SEQ number {}: expected SEQ number between {} and {} (exclusive of {})",
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
                        // Case 3: not acceptable (we have received bytes when
                        // we are advertising a window size of 0).
                        warn!(
                            "({:?}) received {len} bytes of data from peer with current receive window size: 0",
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
                                seqn + len - 1,
                                nxt_wnd,
                            )
                        {
                            warn!(
                                "({:?}) invalid SEQ number {}: expected first or last SEQ number occupied by the segment between {} and {} (exclusive of {})",
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
            }
        }

        loop {
            match self.state {
                ConnectionState::SYN_SENT => {
                    // Do not process the FIN if the state is CLOSED, LISTEN or
                    // SYN-SENT since the SEG.SEQ cannot be validated; drop the
                    // segment and return.
                    if tcph.fin() {
                        warn!("({:?}) received FIN: ignoring", self.state);
                        break;
                    }

                    let mut validate_ack = || {
                        // Peer did not correctly ACK our SYN.
                        if ackn <= self.snd.iss || ackn > self.snd.nxt {
                            if !tcph.rst() {
                                self.send_rst(nic, ackn, 0)?;

                                // TODO: Probably should delete TCB and inform
                                // user the connection was reset.
                            }

                            return Err(format!(
                                "({:?}) received invalid ACK number: {}",
                                self.state, ackn,
                            ));
                        }

                        // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is
                        // acceptable.
                        if !is_between_wrapped(
                            self.snd.una.wrapping_sub(1),
                            ackn,
                            self.snd.nxt.wrapping_add(1),
                        ) {
                            return Err(format!(
                                "({:?}) unacceptable ACK number {}: expected ACK number between {} and {} (inclusive of both)",
                                self.state,
                                ackn,
                                self.snd.una.wrapping_sub(1),
                                self.snd.nxt.wrapping_add(1),
                            ));
                        }

                        if tcph.rst() {
                            info!("({:?}) transitioning to CLOSED", self.state);

                            // TODO: drop the segment, enter CLOSED state, and
                            // delete TCB.
                            self.state = ConnectionState::CLOSED;

                            return Err(format!(
                                "({:?}) received RST with acceptable ACK: connection reset",
                                self.state
                            ));
                        }

                        Ok(())
                    };

                    match (tcph.syn(), tcph.ack()) {
                        (true, true) => {
                            // Case 1: SYN and ACK received
                            // (send ACK -> ESTABLISHED).
                            if let Err(err) = validate_ack() {
                                warn!("{err}");
                                break;
                            }

                            // Previously unknown values can now be updated.
                            self.rcv.nxt = seqn + 1;
                            self.rcv.up = tcph.urgent_pointer();
                            self.rcv.irs = seqn;
                            self.snd.wnd = tcph.window();
                            self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_MSS);

                            self.snd.una = ackn;

                            info!("({:?}) transitioning to ESTABLISHED", self.state);
                            self.state = ConnectionState::ESTABLISHED;

                            // Send piggybacked payload with ACK.
                            let payload = b"hello, world";

                            // Send ACK
                            // ```
                            //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                            // ```
                            self.send_ack(nic, payload)?;

                            // Accounts for the bytes just sent.
                            self.snd.nxt += payload.len() as u32;
                        }
                        (true, false) => {
                            // Case 2: Only SYN received
                            // (send SYN_ACK -> SYN_RECEIVED).

                            // Previously unknown values can now be updated.
                            self.rcv.nxt = seqn + 1;
                            self.rcv.up = tcph.urgent_pointer();
                            self.rcv.irs = seqn;
                            self.snd.wnd = tcph.window();
                            self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_MSS);

                            info!("({:?}) transitioning to SYN_RECEIVED", self.state);
                            self.state = ConnectionState::SYN_RECEIVED;

                            // Since we are sending a SYN.
                            self.snd.nxt += 1;

                            // Send SYN_ACK
                            // ```
                            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                            // ```
                            self.send_syn_ack(nic)?;
                        }
                        (false, true) => {
                            // Case 3: Only ACK received
                            // (send RST or drop segment).

                            // If the ACK number received is valid, we continue
                            // to wait in the SYN_SENT state for a valid SYN or
                            // SYN_ACK segment.
                            if let Err(err) = validate_ack() {
                                warn!("{err}");
                            }
                        }
                        (false, false) => {
                            // Case 4: Neither SYN or ACK received
                            // (drop segment).
                            warn!(
                                "({:?}) received neither a SYN or ACK to establish connection: ignoring",
                                self.state
                            );
                        }
                    }

                    break;
                }
                ConnectionState::SYN_RECEIVED => {
                    if tcph.rst() {
                        // TODO: delete the TCB in either case.
                        match self.open_kind {
                            OpenKind::PASSIVE_OPEN => {
                                warn!(
                                    "({:?}) received RST starting from {:?} state: connection reset",
                                    self.state, self.open_kind
                                );

                                info!("({:?}) transitioning to LISTEN", self.state);
                                self.state = ConnectionState::LISTEN;
                                break;
                            }
                            OpenKind::ACTIVE_OPEN => {
                                warn!(
                                    "({:?}) received RST starting from {:?} state: connection refused",
                                    self.state, self.open_kind
                                );

                                info!("({:?}) transitioning to CLOSED", self.state);
                                self.state = ConnectionState::CLOSED;
                                break;
                            }
                        }
                    }

                    if !tcph.ack() {
                        warn!("({:?}) did not receive ACK", self.state);
                        break;
                    }

                    // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is
                    // acceptable.
                    if !is_between_wrapped(
                        self.snd.una.wrapping_sub(1),
                        ackn,
                        self.snd.nxt.wrapping_add(1),
                    ) {
                        warn!(
                            "({:?}) unacceptable ACK number {}: expected ACK number between {} and {} (inclusive of both)",
                            self.state,
                            ackn,
                            self.snd.una.wrapping_sub(1),
                            self.snd.nxt.wrapping_add(1),
                        );

                        self.send_rst(nic, ackn, 0)?;
                        break;
                    }

                    info!("({:?}) transitioning to ESTABLISHED", self.state);
                    self.state = ConnectionState::ESTABLISHED;
                }
                ConnectionState::ESTABLISHED => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;
                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    if !tcph.ack() {
                        warn!("({:?}) did not receive ACK: ignoring", self.state);
                        break;
                    }

                    if ackn < self.snd.una {
                        warn!("({:?}) received duplicate ACK number: {}", self.state, ackn);
                        break;
                    } else if ackn > self.snd.nxt {
                        warn!(
                            "({:?}) invalid ACK number: {}, these sequence number have not yet been transmitted",
                            self.state, ackn
                        );

                        self.send_ack(nic, &[])?;

                        break;
                    } else {
                        // If SND.UNA < SEG.ACK =< SND.NXT then, set
                        // SND.UNA <- SEG.ACK
                        //
                        // If SND.UNA < SEG.ACK =< SND.NXT, the send window
                        // should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
                        // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
                        // SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set
                        // SND.WL2 <- SEG.ACK.
                        if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                            self.snd.una = ackn;

                            if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn)
                            {
                                self.snd.wnd = tcph.window();
                                self.snd.wl1 = seqn;
                                self.snd.wl2 = ackn;
                            }
                        }
                    }

                    if seg_len > 0 {
                        if let Ok(str) = std::str::from_utf8(payload) {
                            info!("({:?}) payload received from peer: {}", self.state, str)
                        }

                        self.rcv.nxt += seg_len;
                        // TODO: RCV.WND should be updated with payload.len()
                        // when buffering data received.

                        // Send ACK
                        // ```
                        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        // ```
                        self.send_ack(nic, &[])?;

                        if tcph.fin() {
                            warn!("({:?}) received FIN: connection closing", self.state);

                            info!("({:?}) transitioning to CLOSE_WAIT", self.state);
                            self.state = ConnectionState::CLOSE_WAIT;

                            continue;
                        }
                    }

                    break;
                }
                ConnectionState::FIN_WAIT_1 => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;

                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    if !tcph.ack() {
                        // Simultaneous graceful terminations.
                        if tcph.fin() {
                            warn!("({:?}) received FIN", self.state);

                            info!("({:?}) transitioning to CLOSING", self.state);
                            self.state = ConnectionState::CLOSING;
                            // FIN takes up a byte in the sequence space.
                            self.rcv.nxt += 1;

                            self.send_ack(nic, &[])?;
                        } else {
                            warn!("({:?}) did not receive ACK: ignoring", self.state);
                        }

                        break;
                    }

                    if ackn < self.snd.una {
                        warn!("({:?}) received duplicate ACK number: {}", self.state, ackn);
                        break;
                    } else if ackn > self.snd.nxt {
                        warn!(
                            "({:?}) invalid ACK number: {}, these sequence number have not yet been transmitted",
                            self.state, ackn
                        );

                        self.send_ack(nic, &[])?;

                        break;
                    } else {
                        // If SND.UNA < SEG.ACK =< SND.NXT then, set
                        // SND.UNA <- SEG.ACK
                        //
                        // If SND.UNA < SEG.ACK =< SND.NXT, the send window
                        // should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
                        // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
                        // SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set
                        // SND.WL2 <- SEG.ACK.
                        if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                            self.snd.una = ackn;

                            if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn)
                            {
                                self.snd.wnd = tcph.window();
                                self.snd.wl1 = seqn;
                                self.snd.wl2 = ackn;
                            }
                        }
                    }

                    if tcph.fin() {
                        // Our FIN was ACKed and we received a FIN.
                        info!("({:?}) transitioning to TIME_WAIT", self.state);
                        self.state = ConnectionState::TIME_WAIT;
                    } else {
                        // Our FIN was ACKed.
                        info!("({:?}) transitioning to FIN_WAIT_2", self.state);
                        self.state = ConnectionState::FIN_WAIT_2;
                    }

                    if seg_len > 0 {
                        if let Ok(str) = std::str::from_utf8(payload) {
                            info!("({:?}) payload received from peer: {}", self.state, str)
                        }

                        self.rcv.nxt += seg_len;
                        // TODO: RCV.WND should be updated with payload.len()
                        // when buffering data received.

                        // Send ACK
                        // ```
                        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        // ```
                        self.send_ack(nic, &[])?;
                    }

                    break;
                }
                ConnectionState::FIN_WAIT_2 => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;

                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    if !tcph.ack() {
                        warn!("({:?}) did not receive ACK: ignoring", self.state);
                        break;
                    }

                    if ackn < self.snd.una {
                        warn!("({:?}) received duplicate ACK number: {}", self.state, ackn);
                        break;
                    } else if ackn > self.snd.nxt {
                        warn!(
                            "({:?}) invalid ACK number: {}, these sequence number have not yet been transmitted",
                            self.state, ackn
                        );

                        self.send_ack(nic, &[])?;

                        break;
                    } else {
                        // If SND.UNA < SEG.ACK =< SND.NXT then, set
                        // SND.UNA <- SEG.ACK
                        //
                        // If SND.UNA < SEG.ACK =< SND.NXT, the send window
                        // should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
                        // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
                        // SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set
                        // SND.WL2 <- SEG.ACK.
                        if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                            self.snd.una = ackn;

                            if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn)
                            {
                                self.snd.wnd = tcph.window();
                                self.snd.wl1 = seqn;
                                self.snd.wl2 = ackn;
                            }
                        }
                    }

                    if tcph.fin() {
                        // We received a FIN.
                        info!("({:?}) transitioning to TIME_WAIT", self.state);
                        self.state = ConnectionState::TIME_WAIT;
                    }

                    if seg_len > 0 {
                        if let Ok(str) = std::str::from_utf8(payload) {
                            info!("({:?}) payload received from peer: {}", self.state, str)
                        }

                        self.rcv.nxt += seg_len;
                        // TODO: RCV.WND should be updated with payload.len()
                        // when buffering data received.

                        // Send ACK
                        // ```
                        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        // ```
                        self.send_ack(nic, &[])?;
                    }

                    break;
                }
                ConnectionState::CLOSE_WAIT => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;

                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    if !tcph.ack() {
                        warn!("({:?}) did not receive ACK: ignoring", self.state);
                        break;
                    }

                    if ackn < self.snd.una {
                        warn!("({:?}) received duplicate ACK number: {}", self.state, ackn);
                        break;
                    } else if ackn > self.snd.nxt {
                        warn!(
                            "({:?}) invalid ACK number: {}, these sequence number have not yet been transmitted",
                            self.state, ackn
                        );

                        self.send_ack(nic, &[])?;

                        break;
                    } else {
                        // If SND.UNA < SEG.ACK =< SND.NXT then, set
                        // SND.UNA <- SEG.ACK
                        //
                        // If SND.UNA < SEG.ACK =< SND.NXT, the send window
                        // should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
                        // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
                        // SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set
                        // SND.WL2 <- SEG.ACK.
                        if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                            self.snd.una = ackn;

                            if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn)
                            {
                                self.snd.wnd = tcph.window();
                                self.snd.wl1 = seqn;
                                self.snd.wl2 = ackn;
                            }
                        }
                    }

                    // TODO: For now the FIN is immediately sent in response but
                    // it should instead be triggered by user code. The peer
                    // indicated they are done sending data, but the user can
                    // continue to send data.
                    info!("({:?}) transitioning to LAST_ACK", self.state);
                    self.state = ConnectionState::LAST_ACK;

                    self.send_fin_ack(nic, &[])?;

                    // Since we are sending a FIN.
                    self.snd.nxt += 1;

                    break;
                }
                ConnectionState::CLOSING => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;

                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    if !tcph.ack() {
                        warn!("({:?}) did not receive ACK: ignoring", self.state);
                        break;
                    }

                    if ackn < self.snd.una {
                        warn!("({:?}) received duplicate ACK number: {}", self.state, ackn);
                        break;
                    } else if ackn > self.snd.nxt {
                        warn!(
                            "({:?}) invalid ACK number: {}, these sequence number have not yet been transmitted",
                            self.state, ackn
                        );

                        self.send_ack(nic, &[])?;

                        break;
                    } else {
                        // If SND.UNA < SEG.ACK =< SND.NXT then, set
                        // SND.UNA <- SEG.ACK
                        //
                        // If SND.UNA < SEG.ACK =< SND.NXT, the send window
                        // should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
                        // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
                        // SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set
                        // SND.WL2 <- SEG.ACK.
                        if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                            self.snd.una = ackn;

                            if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn)
                            {
                                self.snd.wnd = tcph.window();
                                self.snd.wl1 = seqn;
                                self.snd.wl2 = ackn;
                            }
                        }
                    }

                    // We have received a FIN at this point, meaning the peer
                    // indicated it is no longer sending data, so immediately
                    // transition states.
                    info!("({:?}) transitioning to TIME_WAIT", self.state);
                    self.state = ConnectionState::TIME_WAIT;

                    break;
                }
                ConnectionState::LAST_ACK => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;

                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    if !tcph.ack() {
                        warn!("({:?}) did not receive ACK: ignoring", self.state);
                        break;
                    }

                    if ackn < self.snd.una {
                        warn!("({:?}) received duplicate ACK number: {}", self.state, ackn);
                        break;
                    } else if ackn > self.snd.nxt {
                        warn!(
                            "({:?}) invalid ACK number: {}, these sequence number have not yet been transmitted",
                            self.state, ackn
                        );

                        self.send_ack(nic, &[])?;

                        break;
                    } else {
                        // If SND.UNA < SEG.ACK =< SND.NXT then, set
                        // SND.UNA <- SEG.ACK
                        //
                        // If SND.UNA < SEG.ACK =< SND.NXT, the send window
                        // should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
                        // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
                        // SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set
                        // SND.WL2 <- SEG.ACK.
                        if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                            self.snd.una = ackn;

                            if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn)
                            {
                                self.snd.wnd = tcph.window();
                                self.snd.wl1 = seqn;
                                self.snd.wl2 = ackn;
                            }
                        }
                    }

                    // TODO: Connection finally closed. Delete TCB.
                    info!("({:?}) transitioning to CLOSED", self.state);
                    self.state = ConnectionState::CLOSED;

                    break;
                }
                ConnectionState::TIME_WAIT => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        warn!("({:?}) received RST: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        self.state = ConnectionState::CLOSED;

                        break;
                    }

                    if tcph.syn() {
                        warn!("({:?}) received SYN: connection reset", self.state);

                        info!("({:?}) transitioning to CLOSED", self.state);
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // Shouldn't receive a SYN_ACK in this state, but still
                        // checking...
                        if tcph.ack() {
                            // Respond with RST
                            // ```
                            //  <SEQ=SEG.ACK><CTL=RST>
                            // ```
                            self.send_rst(nic, ackn, 0)?;
                        } else {
                            // Reset the connection while acknowledging the SYN.
                            self.send_rst(nic, 0, seg_len)?;
                        }

                        break;
                    }

                    // The only thing that can arrive in this state is a
                    // retransmission of the remote FIN.  Acknowledge it, and
                    // restart the 2 MSL timeout.
                    if tcph.fin() {
                        self.send_ack(nic, &[])?;
                    }
                }
                _ => {
                    warn!(
                        "connection state ({:?}) is not currently being handled",
                        self.state
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    /// Transmits a TCP SYN packet to initiate a connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_syn(&self, nic: &mut Tun) -> Result<(), String> {
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

        TCB::write(nic, &ip, &syn, &[])
            .map_err(|err| format!("({:?}) failed to write SYN: {err}", self.state))?;

        Ok(())
    }

    /// Transmits a TCP SYN_ACK packet in response to a connection request.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_syn_ack(&self, nic: &mut Tun) -> Result<(), String> {
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

        TCB::write(nic, &ip, &syn_ack, &[])
            .map_err(|err| format!("({:?}) failed to write SYN_ACK: {err}", self.state))?;

        Ok(())
    }

    /// Transmits a TCP ACK packet in response to a peer's TCP segment.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_ack(&self, nic: &mut Tun, payload: &[u8]) -> Result<(), String> {
        let mut ack = TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.nxt, self.rcv.wnd);

        ack.set_ack_number(self.rcv.nxt);
        ack.set_ack();

        let mut ip = Ipv4Header::new(self.sock.src.0, self.sock.dst.0, 0, 64, Protocol::TCP)?;

        ip.set_payload_len((ack.header_len() + payload.len()) as u16)?;

        ip.set_header_checksum();
        ack.set_checksum(&ip, payload);

        TCB::write(nic, &ip, &ack, payload)
            .map_err(|err| format!("({:?}) failed to write ACK: {err}", self.state))?;

        Ok(())
    }

    /// Transmits a TCP FIN_ACK packet for graceful connection termination.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_fin_ack(&self, nic: &mut Tun, payload: &[u8]) -> Result<(), String> {
        let mut fin_ack =
            TcpHeader::new(self.sock.src.1, self.sock.dst.1, self.snd.nxt, self.rcv.wnd);

        fin_ack.set_ack_number(self.rcv.nxt);
        fin_ack.set_fin();
        fin_ack.set_ack();

        let mut ip = Ipv4Header::new(self.sock.src.0, self.sock.dst.0, 0, 64, Protocol::TCP)?;

        ip.set_payload_len((fin_ack.header_len() + payload.len()) as u16)?;

        ip.set_header_checksum();
        fin_ack.set_checksum(&ip, payload);

        TCB::write(nic, &ip, &fin_ack, payload)
            .map_err(|err| format!("({:?}) failed to write ACK: {err}", self.state))?;

        Ok(())
    }

    /// Transmits a TCP RST packet to terminate the current connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn send_rst(&self, nic: &mut Tun, seq: u32, ack: u32) -> Result<(), String> {
        let mut rst = TcpHeader::new(self.sock.src.1, self.sock.dst.1, seq, self.rcv.wnd);

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

        TCB::write(nic, &ip, &rst, &[])
            .map_err(|err| format!("({:?}) failed to write RST: {err}", self.state))?;

        Ok(())
    }

    /// Writes the IP and TCP headers, along with a payload, to the TUN device.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP segment could not be written to the TUN
    /// device.
    fn write(
        nic: &mut Tun,
        ip: &Ipv4Header,
        tcp: &TcpHeader,
        payload: &[u8],
    ) -> Result<usize, String> {
        let mut buf = [0u8; MTU_SIZE];

        let nbytes = {
            let mut unwritten = &mut buf[..];

            ip.write(&mut unwritten).map_err(|err| err.to_string())?;
            tcp.write(&mut unwritten).map_err(|err| err.to_string())?;

            unwritten.write(payload).map_err(|err| err.to_string())?;

            MTU_SIZE - unwritten.len()
        };

        nic.send(&buf[..nbytes]).map_err(|err| err.to_string())
    }
}

/// Logs the details of an incoming TCP segment.
#[inline]
#[allow(dead_code)]
fn log_packet(iph: &Ipv4Header, tcph: &TcpHeader, payload: &[u8]) {
    info!(
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
        iph.compute_header_checksum() == iph.header_checksum(),
        iph.src(),
        iph.dst(),
    );

    info!(
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
        tcph.compute_checksum(iph, payload) == tcph.checksum(),
        tcph.options().mss(),
    );

    info!(
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
