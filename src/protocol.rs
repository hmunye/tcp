//! Minimal implementation of the Transmission Control Protocol (TCP).

use std::io::Write;

use crate::parse::{Ipv4Header, Protocol, TcpHeader};
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
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Socket {
    /// Source address and port.
    src: ([u8; 4], u16),
    /// Destination address and port.
    dst: ([u8; 4], u16),
}

impl Socket {
    /// Creates a new socket using the provided (source address, source port)
    /// and (destination address, destination port) pairs.
    pub fn new(src: ([u8; 4], u16), dst: ([u8; 4], u16)) -> Self {
        Self { src, dst }
    }

    /// Returns the (source address, source port) pair of the socket.
    pub fn src(&self) -> ([u8; 4], u16) {
        self.src
    }

    /// Returns the (destination address, destination port) pair of the socket.
    pub fn dst(&self) -> ([u8; 4], u16) {
        self.dst
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
    pub fn on_conn_init(nic: &mut Tun, socket: &Socket) -> Result<Self, String> {
        // Initial Send Sequence Number.
        let iss = 0;

        let conn = TCB {
            state: ConnectionState::SYN_SENT,
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

        let mut syn = TcpHeader::new(socket.dst().1, socket.src().1, conn.snd.iss, conn.rcv.wnd);

        syn.set_syn();
        syn.set_option_mss(1460)?;

        let mut ip = Ipv4Header::new(
            socket.dst().0,
            socket.src().0,
            syn.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        // Checksum must be computed for each header.
        ip.set_header_checksum();
        syn.set_checksum(&ip, &[]);

        conn.write(nic, &ip, &syn, &[])
            .map_err(|err| format!("(ACTIVE_OPEN) failed to write SYN: {err}"))?;

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
    pub fn on_conn_req(nic: &mut Tun, iph: &Ipv4Header, tcph: &TcpHeader) -> Result<Self, String> {
        log_packet(iph, tcph, &[]);

        // An incoming RST should be ignored.
        if tcph.rst() {
            return Err("(LISTEN) received RST".into());
        }

        // Any acknowledgment is bad if it arrives on a connection still in the
        // LISTEN state.
        if tcph.ack() {
            // TODO: Respond with RST
            // ```
            //  <SEQ=SEG.ACK><CTL=RST>
            // ```
            return Err("(LISTEN) received ACK: sending RST".into());
        }

        if !tcph.syn() {
            return Err("(LISTEN) did not receive SYN".into());
        }

        // Initial Send Sequence Number.
        let iss = 0;

        let conn = TCB {
            state: ConnectionState::SYN_RECEIVED,
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

        let mut syn_ack =
            TcpHeader::new(tcph.dst_port(), tcph.src_port(), conn.snd.iss, conn.rcv.wnd);

        // Acknowledge the peer's SYN.
        syn_ack.set_ack_number(conn.rcv.nxt);
        syn_ack.set_syn();
        syn_ack.set_ack();
        syn_ack.set_option_mss(1460)?;

        let mut ip = Ipv4Header::new(
            iph.dst(),
            iph.src(),
            syn_ack.header_len() as u16,
            64,
            Protocol::TCP,
        )?;

        // Checksum must be computed for each header.
        ip.set_header_checksum();
        syn_ack.set_checksum(&ip, &[]);

        conn.write(nic, &ip, &syn_ack, &[])
            .map_err(|err| format!("(LISTEN) failed to write SYN_ACK: {err}"))?;

        Ok(conn)
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
        iph: &Ipv4Header,
        tcph: &TcpHeader,
        payload: &[u8],
    ) -> Result<(), String> {
        log_packet(iph, tcph, payload);

        // TODO: If the RCV.WND is zero, no segments will be acceptable, but
        // special allowance should be made to accept valid ACKs, URGs and RSTs.

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();

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

        // The number of octets occupied by the data in the segment
        // (counting SYN and FIN).
        let seg_len =
            payload.len() as u32 + if tcph.syn() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

        if !(self.state == ConnectionState::SYN_SENT) {
            // Respond with ACK
            // ```
            //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            // ```
            let mut send_ack = || {
                let mut ack =
                    TcpHeader::new(tcph.dst_port(), tcph.src_port(), self.snd.nxt, self.rcv.wnd);

                ack.set_ack_number(self.rcv.nxt);
                ack.set_ack();

                let mut ip = Ipv4Header::new(
                    iph.dst(),
                    iph.src(),
                    ack.header_len() as u16,
                    64,
                    Protocol::TCP,
                )?;

                ip.set_header_checksum();
                ack.set_checksum(&ip, &[]);

                self.write(nic, &ip, &ack, &[])
                    .map_err(|err| format!("({:?}) failed to write ACK: {err}", self.state))?;

                Ok::<(), String>(())
            };

            let nxt_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

            match seg_len {
                0 => match self.rcv.wnd {
                    0 => {
                        // Case 1: SEG.SEQ = RCV.NXT
                        if seqn != self.rcv.nxt {
                            if !tcph.rst() {
                                send_ack()?;
                            }

                            return Err(format!(
                                "({:?}) invalid SEQ number {}: expected SEQ number {}",
                                self.state, seqn, self.rcv.nxt
                            ));
                        }
                    }
                    _ => {
                        // Case 2: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                        if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd) {
                            if !tcph.rst() {
                                send_ack()?;
                            }

                            return Err(format!(
                                "({:?}) invalid SEQ number {}: expected SEQ number between {} and {} (exclusive of {})",
                                self.state,
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
                        // Case 3: not acceptable (we have received bytes when
                        // we are advertising a window size of 0).
                        if !tcph.rst() {
                            send_ack()?;
                        }

                        return Err(format!(
                            "({:?}) received {len} bytes of data from peer with current receive window size: 0",
                            self.state
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
                            if !tcph.rst() {
                                send_ack()?;
                            }

                            return Err(format!(
                                "({:?}) invalid SEQ number {}: expected first or last SEQ number occupied by the segment between {} and {} (exclusive of {})",
                                self.state,
                                seqn,
                                self.rcv.nxt.wrapping_sub(1),
                                nxt_wnd,
                                nxt_wnd
                            ));
                        }
                    }
                },
            }
        }

        loop {
            match self.state {
                ConnectionState::SYN_SENT => {
                    let mut validate_ack = || {
                        // Peer did not correctly ACK our SYN.
                        if ackn <= self.snd.iss || ackn > self.snd.nxt {
                            if !tcph.rst() {
                                // TODO: Respond with RST
                                // ```
                                //  <SEQ=SEG.ACK><CTL=RST>
                                // ```
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
                            validate_ack()?;

                            // Previously unknown values can now be updated.
                            self.rcv.nxt = seqn + 1;
                            self.rcv.up = tcph.urgent_pointer();
                            self.rcv.irs = seqn;
                            self.snd.wnd = tcph.window();
                            self.peer_mss = tcph.options().mss().unwrap_or(DEFAULT_MSS);

                            self.snd.una = ackn;
                            self.state = ConnectionState::ESTABLISHED;

                            // Send ACK
                            // ```
                            //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                            // ```
                            let mut ack = TcpHeader::new(
                                tcph.dst_port(),
                                tcph.src_port(),
                                self.snd.nxt,
                                self.rcv.wnd,
                            );

                            ack.set_ack_number(self.rcv.nxt);
                            ack.set_ack();

                            let mut ip = Ipv4Header::new(
                                iph.dst(),
                                iph.src(),
                                ack.header_len() as u16,
                                64,
                                Protocol::TCP,
                            )?;

                            ip.set_header_checksum();
                            ack.set_checksum(&ip, &[]);

                            self.write(nic, &ip, &ack, &[]).map_err(|err| {
                                format!("({:?}) failed to write ACK: {err}", self.state)
                            })?;
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

                            self.state = ConnectionState::SYN_RECEIVED;

                            // Since we are sending a SYN.
                            self.snd.nxt += 1;

                            // Send SYN_ACK
                            // ```
                            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                            // ```
                            let mut syn_ack = TcpHeader::new(
                                tcph.dst_port(),
                                tcph.src_port(),
                                self.snd.iss,
                                self.rcv.wnd,
                            );

                            syn_ack.set_ack_number(self.rcv.nxt);
                            syn_ack.set_syn();
                            syn_ack.set_ack();

                            let mut ip = Ipv4Header::new(
                                iph.dst(),
                                iph.src(),
                                syn_ack.header_len() as u16,
                                64,
                                Protocol::TCP,
                            )?;

                            ip.set_header_checksum();
                            syn_ack.set_checksum(&ip, &[]);

                            self.write(nic, &ip, &syn_ack, &[]).map_err(|err| {
                                format!("({:?}) failed to write ACK: {err}", self.state)
                            })?;
                        }
                        (false, true) => {
                            // Case 3: Only ACK received
                            // (send RST or drop segment).
                            validate_ack()?;
                        }
                        (false, false) => {
                            // Case 4: Neither SYN or ACK received
                            // (drop segment).
                            return Err(format!(
                                "({:?}) received neither a SYN or ACK to establish connection",
                                self.state
                            ));
                        }
                    }

                    break;
                }
                ConnectionState::SYN_RECEIVED => {
                    if tcph.rst() {
                        match self.open_kind {
                            OpenKind::PASSIVE_OPEN => {
                                self.state = ConnectionState::LISTEN;

                                return Err(format!(
                                    "({:?}) received RST starting from {:?} state",
                                    self.state, self.open_kind
                                ));
                            }
                            OpenKind::ACTIVE_OPEN => {
                                // TODO: enter the CLOSED state and delete the
                                // TCB.
                                self.state = ConnectionState::CLOSED;

                                return Err(format!(
                                    "({:?}) received RST starting from {:?} state: connection refused",
                                    self.state, self.open_kind
                                ));
                            }
                        }
                    }

                    if tcph.syn() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // TODO: Respond with RST
                        // ```
                        //  <SEQ=SEG.ACK><CTL=RST>
                        // ```
                        return Err(format!("({:?}) received SYN: connection reset", self.state));
                    }

                    if !tcph.ack() {
                        // TODO: Respond with RST
                        // ```
                        //  <SEQ=SEG.ACK><CTL=RST>
                        // ```
                        return Err(format!("({:?}) did not receive ACK", self.state));
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

                    self.state = ConnectionState::ESTABLISHED;
                }
                ConnectionState::ESTABLISHED => {
                    if tcph.rst() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;
                        return Err(format!("({:?}) received RST: connection reset", self.state));
                    }

                    if tcph.syn() {
                        // TODO: Enter the CLOSED state and delete the TCB
                        self.state = ConnectionState::CLOSED;

                        // TODO: Respond with RST
                        // ```
                        //  <SEQ=SEG.ACK><CTL=RST>
                        // ```
                        return Err(format!("({:?}) received SYN: connection reset", self.state));
                    }

                    if !tcph.ack() {
                        return Err(format!("({:?}) did not receive ACK", self.state));
                    }

                    if ackn < self.snd.una {
                        return Err(format!(
                            "({:?}) received duplicate ACK number: {}",
                            self.state, ackn
                        ));
                    } else if ackn > self.snd.nxt {
                        let mut ack = TcpHeader::new(
                            tcph.dst_port(),
                            tcph.src_port(),
                            self.snd.nxt,
                            self.rcv.wnd,
                        );

                        ack.set_ack_number(self.rcv.nxt);
                        ack.set_ack();

                        let mut ip = Ipv4Header::new(
                            iph.dst(),
                            iph.src(),
                            ack.header_len() as u16,
                            64,
                            Protocol::TCP,
                        )?;

                        ip.set_header_checksum();
                        ack.set_checksum(&ip, &[]);

                        self.write(nic, &ip, &ack, &[]).map_err(|err| {
                            format!("({:?}) failed to write ACK: {err}", self.state)
                        })?;

                        return Err(format!(
                            "({:?}) invalid ACK number: {}, these bytes have not yet been sent",
                            self.state, ackn
                        ));
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

                        // Send ACK
                        // ```
                        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        // ```
                        let mut ack = TcpHeader::new(
                            tcph.dst_port(),
                            tcph.src_port(),
                            self.snd.nxt,
                            self.rcv.wnd,
                        );

                        ack.set_ack_number(self.rcv.nxt);
                        ack.set_ack();

                        let mut ip = Ipv4Header::new(
                            iph.dst(),
                            iph.src(),
                            ack.header_len() as u16,
                            64,
                            Protocol::TCP,
                        )?;

                        ip.set_header_checksum();
                        ack.set_checksum(&ip, &[]);

                        self.write(nic, &ip, &ack, &[]).map_err(|err| {
                            format!("({:?}) failed to write ACK: {err}", self.state)
                        })?;
                    }
                }
                _ => {
                    warn!(
                        "connection state {:?} is not currently being handled",
                        self.state
                    );

                    break;
                }
            }
        }

        Ok(())
    }

    fn write(
        &self,
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
fn log_packet(iph: &Ipv4Header, tcph: &TcpHeader, payload: &[u8]) {
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
        "tcp segment   | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), mss: {:?}",
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
