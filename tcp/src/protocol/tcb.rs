use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};
use std::{fmt, io, mem};

use crate::protocol::{RetransmissionEntry, segment_builders};
use crate::wire::{Ipv4Header, TcpHeader, TcpSegment};
use crate::{Error, Result, SocketAddrV4, SocketV4};

/// [RFC 1122, Section 4.2.2.6]:
///
/// If an MSS option is not received at connection setup, TCP MUST assume a
/// default send MSS of 536 (576-40).
///
/// [RFC 1122, Section 4.2.2.6]: https://www.rfc-editor.org/rfc/rfc1122#section-4.2.2.6
const DEFAULT_PEER_TCP_MSS: u16 = 536;

/// Default receive window size (`RCV.WND`) advertised to the peer.
const DEFAULT_RCV_WND: u16 = u16::MAX; // 64 KB

/// Transmission Control Block [(RFC 793, Section 3.2)].
///
/// [(RFC 793, Section 3.2)]: https://www.rfc-editor.org/rfc/rfc793#section-3.2
#[derive(Debug)]
pub struct TCB {
    /// TCP connection state.
    pub(crate) state: ConnectionState,
    /// Local and peer socket addresses.
    pub(crate) sock: SocketV4,
    /// Receive sequence space tracking.
    pub(crate) rcv: RcvSeqSpace,
    /// Send sequence space tracking.
    pub(crate) snd: SndSeqSpace,
    /// In-order bytes received from the peer, ready for application delivery.
    pub(crate) rcv_buf: Vec<u8>,
    /// Application data not yet transmitted (e.g., peer window closing).
    ///
    /// TODO: Any data that could not be sent due to the peer window closing
    /// should be buffered and attempted to be piggybacked on future ACKs.
    pub(crate) snd_queue: VecDeque<Vec<u8>>,
    /// Out-of-order segments buffered by sequence number for in-order
    /// reassembly.
    pub(crate) reassembly_map: BTreeMap<u32, Vec<u8>>,
    /// Sent TCP segments awaiting acknowledgment, tracked for retransmission.
    pub(crate) retransmit_queue: VecDeque<RetransmissionEntry>,
    /// Expiration time for the `TIME_WAIT` state.
    pub(crate) time_wait: Instant,
    /// Peer-advertised maximum segment size (MSS).
    pub(crate) peer_mss: u16,
}

/// States in the TCP connection lifecycle [(RFC 793, Section 3.2)].
///
/// [(RFC 793, Section 3.2)]: https://www.rfc-editor.org/rfc/rfc793#section-3.2
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ConnectionState {
    /// Waiting for a connection request from any remote TCP and port.
    LISTEN,
    /// Waiting for a matching connection request after having sent a connection
    /// request.
    SYN_SENT,
    /// Waiting for a confirming connection request acknowledgment after having
    /// both received and sent a connection request.
    SYN_RECEIVED,
    /// An open connection, data received can be delivered to the user. The
    /// normal state for the data transfer phase of the connection.
    ESTABLISHED,
    /// Waiting for a connection termination request from the remote TCP, or an
    /// acknowledgment of the connection termination request previously sent.
    FIN_WAIT_1,
    /// Waiting for a connection termination request from the remote TCP.
    FIN_WAIT_2,
    /// Waiting for a connection termination request from the local user.
    CLOSE_WAIT,
    /// Waiting for a connection termination request acknowledgment from the
    /// remote TCP.
    CLOSING,
    /// Waiting for an acknowledgment of the connection termination request
    /// previously sent to the remote TCP (which includes an acknowledgment of
    /// its connection termination request).
    LAST_ACK,
    /// Waiting for enough time to pass to be sure the remote TCP received the
    /// acknowledgment of its connection termination request.
    TIME_WAIT,
    /// No connection state at all.
    CLOSED,
}

impl fmt::Debug for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LISTEN => write!(f, "LISTEN"),
            Self::SYN_SENT => write!(f, "SYN_SENT"),
            Self::SYN_RECEIVED => write!(f, "SYN_RECEIVED"),
            Self::ESTABLISHED => write!(f, "ESTABLISHED"),
            Self::FIN_WAIT_1 => write!(f, "FIN_WAIT_1"),
            Self::FIN_WAIT_2 => write!(f, "FIN_WAIT_2"),
            Self::CLOSE_WAIT => write!(f, "CLOSE_WAIT"),
            Self::CLOSING => write!(f, "CLOSING"),
            Self::LAST_ACK => write!(f, "LAST_ACK"),
            Self::TIME_WAIT => write!(f, "TIME_WAIT"),
            Self::CLOSED => write!(f, "CLOSED"),
        }
    }
}

/// Send Sequence Space [(RFC 793, Section 3.2)].
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
///
/// [(RFC 793, Section 3.2)]: https://www.rfc-editor.org/rfc/rfc793#section-3.2
#[derive(Debug)]
pub struct SndSeqSpace {
    /// SND.UNA - send unacknowledged
    pub(crate) una: u32,
    /// SND.NXT - send next
    pub(crate) nxt: u32,
    /// SND.WND - send window
    pub(crate) wnd: u16,
    /// SND.UP - send urgent pointer
    #[allow(unused)]
    pub(crate) up: u16,
    /// SND.WL1 - segment sequence number used for last window update
    pub(crate) wl1: u32,
    /// SND.WL2 - segment acknowledgment number used for last window update
    pub(crate) wl2: u32,
    /// ISS - initial send sequence number
    pub(crate) iss: u32,
}

/// Receive Sequence Space [(RFC 793, Section 3.2)].
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
///
/// [(RFC 793, Section 3.2)]: https://www.rfc-editor.org/rfc/rfc793#section-3.2
#[derive(Debug)]
pub struct RcvSeqSpace {
    /// RCV.NXT - receive next
    pub(crate) nxt: u32,
    /// RCV.WND - receive window
    pub(crate) wnd: u16,
    /// RCV.UP - receive urgent pointer
    pub(crate) up: u16,
    /// IRS - initial receive sequence number
    pub(crate) irs: u32,
}

#[must_use]
enum SeqDisposition {
    /// Segment is invalid; connection state unchanged.
    Invalid(Option<TcpSegment>),
    /// SEQ was valid and acceptable; continue processing.
    Valid,
}

#[must_use]
enum AckDisposition {
    /// Connection terminated (`CLOSED`).
    Closed(Option<TcpSegment>),
    /// Segment can be ignored; connection state unchanged.
    Ignored,
    /// ACK was valid and acceptable; continue processing.
    Valid,
}

impl TCB {
    /// Handles an incoming connection request for which no matching connection
    /// exists, returning a new `TCB` in `SYN-RECEIVED` and a `SYN+ACK` segment
    /// for continuing the handshake.
    ///
    /// Segments containing `RST` or lacking `SYN` are ignored. If an unexpected
    /// `ACK` is received, a `RST` segment is returned instead with no `TCB`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `RST` or `SYN+ACK` segment cannot be created.
    #[inline]
    pub fn passive_open(
        iph: &Ipv4Header,
        tcph: &TcpHeader,
    ) -> Result<(Option<Self>, Option<TcpSegment>)> {
        // RFC 793, Section 3.9:
        //
        // SEGMENT ARRIVES (LISTEN)

        tcp_log_segment!(iph, tcph, &[]);

        // Segment arrives as `peer -> local` (wire-format). Normalize it to the
        // socket representation: `local -> peer`.
        let sock = SocketV4 {
            src: SocketAddrV4 {
                addr: iph.dst_addr(),
                port: tcph.dst_port(),
            },
            dst: SocketAddrV4 {
                addr: iph.src_addr(),
                port: tcph.src_port(),
            },
        };

        if tcph.rst() {
            tcp_warn!("(LISTEN) received RST: ignoring");
            return Ok((None, None));
        }

        if tcph.ack() {
            let rst = segment_builders::rst_bare(sock, tcph.ack_number(), 0)?;

            tcp_warn!("(LISTEN) received ACK: constructed RST");
            return Ok((None, Some(rst)));
        }

        if !tcph.syn() {
            tcp_warn!("(LISTEN) no SYN received: ignoring");
            return Ok((None, None));
        }

        let iss = TCB::generate_iss();

        let mut tcb = TCB::new(
            ConnectionState::SYN_RECEIVED,
            sock,
            RcvSeqSpace {
                // Next sequence number expected from the peer (RCV.NXT).
                nxt: tcph.seq_number().wrapping_add(1),
                // Receive window advertised to the peer.
                wnd: DEFAULT_RCV_WND,
                // Urgent pointer from the incoming segment (if any).
                up: tcph.urgent_pointer(),
                // Initial peer sequence number (RCV.IRS).
                irs: tcph.seq_number(),
            },
            SndSeqSpace {
                // Oldest unacknowledged sequence number (SND.UNA).
                una: iss,
                // Next sequence number to send (SND.NXT). `SYN` consumes one
                // sequence number in the sequence space.
                nxt: iss.wrapping_add(1),
                // Peer’s advertised receive window.
                wnd: tcph.window(),
                // Not yet used for window update tracking.
                up: 0,
                // Last segment sequence number used for window update.
                wl1: 0,
                // Last segment acknowledgment number used for window update.
                wl2: 0,
                // Initial send sequence number (SND.ISS).
                iss,
            },
            tcph.options().mss().unwrap_or(DEFAULT_PEER_TCP_MSS),
        );

        let syn_ack = segment_builders::syn_ack(&tcb)?;

        // Queue `SYN+ACK` for potential retransmission.
        tcb.retransmit_queue
            .push_back(RetransmissionEntry::new(syn_ack.clone()));

        tcp_debug!(
            "[{}] (LISTEN) received SYN, constructed SYN+ACK: LISTEN -> SYN_RECEIVED",
            tcb.sock
        );

        Ok((Some(tcb), Some(syn_ack)))
    }

    /// Initiates a TCP connection for the given socket, returning a new `TCB`
    /// in `SYN-SENT` and a `SYN` segment for beginning the handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SYN` segment cannot be created.
    #[inline]
    pub fn active_open(socket: SocketV4) -> Result<(Self, TcpSegment)> {
        // RFC 793, Section 3.9:
        //
        // OPEN (CLOSED)

        let iss = TCB::generate_iss();

        let mut tcb = TCB::new(
            ConnectionState::SYN_SENT,
            socket,
            RcvSeqSpace {
                // Next sequence number expected from the peer (RCV.NXT). Not
                // yet known until SYN-ACK is received.
                nxt: 0,
                // Receive window advertised to the peer.
                wnd: DEFAULT_RCV_WND,
                // Not yet used until SYN-ACK is received.
                up: 0,
                // Initial peer sequence number (RCV.IRS). Not yet known until
                // SYN-ACK is received.
                irs: 0,
            },
            SndSeqSpace {
                // Oldest unacknowledged sequence number (SND.UNA).
                una: iss,
                // Next sequence number to send (SND.NXT). `SYN` consumes one
                // sequence number in the sequence space.
                nxt: iss.wrapping_add(1),
                // Peer’s advertised receive window (SND.WND). Not yet known
                // until SYN-ACK is received.
                wnd: 0,
                // Not yet used until SYN-ACK is received.
                up: 0,
                // Last segment sequence number used for window update.
                wl1: 0,
                // Last segment acknowledgment number used for window update.
                wl2: 0,
                // Initial send sequence number (SND.ISS).
                iss,
            },
            // MSS assumed until negotiated in SYN-ACK.
            DEFAULT_PEER_TCP_MSS,
        );

        let syn = segment_builders::syn(&tcb)?;

        // Queue `SYN` for potential retransmission.
        tcb.retransmit_queue
            .push_back(RetransmissionEntry::new(syn.clone()));

        tcp_debug!(
            "[{}] (CLOSED) constructed SYN: CLOSED -> SYN_SENT",
            tcb.sock
        );

        Ok((tcb, syn))
    }

    /// Segments application data into `PSH+ACK` segments for transmission, also
    /// returning the number of bytes consumed from `buf`.
    ///
    /// Data is segmented according to the peer's advertised window (`SND.WND`)
    /// and negotiated MSS. If the window is zero or the connection is in
    /// `SYN_SENT`/`SYN_RECEIVED`, `buf` is buffered for later transmission.
    ///
    /// # Errors
    ///
    /// Returns an error if `PSH+ACK` segments cannot be created or the
    /// connection state prohibits sending (e.g., connection is closing).
    #[inline]
    pub fn send(&mut self, buf: &[u8]) -> Result<(Option<VecDeque<TcpSegment>>, usize)> {
        // RFC 793, Section 3.9:
        //
        // SEND Call

        if self.snd.wnd == 0 {
            tcp_debug!(
                "[{}] ({:?}) send: peer send window closed, buffering {} bytes",
                self.sock,
                self.state,
                buf.len()
            );

            self.snd_queue.push_back(buf.to_vec());
            return Ok((None, buf.len()));
        }

        match self.state {
            // Queue the data for transmission after entering ESTABLISHED state.
            ConnectionState::SYN_SENT | ConnectionState::SYN_RECEIVED => {
                tcp_debug!(
                    "[{}] (SYN_SENT) send: connection not established, buffering {} bytes",
                    self.sock,
                    buf.len()
                );

                self.snd_queue.push_back(buf.to_vec());
                Ok((None, buf.len()))
            }
            ConnectionState::ESTABLISHED | ConnectionState::CLOSE_WAIT => {
                // Payload size clamped to remaining window space and negotiated
                // MSS.
                let seg_size = u16::min(self.snd.wnd, self.peer_mss);

                let mut psh_acks = VecDeque::new();
                let mut pos = 0;

                while pos < buf.len() {
                    let chunk_len = usize::min(seg_size as usize, buf.len() - pos);

                    if self.snd.wnd as usize >= chunk_len {
                        let ack = segment_builders::ack(self, &buf[pos..pos + chunk_len])?;

                        // Queue `ACK` for potential retransmission.
                        self.retransmit_queue
                            .push_back(RetransmissionEntry::new(ack.clone()));

                        psh_acks.push_back(ack);

                        pos += chunk_len;
                        self.snd.wnd -= chunk_len as u16;
                        self.snd.nxt = self.snd.nxt.wrapping_add(chunk_len as u32);
                    } else {
                        let ack =
                            segment_builders::ack(self, &buf[pos..pos + self.snd.wnd as usize])?;

                        // Queue `ACK` for potential retransmission.
                        self.retransmit_queue
                            .push_back(RetransmissionEntry::new(ack.clone()));

                        psh_acks.push_back(ack);

                        pos += self.snd.wnd as usize;
                        self.snd.nxt = self.snd.nxt.wrapping_add(u32::from(self.snd.wnd));
                        self.snd.wnd = 0;

                        let slice = &buf[pos..];

                        tcp_debug!(
                            "[{}] ({:?}) send: peer send window exhausted, buffering {} bytes",
                            self.sock,
                            self.state,
                            slice.len()
                        );

                        self.snd_queue.push_back(slice.to_vec());

                        break;
                    }
                }

                Ok((Some(psh_acks), pos))
            }
            ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2
            | ConnectionState::CLOSING
            | ConnectionState::LAST_ACK
            | ConnectionState::TIME_WAIT => {
                tcp_error!(
                    "[{}] ({:?}) send: connection closing",
                    self.sock,
                    self.state
                );

                Err(Error::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "unable to send application data",
                )))
            }
            ConnectionState::LISTEN | ConnectionState::CLOSED => unreachable!(),
        }
    }

    /// Transfers in-order data from the receive buffer into the provided
    /// user buffer, returning the number of bytes written.
    ///
    /// NOTE: `recv` requests are not queued when unable to be serviced. If
    /// available, buffered data is used to satisfy the call.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection state prohibits receiving data or
    /// requires queuing.
    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        // RFC 793, Section 3.9:
        //
        // RECEIVE Call

        if !matches!(
            self.state,
            ConnectionState::ESTABLISHED
                | ConnectionState::FIN_WAIT_1
                | ConnectionState::FIN_WAIT_2
                | ConnectionState::CLOSE_WAIT,
        ) {
            tcp_error!(
                "[{}] ({:?}) recv: unable to receive connection data",
                self.sock,
                self.state
            );

            return Err(Error::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "unable to receive connection data",
            )));
        }

        let min = usize::min(self.rcv_buf.len(), buf.len());

        buf[..min].copy_from_slice(self.rcv_buf.drain(..min).as_slice());

        // NOTE: `DEFAULT_RCV_WND` must be `u16::MAX` for this to work.
        self.rcv.wnd = self.rcv.wnd.saturating_add(min as u16);

        Ok(min)
    }

    /// Initiates a graceful connection termination, returning a `FIN+ACK`
    /// segment for transmission.
    ///
    /// If the connection is in `SYN_SENT` or has already transmitted a `FIN`,
    /// no segment is created.
    ///
    /// If the connection state transitions to `CLOSED`, `self` can be safely
    /// dropped by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the `FIN+ACK` segment cannot be created.
    #[inline]
    pub fn close(&mut self) -> Result<Option<TcpSegment>> {
        // RFC 793, Section 3.9:
        //
        // CLOSE Call

        match self.state {
            ConnectionState::SYN_SENT => {
                tcp_debug!(
                    "[{}] (SYN_SENT) close: closing connection: SYN_SENT -> CLOSED",
                    self.sock,
                );

                self.state = ConnectionState::CLOSED;
                Ok(None)
            }
            // NOTE: `close` request is not queued (until all preceding SENDs
            // have been segmentized) for `ESTABLISHED` and `CLOSE_WAIT`.
            ConnectionState::SYN_RECEIVED
            | ConnectionState::ESTABLISHED
            | ConnectionState::CLOSE_WAIT => {
                let fin_ack = segment_builders::fin_ack(self, &[])?;

                // Queue `FIN+ACK` for potential retransmission.
                self.retransmit_queue
                    .push_back(RetransmissionEntry::new(fin_ack.clone()));

                tcp_debug!(
                    "[{}] ({state:?}) close: constructed FIN+ACK: {state:?} -> FIN_WAIT_1",
                    self.sock,
                    state = self.state
                );

                // `FIN` consumes one sequence number in the sequence space.
                self.snd.nxt = self.snd.nxt.wrapping_add(1);

                if self.state == ConnectionState::CLOSE_WAIT {
                    self.state = ConnectionState::LAST_ACK;
                } else {
                    self.state = ConnectionState::FIN_WAIT_1;
                }

                Ok(Some(fin_ack))
            }
            ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2
            | ConnectionState::CLOSING
            | ConnectionState::LAST_ACK
            | ConnectionState::TIME_WAIT => {
                tcp_warn!(
                    "[{}] ({:?}) close: connection closing",
                    self.sock,
                    self.state
                );

                Ok(None)
            }
            ConnectionState::LISTEN | ConnectionState::CLOSED => unreachable!(),
        }
    }

    /// Initiates an abort of the connection, returning a `RST+ACK` segment for
    /// transmission.
    ///
    /// If the connection is in `SYN_SENT`, `CLOSING`, `LAST_ACK`, or
    /// `TIME_WAIT`, no segment is returned.
    ///
    /// Connection state is transitioned to `CLOSED` and `self` can be safely
    /// dropped by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the `RST+ACK` segment cannot be created.
    #[inline]
    pub fn abort(&mut self) -> Result<Option<TcpSegment>> {
        match self.state {
            ConnectionState::SYN_SENT
            | ConnectionState::CLOSING
            | ConnectionState::LAST_ACK
            | ConnectionState::TIME_WAIT => {
                tcp_debug!(
                    "[{}] ({state:?}) abort: connection reset: {state:?} -> CLOSED",
                    self.sock,
                    state = self.state
                );

                self.state = ConnectionState::CLOSED;
                Ok(None)
            }
            ConnectionState::SYN_RECEIVED
            | ConnectionState::ESTABLISHED
            | ConnectionState::FIN_WAIT_1
            | ConnectionState::FIN_WAIT_2
            | ConnectionState::CLOSE_WAIT => {
                let rst = segment_builders::rst(self, self.snd.nxt, 0)?;

                tcp_debug!(
                    "[{}] ({state:?}) abort: constructed RST+ACK: {state:?} -> CLOSED",
                    self.sock,
                    state = self.state
                );

                self.state = ConnectionState::CLOSED;
                Ok(Some(rst))
            }
            ConnectionState::LISTEN | ConnectionState::CLOSED => unreachable!(),
        }
    }

    /// Processes an incoming TCP segment for an existing connection, returning
    /// a segment for transmission based on current state.
    ///
    /// If the connection state transitions to `CLOSED`, `self` can be safely
    /// dropped by the caller. In that case, if a TCP segment is returned, it
    /// must first be transmitted to the peer.
    ///
    /// TCP State Diagram [(RFC 793, Section 3.2)].
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
    /// Returns an error if the segment for transmission could not created.
    ///
    /// [(RFC 793, Section 3.2)]: https://www.rfc-editor.org/rfc/rfc793#section-3.2
    pub fn process_segment(
        &mut self,
        iph: &Ipv4Header,
        tcph: &TcpHeader,
        payload: &[u8],
    ) -> Result<Option<TcpSegment>> {
        #[allow(unused_variables)]
        let iph_ = iph;

        // if let ConnectionState::CLOSED = self.state {
        //     return Err(Error::Io(io::Error::new(
        //         io::ErrorKind::ConnectionReset,
        //         "connection reset",
        //     )));
        // }

        tcp_log_segment!(iph_, tcph, payload);

        if self.state == ConnectionState::SYN_SENT {
            return self.process_syn_sent(tcph);
        }

        // Sequence space occupied by TCP segment, including `SYN`/`FIN` flags.
        let seg_len = tcp_segment_len(payload, tcph.syn(), tcph.fin());

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();

        if let SeqDisposition::Invalid(seg) = self.validate_seq(seqn, seg_len, tcph.rst())? {
            return Ok(seg);
        }

        if tcph.rst() {
            tcp_warn!(
                "[{}] ({state:?}) received valid RST, connection reset: {state:?} -> CLOSED",
                self.sock,
                state = self.state,
            );

            self.state = ConnectionState::CLOSED;
            return Ok(None);
        }

        if tcph.syn() {
            let rst = segment_builders::rst(self, ackn, 0)?;

            tcp_warn!(
                "[{}] ({state:?}) received SYN, constructed RST: {state:?} -> CLOSED",
                self.sock,
                state = self.state,
            );

            self.state = ConnectionState::CLOSED;
            return Ok(Some(rst));
        }

        if !tcph.ack() {
            tcp_warn!(
                "[{}] ({:?}) did not receive ACK: ignoring",
                self.sock,
                self.state,
            );

            return Ok(None);
        }

        if self.state == ConnectionState::SYN_RECEIVED {
            if let Some(seg) = self.process_syn_recv(ackn)? {
                return Ok(Some(seg));
            }
        }

        if matches!(
            self.state,
            ConnectionState::ESTABLISHED
                | ConnectionState::FIN_WAIT_1
                | ConnectionState::FIN_WAIT_2
                | ConnectionState::CLOSE_WAIT
                | ConnectionState::CLOSING
                | ConnectionState::LAST_ACK
                | ConnectionState::TIME_WAIT
        ) {
            // RFC 793, Section 3.9:
            //
            // SEGMENT ARRIVES
            //
            // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
            // If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be
            // ignored. If the ACK acks something not yet sent
            // (SEG.ACK > SND.NXT) then send an ACK, drop the segment, and
            // return.
            //
            // If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
            // updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
            // SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
            // SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
            if ackn <= self.snd.una {
                tcp_warn!(
                    "[{}] ({:?}) received duplicate ACK `{ackn}`: ignoring",
                    self.sock,
                    self.state
                );

                return Ok(None);
            } else if ackn > self.snd.nxt {
                let ack = segment_builders::ack(self, &[])?;

                tcp_warn!(
                    "[{}] ({:?}) received ACK `{ackn}` for data not transmitted: constructed ACK",
                    self.sock,
                    self.state
                );

                return Ok(Some(ack));
            } else {
                self.snd.una = ackn;

                if self.snd.wl1 < seqn || (self.snd.wl1 == seqn && self.snd.wl2 <= ackn) {
                    self.snd.wnd = tcph.window();
                    self.snd.wl1 = seqn;
                    self.snd.wl2 = ackn;

                    tcp_debug!(
                        "[{}] ({:?}) updated snd window size: {}",
                        self.sock,
                        self.state,
                        self.snd.wnd
                    );
                }
            }

            match self.state {
                ConnectionState::ESTABLISHED
                | ConnectionState::CLOSE_WAIT
                | ConnectionState::TIME_WAIT
                // FIN-WAIT-2 STATE
                //
                // In addition to the processing for the ESTABLISHED state,
                // if the retransmission queue is empty, the user's CLOSE
                // can be acknowledged ("ok") but do not delete the TCB.
                | ConnectionState::FIN_WAIT_2 => {}
                ConnectionState::FIN_WAIT_1 => {
                    tcp_debug!(
                        "[{}] (FIN_WAIT_1) received ACK for FIN: FIN_WAIT_1 -> FIN_WAIT_2",
                        self.sock
                    );

                    self.state = ConnectionState::FIN_WAIT_2;
                }
                ConnectionState::CLOSING => {
                    tcp_debug!(
                        "[{}] (CLOSING) received ACK for FIN: CLOSING -> TIME_WAIT",
                        self.sock
                    );

                    self.time_wait = Instant::now();
                    self.state = ConnectionState::TIME_WAIT;
                }
                ConnectionState::LAST_ACK => {
                    tcp_warn!(
                        "[{}] (LAST_ACK) received ACK for FIN: LAST_ACK -> CLOSED",
                        self.sock
                    );

                    self.state = ConnectionState::CLOSED;
                    return Ok(None);
                }
                _ => unreachable!(),
            }
        }

        if matches!(
            self.state,
            ConnectionState::ESTABLISHED
                | ConnectionState::FIN_WAIT_1
                | ConnectionState::FIN_WAIT_2
        ) && seg_len > 0
        {
            self.process_segment_text(seqn, payload);

            if tcph.fin() {
                // Accounting for the peer's FIN.
                self.rcv.nxt = self.rcv.nxt.wrapping_add(1);

                // Peer signaled end-of-transmission; drain contiguous
                // buffered segments for delivery.
                for (seq, mut data) in mem::take(&mut self.reassembly_map) {
                    if seq == self.rcv.nxt {
                        let len = data.len();

                        self.rcv_buf.append(&mut data);
                        self.rcv.nxt = self.rcv.nxt.wrapping_add(len as u32);
                        self.rcv.wnd = self.rcv.wnd.saturating_sub(len as u16);
                    }
                }

                match self.state {
                    ConnectionState::ESTABLISHED => {
                        tcp_debug!(
                            "[{}] (ESTABLISHED) received FIN with valid ACK: ESTABLISHED -> CLOSE_WAIT",
                            self.sock
                        );

                        self.state = ConnectionState::CLOSE_WAIT;
                    }
                    // Unreachable under normal RFC 793 flow
                    // (FIN_WAIT_1 -> FIN_WAIT_2 on ACK). Kept as a
                    // fallback.
                    ConnectionState::FIN_WAIT_1 => {
                        tcp_debug!(
                            "[{}] (FIN_WAIT_1) received FIN: FIN_WAIT_1 -> CLOSING",
                            self.sock
                        );

                        self.state = ConnectionState::CLOSING;
                    }
                    ConnectionState::FIN_WAIT_2 => {
                        tcp_debug!(
                            "[{}] (FIN_WAIT_2) received FIN: FIN_WAIT_2 -> TIME_WAIT",
                            self.sock
                        );

                        self.time_wait = Instant::now();
                        self.state = ConnectionState::TIME_WAIT;
                    }
                    _ => unreachable!(),
                }
            }

            let ack = segment_builders::ack(self, &[])?;

            tcp_debug!(
                "[{}] ({:?}) received segment data: constructed ACK",
                self.sock,
                self.state,
            );

            return Ok(Some(ack));
        }

        if self.state == ConnectionState::TIME_WAIT {
            if let Some(seg) = self.process_time_wait(tcph.fin())? {
                return Ok(Some(seg));
            }
        }

        Ok(None)
    }

    /// Processes the connection's retransmission queue for acknowledged or
    /// expired segments, returning a `Duration` until the next expiration and
    /// any segments requiring transmission. Returns `None` if the queue is
    /// empty.
    ///
    /// If the connection state transitions to `CLOSED`, `self` can be safely
    /// dropped by the caller. In that case, the returned `RST` segment should
    /// first be transmitted to the peer.
    ///
    /// # Panics
    ///
    /// Panics if the RST segment could not be created.
    #[inline]
    pub fn process_retransmissions(&mut self) -> Option<(Duration, VecDeque<TcpSegment>)> {
        if !self.retransmit_queue.is_empty() {
            let mut segments = VecDeque::new();
            let mut nearest_timer = Duration::MAX;

            self.retransmit_queue.retain_mut(|retransmit| {
                let seg_len = tcp_segment_len(
                    &retransmit.segment.payload,
                    retransmit.segment.tcph.syn(),
                    retransmit.segment.tcph.fin(),
                );
                let effective_rto = retransmit.effective_rto();

                if retransmit.is_acked(seg_len, self.snd.una) {
                    false
                } else if retransmit.is_expired() {
                    if retransmit.at_retry_limit() {
                        let rst = segment_builders::rst_bare(self.sock, self.snd.nxt, 0).expect(
                            "IPv4 header creation should not fail, payload length less than maximum allowed",
                        );

                        tcp_warn!(
                            "[{}] ({state:?}) retransmission limit exceeded, constructed RST: {state:?} -> CLOSED",
                            self.sock,
                            state = self.state,
                        );

                        self.state = ConnectionState::CLOSED;
                        segments.push_back(rst);

                        false
                    } else {
                        retransmit.timer = Instant::now();
                        retransmit.transmit_count += 1;

                        segments.push_back(retransmit.segment.clone());

                        tcp_debug!(
                            "[{}] ({:?}) segment queued for retransmission, current transmit count: {}",
                            self.sock,
                            self.state,
                            retransmit.transmit_count
                        );

                        true
                    }
                } else {
                    // Peer still has time to acknowledge the segment.
                    #[allow(clippy::unchecked_time_subtraction)]
                    let remaining = effective_rto - retransmit.timer.elapsed();

                    if remaining < nearest_timer {
                        nearest_timer = remaining;
                    }

                    true
                }
            });

            return Some((nearest_timer, segments));
        }

        None
    }

    #[inline]
    #[must_use]
    fn new(
        state: ConnectionState,
        sock: SocketV4,
        rcv: RcvSeqSpace,
        snd: SndSeqSpace,
        peer_mss: u16,
    ) -> Self {
        TCB {
            state,
            sock,
            rcv,
            snd,
            rcv_buf: Vec::new(),
            snd_queue: VecDeque::new(),
            reassembly_map: BTreeMap::new(),
            retransmit_queue: VecDeque::new(),
            time_wait: Instant::now(),
            peer_mss,
        }
    }

    #[inline]
    fn process_syn_sent(&mut self, tcph: &TcpHeader) -> Result<Option<TcpSegment>> {
        // RFC 793, Section 3.9:
        //
        // SEGMENT ARRIVES
        //
        // Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
        // since the SEG.SEQ cannot be validated; drop the segment and
        if tcph.fin() {
            tcp_warn!("[{}] (SYN_SENT) received FIN: ignoring", self.sock);
            return Ok(None);
        }

        let seqn = tcph.seq_number();
        let ackn = tcph.ack_number();

        match (tcph.syn(), tcph.ack()) {
            // Case 1: SYN and ACK received (send ACK).
            (true, true) => {
                match self.validate_ack(ackn, tcph.rst())? {
                    AckDisposition::Closed(rst) => return Ok(rst),
                    AckDisposition::Ignored => {}
                    AckDisposition::Valid => {
                        self.rcv.nxt = seqn.wrapping_add(1);
                        self.rcv.up = tcph.urgent_pointer();
                        self.rcv.irs = seqn;
                        self.snd.wnd = tcph.window();
                        self.peer_mss = tcph.options().mss().unwrap_or(self.peer_mss);

                        // Previous SYN was ACKed by the peer.
                        self.snd.una = ackn;

                        let ack = segment_builders::ack(self, &[])?;

                        tcp_debug!(
                            "[{}] (SYN_SENT) received SYN+ACK: constructed ACK: SYN_SENT -> ESTABLISHED",
                            self.sock
                        );

                        self.state = ConnectionState::ESTABLISHED;
                        return Ok(Some(ack));
                    }
                }
            }
            // Case 2: Only SYN received (send SYN+ACK).
            (true, false) => {
                if tcph.rst() {
                    // Ignore RST without ACK.
                    return Ok(None);
                }

                self.rcv.nxt = seqn.wrapping_add(1);
                self.rcv.up = tcph.urgent_pointer();
                self.rcv.irs = seqn;
                self.snd.wnd = tcph.window();
                self.peer_mss = tcph.options().mss().unwrap_or(self.peer_mss);

                let syn_ack = segment_builders::syn_ack(self)?;

                // Queue `SYN+ACK` for potential retransmission.
                self.retransmit_queue
                    .push_back(RetransmissionEntry::new(syn_ack.clone()));

                tcp_debug!(
                    "[{}] (SYN_SENT) received SYN: constructed SYN+ACK: SYN_SENT -> SYN_RECEIVED",
                    self.sock
                );

                // Accounting for the SYN+ACK sent.
                self.snd.nxt = self.snd.nxt.wrapping_add(1);

                self.state = ConnectionState::SYN_RECEIVED;
                return Ok(Some(syn_ack));
            }
            // Case 3: Only ACK received (validate ACK).
            (false, true) => {
                match self.validate_ack(ackn, tcph.rst())? {
                    AckDisposition::Closed(rst) => return Ok(rst),
                    AckDisposition::Ignored => {}
                    AckDisposition::Valid => {
                        // Previous SYN was ACKed by the peer.
                        self.snd.una = ackn;

                        tcp_debug!(
                            "[{}] (SYN_SENT) received valid ACK: waiting for SYN",
                            self.sock
                        );
                    }
                }
            }
            // Case 4: Neither SYN or ACK received (return).
            (false, false) => {
                tcp_warn!(
                    "[{}] (SYN_SENT) received neither SYN or ACK: ignoring",
                    self.sock
                );
            }
        }

        Ok(None)
    }

    #[inline]
    fn process_syn_recv(&mut self, ackn: u32) -> Result<Option<TcpSegment>> {
        // RFC 793, Section 3.9:
        //
        // SEGMENT ARRIVES
        //
        // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state and
        // continue processing.
        if !is_between_wrapped(
            self.snd.una.wrapping_sub(1),
            ackn,
            self.snd.nxt.wrapping_add(1),
        ) {
            let rst = segment_builders::rst(self, ackn, 0)?;

            tcp_warn!(
                "[{}] (SYN_RECEIVED) received unacceptable ACK `{}`, constructed RST: SYN_RECEIVED -> CLOSED",
                self.sock,
                ackn,
            );

            self.state = ConnectionState::CLOSED;
            return Ok(Some(rst));
        }

        tcp_debug!(
            "[{}] (SYN_RECEIVED) received valid ACK: SYN_RECEIVED -> ESTABLISHED",
            self.sock
        );

        self.state = ConnectionState::ESTABLISHED;

        Ok(None)
    }

    #[inline]
    fn process_time_wait(&mut self, fin: bool) -> Result<Option<TcpSegment>> {
        // TIME-WAIT STATE
        //
        // The only thing that can arrive in this state is a retransmission of
        // the remote FIN. Acknowledge it, and restart the 2 `MSL` timeout.
        if fin {
            let ack = segment_builders::ack(self, &[])?;
            self.time_wait = Instant::now();

            tcp_debug!(
                "[{}] (TIME_WAIT) received FIN: reset TIME_WAIT timer and constructed ACK",
                self.sock
            );

            return Ok(Some(ack));
        }

        Ok(None)
    }

    /// Validates an incoming ACK number.
    ///
    /// If the ACK is invalid and lacks a RST bit, a RST segment is returned and
    /// connection transitions to CLOSED. If the ACK is valid with a set RST,
    /// connection transitions to CLOSED. For any received RST (valid or
    /// invalid), `None` is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the `RST` segment cannot be created.
    #[inline]
    fn validate_ack(&mut self, ackn: u32, rst: bool) -> Result<AckDisposition> {
        // If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless the RST
        // bit is set, if so drop the segment and return)
        //
        // If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
        if !is_between_wrapped(
            self.snd.una.wrapping_sub(1),
            ackn,
            self.snd.nxt.wrapping_add(1),
        ) {
            if rst {
                tcp_warn!(
                    "[{}] (SYN_SENT) invalid ACK `{ackn}` with RST: ignoring",
                    self.sock,
                );

                return Ok(AckDisposition::Ignored);
            }

            let rst = segment_builders::rst(self, ackn, 0)?;

            tcp_warn!(
                "[{}] (SYN_SENT) received invalid ACK `{ackn}`, constructed RST: SYN_SENT -> CLOSED",
                self.sock
            );

            self.state = ConnectionState::CLOSED;
            return Ok(AckDisposition::Closed(Some(rst)));
        }

        if rst {
            tcp_warn!(
                "[{}] (SYN_SENT) received valid RST: connection reset: SYN_SENT -> CLOSED",
                self.sock
            );

            self.state = ConnectionState::CLOSED;
            return Ok(AckDisposition::Closed(None));
        }

        Ok(AckDisposition::Valid)
    }

    #[inline]
    fn validate_seq(&self, seqn: u32, seg_len: u32, rst: bool) -> Result<SeqDisposition> {
        // RFC 793, Section 3.9:
        //
        // SEGMENT ARRIVES
        //
        // There are four cases for the acceptability test for an incoming
        // segment:
        //
        // ```
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

        let nxt_wnd = self.rcv.nxt.wrapping_add(u32::from(self.rcv.wnd));

        let is_invalid = match (seg_len, self.rcv.wnd) {
            // Case 1: SEG.SEQ = RCV.NXT
            (0, 0) => seqn != self.rcv.nxt,
            // Case 2: RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            (0, _wnd) => !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd),
            // Case 3: not acceptable
            //
            // If the RCV.WND is zero, no segments will be acceptable, but
            // special allowance should be made to accept valid ACKs, URGs and
            // RSTs.
            (_len, 0) => true,
            // Case 4:    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            //         or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
            (len, _wnd) => {
                !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seqn, nxt_wnd)
                    && !is_between_wrapped(
                        self.rcv.nxt.wrapping_sub(1),
                        seqn.wrapping_add(len - 1),
                        nxt_wnd,
                    )
            }
        };

        if is_invalid {
            let ack = if rst {
                None
            } else {
                Some(segment_builders::ack(self, &[])?)
            };

            tcp_warn!(
                "[{}] ({:?}) received invalid SEQ `{seqn}`: constructed ACK",
                self.sock,
                self.state
            );

            return Ok(SeqDisposition::Invalid(ack));
        }

        Ok(SeqDisposition::Valid)
    }

    #[inline]
    fn process_segment_text(&mut self, seqn: u32, payload: &[u8]) {
        // RFC 793, Section 3.9:
        //
        // SEGMENT ARRIVES
        //
        // If the RCV.WND is zero, no segments will be acceptable, but special
        // allowance should be made to accept valid ACKs, URGs and RSTs.
        if !payload.is_empty() && self.rcv.wnd > 0 {
            match seqn.cmp(&self.rcv.nxt) {
                // Matches RCV.NXT exactly; accept immediately in-order.
                Ordering::Equal => {
                    tcp_debug!(
                        "[{}] ({:?}) received expected payload: buffering in-order",
                        self.sock,
                        self.state
                    );

                    self.rcv_buf.extend(payload);
                    self.rcv.nxt = self.rcv.nxt.wrapping_add(payload.len() as u32);
                    self.rcv.wnd = self.rcv.wnd.saturating_sub(payload.len() as u16);

                    // Try to merge out-of-order buffered segments.
                    self.drain_reassembly_map();
                }
                // Out-of-order segment; buffer for in-order delivery, keeping
                // RCV.NXT unchanged.
                Ordering::Greater => {
                    tcp_warn!(
                        "[{}] ({:?}) received out-of-order payload: buffering out-of-order",
                        self.sock,
                        self.state
                    );

                    self.reassembly_map.insert(seqn, payload.into());
                }
                // Overlap with already received data; accept only the new
                // portion beyond RCV.NXT.
                Ordering::Less => {
                    let start = (self.rcv.nxt - seqn) as usize;

                    if payload.len() <= start {
                        tcp_warn!(
                            "[{}] ({:?}) received fully old/duplicate payload: ignoring",
                            self.sock,
                            self.state
                        );
                    } else {
                        tcp_debug!(
                            "[{}] ({:?}) received partially old/duplicate payload: buffering new portion in-order",
                            self.sock,
                            self.state
                        );

                        let payload = &payload[start..];

                        self.rcv_buf.extend(payload);
                        self.rcv.nxt = self.rcv.nxt.wrapping_add(payload.len() as u32);
                        self.rcv.wnd = self.rcv.wnd.saturating_sub(payload.len() as u16);

                        // Try to merge out-of-order buffered segments.
                        self.drain_reassembly_map();
                    }
                }
            }
        }
    }

    #[inline]
    fn drain_reassembly_map(&mut self) {
        self.reassembly_map.retain(|seq, data| {
            if *seq != self.rcv.nxt {
                return true;
            }

            let len = data.len();
            let payload = mem::take(data);

            self.rcv_buf.extend(payload);
            self.rcv.nxt = self.rcv.nxt.wrapping_add(len as u32);
            self.rcv.wnd = self.rcv.wnd.saturating_sub(len as u16);

            false
        });
    }

    #[inline]
    #[must_use]
    const fn generate_iss() -> u32 {
        // TODO: Should be randomized instead. use `rand` crate.
        0
    }
}

/// Returns the total sequence space occupied by the TCP segment, including
/// `SYN`/`FIN` flags.
#[inline]
#[allow(clippy::missing_const_for_fn)] // MSRV 1.85
pub fn tcp_segment_len(payload: &[u8], syn: bool, fin: bool) -> u32 {
    payload.len() as u32 + u32::from(syn) + u32::from(fin)
}

/// Returns `true` is the value `x` is in between the values `start` and `end`,
/// using wrapping arithmetic.
#[inline]
const fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

#[inline]
const fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // RFC 1323, Section 2.3:
    //
    // TCP determines if a data segment is "old" or "new" by testing whether
    // its sequence number is within 2**31 bytes of the left edge of the window,
    // and if it is not, discarding the data as "old". To insure that new data
    // is never mistakenly considered old and vice-versa, the left edge of the
    // sender's window has to be at most 2**31 away from the right edge of the
    // receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    use crate::wire::Protocol;

    // Socket addresses used for tests.
    const TEST_SOCKET: SocketV4 = SocketV4 {
        src: SocketAddrV4 {
            addr: [192, 168, 0, 4],
            port: 12345,
        },
        dst: SocketAddrV4 {
            addr: [192, 168, 0, 5],
            port: 80,
        },
    };

    /// Generates a new `TCB` and optional segment pair, given the desired
    /// ending state, initial sequence number, and window size of the "peer".
    ///
    /// # Panics
    ///
    /// Will panic if the provided state is `CLOSED`, `LISTEN`, `SYN_SENT`, or
    /// `CLOSING`, if the `TCB` could not be unwrapped, or if the IPv4/TCP
    /// headers could not be constructed.
    fn gen_tcb_with_state(state: ConnectionState, isn: u32, wnd: u16) -> (TCB, Option<TcpSegment>) {
        // Using a separate function to generate a TCB in `SYN_RECEIVED` allows
        // me to adjust the `ISN` provided, so the sequence numbers can align
        // with the arbitrary segments used in prop tests.
        fn create_syn_recv_tcb(isn: u32, wnd: u16) -> (TCB, Option<TcpSegment>) {
            let mut syn = TcpHeader::new(TEST_SOCKET.dst.port, TEST_SOCKET.src.port, isn, wnd);
            syn.set_syn();
            syn.set_option_mss(1460).unwrap();

            let syn_ip = Ipv4Header::new(
                0,
                TEST_SOCKET.dst.addr,
                TEST_SOCKET.src.addr,
                syn.header_len() as u16,
                64,
                Protocol::TCP,
            )
            .unwrap();

            // Transitions from `LISTEN` -> `SYN_RECEIVED`...
            let (maybe_conn, maybe_syn_ack) = TCB::passive_open(&syn_ip, &syn).unwrap();

            (maybe_conn.unwrap(), maybe_syn_ack)
        }

        match state {
            ConnectionState::SYN_RECEIVED => create_syn_recv_tcb(isn.wrapping_sub(1), wnd),
            ConnectionState::ESTABLISHED => {
                let (mut conn, _maybe_syn_ack) = create_syn_recv_tcb(isn.wrapping_sub(1), wnd);

                let mut ack = TcpHeader::new(TEST_SOCKET.dst.port, TEST_SOCKET.src.port, isn, wnd);
                ack.set_ack_number(1);
                ack.set_ack();

                // Transitions from `SYN_RECEIVED` -> `ESTABLISHED`...
                let maybe_ack = conn
                    .process_segment(&Ipv4Header::default(), &ack, &[])
                    .unwrap();

                (conn, maybe_ack)
            }
            ConnectionState::FIN_WAIT_1 => {
                let (mut conn, _maybe_syn_ack) = create_syn_recv_tcb(isn.wrapping_sub(1), wnd);

                // Transitions from `SYN_RECEIVED` -> `FIN_WAIT_1`...
                let maybe_fin_ack = conn.close().unwrap();

                (conn, maybe_fin_ack)
            }
            ConnectionState::FIN_WAIT_2 => {
                let (mut conn, _maybe_syn_ack) = create_syn_recv_tcb(isn.wrapping_sub(1), wnd);

                // Transitions from `SYN_RECEIVED` -> `FIN_WAIT_1`...
                let _ = conn.close().unwrap();

                let mut ack = TcpHeader::new(TEST_SOCKET.dst.port, TEST_SOCKET.src.port, isn, wnd);
                ack.set_ack_number(2);
                ack.set_ack();

                // Transitions from `FIN_WAIT_1` -> `FIN_WAIT_2`...
                let maybe_ack = conn
                    .process_segment(&Ipv4Header::default(), &ack, &[])
                    .unwrap();

                (conn, maybe_ack)
            }
            ConnectionState::CLOSE_WAIT => {
                let (mut conn, _maybe_syn_ack) = create_syn_recv_tcb(isn.wrapping_sub(2), wnd);

                let mut fin_ack = TcpHeader::new(
                    TEST_SOCKET.dst.port,
                    TEST_SOCKET.src.port,
                    isn.wrapping_sub(1),
                    wnd,
                );
                fin_ack.set_ack_number(1);
                fin_ack.set_fin();
                fin_ack.set_ack();

                // Transitions from `SYN_RECEIVED` -> `CLOSE_WAIT`...
                let maybe_ack = conn
                    .process_segment(&Ipv4Header::default(), &fin_ack, &[])
                    .unwrap();

                (conn, maybe_ack)
            }
            ConnectionState::LAST_ACK => {
                let (mut conn, _maybe_syn_ack) = create_syn_recv_tcb(isn.wrapping_sub(2), wnd);

                let mut fin_ack = TcpHeader::new(
                    TEST_SOCKET.dst.port,
                    TEST_SOCKET.src.port,
                    isn.wrapping_sub(1),
                    wnd,
                );
                fin_ack.set_ack_number(1);
                fin_ack.set_fin();
                fin_ack.set_ack();

                // Transitions from `SYN_RECEIVED` -> `CLOSE_WAIT`...
                let _ = conn
                    .process_segment(&Ipv4Header::default(), &fin_ack, &[])
                    .unwrap();

                // Transitions from `CLOSE_WAIT` -> `LAST_ACK`...
                let maybe_fin_ack = conn.close().unwrap();

                (conn, maybe_fin_ack)
            }
            ConnectionState::TIME_WAIT => {
                let (mut conn, _maybe_syn_ack) = create_syn_recv_tcb(isn.wrapping_sub(2), wnd);

                // Transitions from `SYN_RECEIVED` -> `FIN_WAIT_1`...
                let _ = conn.close().unwrap();

                let mut fin_ack = TcpHeader::new(
                    TEST_SOCKET.dst.port,
                    TEST_SOCKET.src.port,
                    isn.wrapping_sub(1),
                    wnd,
                );
                fin_ack.set_ack_number(2);
                fin_ack.set_fin();
                fin_ack.set_ack();

                // Transitions from `FIN_WAIT_1` -> `TIME_WAIT`...
                let maybe_ack = conn
                    .process_segment(&Ipv4Header::default(), &fin_ack, &[])
                    .unwrap();

                (conn, maybe_ack)
            }
            _ => panic!("unable to generate TCB in {state:?} state"),
        }
    }

    /// Returns `true` if the sequence number provided is valid, assuming that
    /// the receive window is non-zero.
    const fn is_valid_seq(seqn: u32, seg_len: u32, rcv_nxt: u32, nxt_wnd: u32) -> bool {
        // NOTE: For sequence number checking, only case 2 and 4 are covered.
        if seg_len == 0 {
            is_between_wrapped(rcv_nxt.wrapping_sub(1), seqn, nxt_wnd)
        } else {
            is_between_wrapped(rcv_nxt.wrapping_sub(1), seqn, nxt_wnd)
                || is_between_wrapped(
                    rcv_nxt.wrapping_sub(1),
                    seqn.wrapping_add(seg_len - 1),
                    nxt_wnd,
                )
        }
    }

    /// Macro for validating TCB SND or RCV sequence spaces in prop tests.
    macro_rules! prop_assert_tcb {
        ($space:expr, $($field:ident: $value:expr),* $(,)?) => {
            $(
                prop_assert_eq!($space.$field, $value, "{} mismatch", stringify!($field));
            )*
        };
    }

    prop_compose! {
        /// Creates an semi-arbitrary TCP segment.
        ///
        /// The range for sequence and acknowledgment numbers are constrained
        /// for better coverage.
        ///
        /// Source and destination socket addresses are hard coded as they do
        /// not affect the state machine logic. Correct `socket -> connection`
        /// handling is not done by the FSM.
        fn arb_segment()
         (
             // seqn in any::<u32>(),
             seqn in 0..10_000u32,
             // ackn in any::<u32>(),
             ackn in 0..10_000u32,
             wnd in 0..64240u16,
             flags in prop_oneof![
                (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
                // Add small bias towards significant combinations.
                Just((false, false, false, true, false)), // SYN
                Just((true, false, false, true, false)), // SYN+ACK
                Just((true, false, false, false, false)), // ACK
                Just((false, false, true, false, false)), // RST
                Just((true, false, true, false, false)), // ACK+RST
                Just((true, false, false, false, true)) // FIN+ACK
             ],
             payload in prop::collection::vec(any::<u8>(), 0..128)
        ) -> TcpSegment {
                 let (ack, psh, rst, syn, fin) = flags;

                 let mut tcph =
                     TcpHeader::new(TEST_SOCKET.dst.port, TEST_SOCKET.src.port, seqn, wnd);
                 tcph.set_ack_number(ackn);

                 if ack {
                     tcph.set_ack();
                 }
                 if psh {
                     tcph.set_psh();
                 }
                 if rst {
                     tcph.set_rst();
                 }
                 if syn {
                     tcph.set_syn();
                 }
                 if fin {
                     tcph.set_fin();
                 }

                 let ip = Ipv4Header::new(
                     0,
                     TEST_SOCKET.dst.addr,
                     TEST_SOCKET.src.addr,
                     (tcph.header_len() + payload.len()) as u16,
                     64,
                     Protocol::TCP,
                 )
                 .unwrap();

                 TcpSegment::new(ip, tcph, &payload)
        }
    }

    proptest! {
        #[test]
        fn fsm_syn_sent_transitions(seg in arb_segment()) {
            let (mut conn, _syn) = TCB::active_open(TEST_SOCKET).unwrap();
            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            match conn.state {
                ConnectionState::SYN_SENT => {}
                ConnectionState::SYN_RECEIVED => {
                    prop_assert!(
                        !seg.tcph.ack() &&
                        !seg.tcph.rst() &&
                        seg.tcph.syn() &&
                        !seg.tcph.fin(),
                        "only SYN segment could transition from SYN_SENT -> SYN_RECEIVED"
                    );

                    let _ = conn.process_retransmissions();
                    prop_assert!(!conn.retransmit_queue.is_empty(),
                        "retransmission buffer should not be empty in transition from SYN_SENT -> SYN_RECEIVED"
                    );

                    prop_assert_tcb!(&conn.snd,
                        una: 0,
                        nxt: 2, // Sent the previous SYN + SYN+ACK
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: 0,
                        wl2: 0,
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        nxt: seg.tcph.seq_number() + 1, // ACKed the peer's SYN
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        irs: seg.tcph.seq_number()
                    );
                }
                ConnectionState::ESTABLISHED => {
                    prop_assert!(
                        seg.tcph.ack() &&
                        !seg.tcph.rst() &&
                        seg.tcph.syn() &&
                        !seg.tcph.fin(),
                        "only SYN+ACK segment could transition from SYN_SENT -> ESTABLISHED"
                    );
                    prop_assert_eq!(seg.tcph.ack_number(), conn.snd.iss + 1,
                        "SYN should be acknowledged in transition from SYN_SENT -> ESTABLISHED"
                    );

                    let _ = conn.process_retransmissions();
                    prop_assert!(conn.retransmit_queue.is_empty(),
                        "retransmission buffer should be empty in transition from SYN_SENT -> ESTABLISHED"
                    );

                    prop_assert_tcb!(&conn.snd,
                        una: 1, // ACKed the previous SYN
                        nxt: 1,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: 0,
                        wl2: 0,
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        nxt: seg.tcph.seq_number() + 1, // ACKed the peer's SYN
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        irs: seg.tcph.seq_number()
                    );
                }
                ConnectionState::CLOSED => {
                    // Either invalid ACK with no RST, or valid ACK+RST.
                    if seg.tcph.rst() {
                        prop_assert!(seg.tcph.ack() && seg.tcph.rst(),
                            "segment with at least ACK+RST (valid) could transition from SYN_SENT -> CLOSED"
                        );
                        prop_assert_eq!(seg.tcph.ack_number(), conn.snd.iss + 1,
                            "SYN should be acknowledged in transition from SYN_SENT -> CLOSED"
                        );
                    } else {
                        prop_assert!(seg.tcph.ack(),
                            "segment with at least ACK (invalid) could transition from SYN_SENT -> CLOSED"
                        );
                        prop_assert_ne!(seg.tcph.ack_number(), conn.snd.iss + 1,
                            "SYN should not be acknowledged in transition from SYN_SENT -> CLOSED"
                        );
                    }

                }
                _ => prop_assert!(false, "unexpected transition from SYN_SENT -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_syn_recv_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_syn_ack) = gen_tcb_with_state(ConnectionState::SYN_RECEIVED, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::SYN_RECEIVED);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            let acked_syn_ack = seg.tcph.ack_number() == conn.snd.nxt;

            match conn.state {
                ConnectionState::SYN_RECEIVED => {}
                ConnectionState::ESTABLISHED => {
                    prop_assert!(
                        (seg.tcph.ack() &&
                            !seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            !seg.tcph.fin()) ||
                        (seg.tcph.ack() &&
                            seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            !seg.tcph.fin()
                        ),
                        "only ACK or ACK+PSH segment could transition from SYN_RECEIVED -> ESTABLISHED"
                    );

                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from SYN_RECEIVED -> ESTABLISHED"
                    );

                    prop_assert!(
                        is_between_wrapped(
                            conn.snd.una.wrapping_sub(1),
                            seg.tcph.ack_number(),
                            conn.snd.nxt.wrapping_add(1),
                        ),
                        "acknowledgment number should be acceptable in transition from SYN_RECEIVED -> ESTABLISHED"
                    );

                    if acked_syn_ack {
                        let _ = conn.process_retransmissions();
                        prop_assert!(conn.retransmit_queue.is_empty(),
                            "retransmission buffer should be empty in transition from SYN_RECEIVED -> ESTABLISHED"
                        );
                    }

                    prop_assert_tcb!(&conn.snd,
                        una: u32::from(acked_syn_ack),
                        nxt: 1,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: if acked_syn_ack { seg.tcph.seq_number() } else { 0 },
                        wl2: if acked_syn_ack { seg.tcph.ack_number() } else { 0 },
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        // nxt: irs,
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        // To account for the TCB generation.
                        irs: irs.wrapping_sub(1)
                    );
                }
                ConnectionState::CLOSE_WAIT => {
                    prop_assert!(
                        (seg.tcph.ack() &&
                            !seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()) ||
                        (seg.tcph.ack() &&
                            seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()
                        ),
                        "only FIN+ACK or FIN+ACK+PSH segment could transition from SYN_RECEIVED -> CLOSE_WAIT"
                    );

                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from SYN_RECEIVED -> CLOSE_WAIT"
                    );

                    prop_assert!(
                        is_between_wrapped(
                            conn.snd.una.wrapping_sub(1),
                            seg.tcph.ack_number(),
                            conn.snd.nxt.wrapping_add(1),
                        ),
                        "acknowledgment number should be acceptable in transition from SYN_RECEIVED -> CLOSE_WAIT"
                    );

                    if acked_syn_ack {
                        let _ = conn.process_retransmissions();
                        prop_assert!(conn.retransmit_queue.is_empty(),
                            "retransmission buffer should be empty in transition from SYN_RECEIVED -> CLOSE_WAIT"
                        );
                    }

                    prop_assert_tcb!(&conn.snd,
                        una: u32::from(acked_syn_ack),
                        nxt: 1,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: if acked_syn_ack { seg.tcph.seq_number() } else { 0 },
                        wl2: if acked_syn_ack { seg.tcph.ack_number() } else { 0 },
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        nxt: irs.wrapping_add(1), // Received FIN
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        // To account for the TCB generation.
                        irs: irs.wrapping_sub(1)
                    );
                }
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from SYN_RECEIVED -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() ||
                        seg.tcph.syn() ||
                        seg.tcph.ack(),
                        "segment with either SYN, RST, or ACK could transition from SYN_RECEIVED -> CLOSED"
                    );

                    if seg.tcph.ack() && !seg.tcph.syn() && !seg.tcph.rst() {
                        prop_assert!(
                            !is_between_wrapped(
                                conn.snd.una.wrapping_sub(1),
                                seg.tcph.ack_number(),
                                conn.snd.nxt.wrapping_add(1),
                            ),
                            "acknowledgment number from ACK segment should not be acceptable in transition from SYN_RECEIVED -> CLOSED"
                        );
                    }
                }
                _ => prop_assert!(false, "unexpected transition from SYN_RECEIVED -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_estab_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_syn_ack) = gen_tcb_with_state(ConnectionState::ESTABLISHED, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::ESTABLISHED);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            match conn.state {
                ConnectionState::ESTABLISHED => {}
                ConnectionState::CLOSE_WAIT => {
                    prop_assert!(
                        (seg.tcph.ack() &&
                            !seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()) ||
                        (seg.tcph.ack() &&
                            seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()
                        ),
                        "only FIN+ACK or FIN+ACK+PSH segment could transition from ESTABLISHED -> CLOSE_WAIT"
                    );

                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from ESTABLISHED -> CLOSE_WAIT"
                    );

                    prop_assert!(
                        is_between_wrapped(
                            conn.snd.una.wrapping_sub(1),
                            seg.tcph.ack_number(),
                            conn.snd.nxt.wrapping_add(1),
                        ),
                        "acknowledgment number should be acceptable in transition from ESTABLISHED -> CLOSE_WAIT"
                    );

                    let _ = conn.process_retransmissions();
                    prop_assert!(conn.retransmit_queue.is_empty(),
                        "retransmission buffer should be empty in transition from ESTABLISHED -> CLOSE_WAIT"
                    );

                    let window_update = is_between_wrapped(
                        conn.snd.una,
                        seg.tcph.ack_number(),
                        conn.snd.nxt.wrapping_add(1),
                    );

                    prop_assert_tcb!(&conn.snd,
                        una: 1,
                        nxt: 1,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        // If the window was not updated, WL1 remains with the
                        // value of the last update (the `irs` when peer sends
                        // ACK in response to SYN+ACK).
                        wl1: if window_update { seg.tcph.seq_number() } else { irs },
                        wl2: 1,
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        nxt: irs.wrapping_add(1), // Received FIN
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        // To account for the TCB generation.
                        irs: irs.wrapping_sub(1)
                    );
                }
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from ESTABLISHED -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() || seg.tcph.syn(),
                        "segment with either SYN or RST could transition from ESTABLISHED -> CLOSED"
                    );
                }
                _ => prop_assert!(false, "unexpected transition from ESTABLISHED -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_fin_wait_1_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_fin_ack) = gen_tcb_with_state(ConnectionState::FIN_WAIT_1, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::FIN_WAIT_1);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            let acked_fin_ack = seg.tcph.ack_number() == conn.snd.nxt;
            let acked_syn_ack = seg.tcph.ack_number() >= conn.snd.nxt - 1;

            match conn.state {
                ConnectionState::FIN_WAIT_1 => {}
                ConnectionState::FIN_WAIT_2 => {
                    prop_assert!(
                        (seg.tcph.ack() &&
                            !seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            !seg.tcph.fin()) ||
                        (seg.tcph.ack() &&
                            seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            !seg.tcph.fin()
                        ),
                        "only ACK or ACK+PSH segment could transition from FIN_WAIT_1 -> FIN_WAIT_2"
                    );

                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from FIN_WAIT_1 -> FIN_WAIT_2"
                    );

                    prop_assert!(
                        is_between_wrapped(
                            conn.snd.una.wrapping_sub(1),
                            seg.tcph.ack_number(),
                            conn.snd.nxt.wrapping_add(1),
                        ),
                        "acknowledgment number should be acceptable in transition from FIN_WAIT_1 -> FIN_WAIT_2"
                    );

                    if acked_fin_ack {
                        let _ = conn.process_retransmissions();
                        prop_assert!(conn.retransmit_queue.is_empty(),
                            "retransmission buffer should be empty in transition from FIN_WAIT_1 -> FIN_WAIT_2"
                        );
                    }

                    prop_assert_tcb!(&conn.snd,
                        una: u32::from(acked_syn_ack) + u32::from(acked_fin_ack),
                        nxt: 2,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: if acked_syn_ack || acked_fin_ack { seg.tcph.seq_number() } else { 0 },
                        wl2: u32::from(acked_syn_ack) + u32::from(acked_fin_ack),
                        iss: 0
                   );

                    prop_assert_tcb!(&conn.rcv,
                        nxt: irs,
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        // To account for the TCB generation.
                        irs: irs.wrapping_sub(1)
                    );
                }
                ConnectionState::TIME_WAIT => {
                    prop_assert!(
                        (seg.tcph.ack() &&
                            !seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()) ||
                        (seg.tcph.ack() &&
                            seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()
                        ),
                        "only FIN+ACK or FIN+ACK+PSH segment could transition from FIN_WAIT_1 -> TIME_WAIT"
                    );

                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from FIN_WAIT_1 -> TIME_WAIT"
                    );

                    prop_assert!(
                        is_between_wrapped(
                            conn.snd.una.wrapping_sub(1),
                            seg.tcph.ack_number(),
                            conn.snd.nxt.wrapping_add(1),
                        ),
                        "acknowledgment number should be acceptable in transition from FIN_WAIT_1 -> TIME_WAIT"
                    );

                    if acked_fin_ack {
                        let _ = conn.process_retransmissions();
                        prop_assert!(conn.retransmit_queue.is_empty(),
                            "retransmission buffer should be empty in transition from FIN_WAIT_1 -> TIME_WAIT"
                        );
                    }

                    prop_assert_tcb!(&conn.snd,
                        una: u32::from(acked_syn_ack) + u32::from(acked_fin_ack),
                        nxt: 2,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: if acked_syn_ack || acked_fin_ack { seg.tcph.seq_number() } else { 0 },
                        wl2: u32::from(acked_syn_ack) + u32::from(acked_fin_ack),
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        // Received a `FIN`.
                        nxt: irs.wrapping_add(1),
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        // To account for the TCB generation.
                        irs: irs.wrapping_sub(1)
                    );
                }
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from FIN_WAIT_1 -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() || seg.tcph.syn(),
                        "segment with either SYN or RST could transition from FIN_WAIT_1 -> CLOSED"
                    );
                }
                _ => prop_assert!(false, "unexpected transition from FIN_WAIT_1 -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_fin_wait_2_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_ack) = gen_tcb_with_state(ConnectionState::FIN_WAIT_2, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::FIN_WAIT_2);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            match conn.state {
                ConnectionState::FIN_WAIT_2 => {}
                ConnectionState::TIME_WAIT => {
                    prop_assert!(
                        (seg.tcph.ack() &&
                            !seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()) ||
                        (seg.tcph.ack() &&
                            seg.tcph.psh() &&
                            !seg.tcph.rst() &&
                            !seg.tcph.syn() &&
                            seg.tcph.fin()
                        ),
                        "only FIN+ACK or FIN+ACK+PSH segment could transition from FIN_WAIT_2 -> TIME_WAIT"
                    );

                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from FIN_WAIT_2 -> TIME_WAIT"
                    );

                    prop_assert!(
                        is_between_wrapped(
                            conn.snd.una.wrapping_sub(1),
                            seg.tcph.ack_number(),
                            conn.snd.nxt.wrapping_add(1),
                        ),
                        "acknowledgment number should be acceptable in transition from FIN_WAIT_2 -> TIME_WAIT"
                    );

                    let _ = conn.process_retransmissions();
                    prop_assert!(conn.retransmit_queue.is_empty(),
                        "retransmission buffer should be empty in transition from FIN_WAIT_2 -> TIME_WAIT"
                    );

                    prop_assert_tcb!(&conn.snd,
                        una: 2,
                        nxt: 2,
                        wnd: seg.tcph.window(),
                        up: seg.tcph.urgent_pointer(),
                        wl1: irs,
                        wl2: 2,
                        iss: 0
                    );

                    prop_assert_tcb!(&conn.rcv,
                        // Received a `FIN`.
                        nxt: irs.wrapping_add(1),
                        wnd: DEFAULT_RCV_WND,
                        up: 0,
                        // To account for the TCB generation.
                        irs: irs.wrapping_sub(1)
                    );
                }
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from FIN_WAIT_2 -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() || seg.tcph.syn(),
                        "segment with either SYN or RST could transition from FIN_WAIT_2 -> CLOSED"
                    );
                }
                _ => prop_assert!(false, "unexpected transition from FIN_WAIT_2 -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_close_wait_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_ack) = gen_tcb_with_state(ConnectionState::CLOSE_WAIT, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::CLOSE_WAIT);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            match conn.state {
                ConnectionState::CLOSE_WAIT => {}
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from CLOSE_WAIT -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() || seg.tcph.syn(),
                        "segment with either SYN or RST could transition from CLOSE_WAIT -> CLOSED"
                    );
                }
                _ => prop_assert!(false, "unexpected transition from CLOSE_WAIT -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_last_ack_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_ack) = gen_tcb_with_state(ConnectionState::LAST_ACK, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::LAST_ACK);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            match conn.state {
                ConnectionState::LAST_ACK => {}
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from LAST_ACK -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() || seg.tcph.syn() || seg.tcph.ack(),
                        "segment with either ACK, SYN, or RST could transition from LAST_ACK -> CLOSED"
                    );

                    if seg.tcph.ack() && !seg.tcph.syn() && !seg.tcph.rst() {
                        prop_assert!(
                            is_between_wrapped(
                                conn.snd.una.wrapping_sub(1),
                                seg.tcph.ack_number(),
                                conn.snd.nxt.wrapping_add(1),
                            ),
                            "acknowledgment number from ACK segment should be acceptable in transition from LAST_ACK -> CLOSED"
                        );
                    }
                }
                _ => prop_assert!(false, "unexpected transition from LAST_ACK -> {:?}", conn.state),
            }
        }

        #[test]
        fn fsm_time_wait_transitions(seg in arb_segment()) {
            // For any arbitrary segment, if we back-compute the IRS and build
            // up the TCB to a target state using it, then the generated TCB
            // will contain synthetic but valid state, essentially building a
            // consistent history up until this arbitrary segment.
            let seg_len = u32::from(seg.tcph.syn()) + u32::from(seg.tcph.fin()) + seg.payload.len() as u32;
            let irs = seg.tcph.seq_number().wrapping_sub(seg_len);

            let (mut conn, _maybe_ack) = gen_tcb_with_state(ConnectionState::TIME_WAIT, irs, seg.tcph.window());

            prop_assert_eq!(conn.state, ConnectionState::TIME_WAIT);
            prop_assert_eq!(conn.rcv.nxt, irs);

            let _maybe_reply = conn.process_segment(&seg.iph, &seg.tcph, &seg.payload);

            match conn.state {
                ConnectionState::TIME_WAIT => {}
                ConnectionState::CLOSED => {
                    prop_assert!(
                        is_valid_seq(
                            seg.tcph.seq_number(),
                            seg_len,
                            conn.rcv.nxt,
                            conn.rcv.nxt.wrapping_add(u32::from(conn.rcv.wnd))
                        ),
                        "sequence number should be valid in transition from TIME_WAIT -> CLOSED"
                    );

                    prop_assert!(
                        seg.tcph.rst() || seg.tcph.syn(),
                        "segment with either SYN or RST could transition from TIME_WAIT -> CLOSED"
                    );
                }
                _ => prop_assert!(false, "unexpected transition from TIME_WAIT -> {:?}", conn.state),
            }
        }
    }
}
