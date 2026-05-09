use std::time::{Duration, Instant};

use crate::wire::TcpSegment;

/// TCP segment awaiting acknowledgment, tracking its transmission timer and
/// retry count.
#[derive(Debug)]
pub struct RetransmissionEntry {
    /// TCP segment queued for retransmission.
    pub(crate) segment: TcpSegment,
    /// [`Instant`] the TCP segment was last transmitted.
    pub(crate) timer: Instant,
    /// Number of retransmission attempts, used for exponential backoff and
    /// retry limit tracking.
    pub(crate) transmit_count: usize,
}

impl RetransmissionEntry {
    /// Maximum number of retransmission attempts before the connection is
    /// closed.
    const RETRANSMIT_LIMIT: usize = 5;

    /// Initial retransmission timeout (`RTO`), in seconds.
    const RTO: u64 = 3;

    /// Returns a new `RetransmissionEntry`, given a `TcpSegment`.
    #[inline]
    #[must_use]
    pub fn new(segment: TcpSegment) -> Self {
        RetransmissionEntry {
            segment,
            timer: Instant::now(),
            transmit_count: 0,
        }
    }

    /// Calculates the effective retransmission timeout using exponential
    /// backoff to avoid excessive retransmissions.
    #[inline]
    pub const fn effective_rto(&self) -> Duration {
        Duration::from_secs(Self::RTO * (1 << self.transmit_count))
    }

    /// Returns the total sequence space occupied by the TCP segment, including
    /// `SYN`/`FIN` flags.
    #[inline]
    pub fn segment_len(&self) -> u32 {
        self.segment.payload.len() as u32
            + self.segment.tcph.syn() as u32
            + self.segment.tcph.fin() as u32
    }

    /// Returns `true` if the peer has fully acknowledged this TCP segment.
    #[inline]
    pub const fn is_acked(&self, segment_len: u32, una: u32) -> bool {
        // Fully acknowledged if the segment's sequence range falls at or below
        // the peer's SND.UNA.
        self.segment.tcph.seq_number().wrapping_add(segment_len) <= una
    }

    /// Returns `true` if the retransmission limit has been exceeded.
    #[inline]
    pub const fn at_retry_limit(&self) -> bool {
        self.transmit_count >= Self::RETRANSMIT_LIMIT
    }

    /// Returns `true` if the retransmission timer has expired.
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.timer.elapsed() >= self.effective_rto()
    }
}
