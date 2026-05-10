//! Transmission Control Protocol [RFC 793]
//!
//! Provides a connection-oriented, end-to-end reliable service for packet-based
//! communication between pairs of processes on hosts within distinct but
//! interconnected networks.
//!
//! Transfers a continuous, bidirectional byte stream between applications by
//! segmenting data for transmission across the network. Connections are
//! multiplexed via sockets, which combine IP addresses and ports. Each
//! connection is uniquely identified by its source and destination socket pair.
//!
//! Guarantees reliable delivery through sequence numbering, positive
//! acknowledgments, and retransmission timeouts. Receivers use these numbers to
//! reorder segments, discard duplicates, and verify data integrity with
//! per-segment checksums. Flow control is managed by the peer advertising a
//! receive window in each ACK, specifying how many bytes the sender can
//! transmit before the window must be refreshed.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793

mod header;
pub use header::TcpHeader;

mod options;
pub use options::TcpOptions;

mod segment;
pub use segment::TcpSegment;
