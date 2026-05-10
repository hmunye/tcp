//! Internet Protocol Version 4 [(RFC 791)].
//!
//! Enables packet-based communication across interconnected networks. Handles
//! fragmentation, reassembly, and delivery of blocks of data (datagrams)
//! between source and destination addresses, treating each datagram as an
//! independent entity.
//!
//! IP fragmentation splits datagrams to traverse networks with a smaller
//! maximum transmission unit (MTU). If the `DF` flag is set, fragmentation is
//! strictly prohibited and the packet above the MTU is dropped instead. The
//! `identification` field groups fragments belonging to the same original
//! datagram. Together with the source and destination addresses and protocol
//! field, it uniquely identifies each datagram for reassembly.
//!
//! Encapsulates upper-layer protocol data for routing across network
//! boundaries. It does **not** provide reliable communication (e.g.,
//! acknowledgments, retransmissions, or error control).
//!
//! [(RFC 791)]: https://www.rfc-editor.org/rfc/rfc791

mod header;
pub use header::Ipv4Header;

mod protocol;
pub use protocol::Protocol;

mod options;
pub use options::Ipv4Options;
