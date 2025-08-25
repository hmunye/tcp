//! Provides networking functionality for the Transmission Control Protocol.

pub(crate) mod interface;
pub use interface::{Shutdown, TcpListener, TcpStream};

// Re-export for use with this crate.
pub use tcp_core::protocol::{Socket, SocketAddr};
