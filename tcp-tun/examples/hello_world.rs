//! A simple client that opens a TCP stream, writes "hello world\n", and closes
//! the connection.
//!
//! To start a server that this client can talk to on port 6142, you can use
//! this command:
//!
//!     nc -s 10.0.0.1 -l -p 6142
//!
//! And then in another terminal run:
//!
//!     cargo r --example hello_world

use tcp_tun::net::TcpStream;

use std::io::{self, Write};

fn main() -> io::Result<()> {
    let mut stream = TcpStream::connect(6142)?;
    stream.write_all(b"hello world\n")?;

    Ok(())
}
