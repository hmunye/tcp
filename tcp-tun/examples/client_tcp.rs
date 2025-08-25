//! A simple client that opens a TCP stream, sends a message received from
//! `stdin` to the peer, and closes the connection upon receiving an "exit"
//! message.
//!
//! Before running this example, ensure the TUN interface and binary are set up
//! by running:
//!
//!     ./setup.sh
//!
//! To start a server that this client can talk to on port 6142, you can use
//! this command:
//!
//!     nc -s 10.0.0.1 -l -p 6142
//!
//! And then in another terminal run:
//!
//!     cargo r --release --example client_tcp

use tcp_tun::net::TcpStream;

use std::io::{self, Write};

fn main() -> io::Result<()> {
    let mut stream = TcpStream::connect("10.0.0.1:6142")?;

    let mut buf = String::new();

    loop {
        let _ = io::stdin().read_line(&mut buf)?;
        if buf == "exit\n" {
            break;
        }

        stream.write_all(buf.as_bytes())?;

        buf.clear();
    }

    Ok(())
}
