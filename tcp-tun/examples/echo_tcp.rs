//! A simple echo server that listens for incoming TCP connections on
//! `10.0.0.1:80`. It spawns a separate thread for each connection and echoes
//! back any data received from the client.
//!
//! Before running this example, make sure to set up the TUN interface and build
//! the binary by executing:
//!
//!     DEBUG=1 ./setup.sh
//!
//! Then, in a separate terminal, start the server with:
//!
//!     cargo r --example echo_tcp
//!
//! To test the server, you can initiate a TCP connections using netcat:
//!
//!     nc -s 10.0.0.1 10.0.0.2 80

use tcp_tun::net::{Socket, TcpListener, TcpStream};

use tcp_core::info;

use std::io::{self, Read, Write};

fn handle_client(mut stream: TcpStream, sock: Socket) -> io::Result<()> {
    let mut buf = [0u8; 1024];

    loop {
        let nbytes = stream.read(&mut buf[..])?;
        if nbytes == 0 {
            break;
        }

        let data = unsafe { std::str::from_utf8_unchecked(&buf[..nbytes]) };

        info!(
            "[{sock}] read {nbytes} bytes from peer: {}",
            data.escape_debug()
        );

        let written = stream.write(&buf[..nbytes])?;
        if written == 0 {
            break;
        }

        info!("[{sock}] wrote {written} bytes to peer");
    }

    Ok(())
}

fn main() -> io::Result<()> {
    // Currently can only listen on the address `10.0.0.1`.
    //
    // Any valid port can be used.
    let listener = TcpListener::bind("10.0.0.1:80")?;

    for stream in listener.incoming() {
        let stream = stream?;

        let sock = Socket {
            src: stream.local_addr(),
            dst: stream.peer_addr(),
        };

        info!("[{sock}] accepted new connection");

        std::thread::spawn(move || handle_client(stream, sock).unwrap());
    }

    Ok(())
}
