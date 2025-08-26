//! A simple echo server that listens for incoming TCP connections on
//! `10.0.0.1:80`. It spawns a separate thread for each connection and echoes
//! back any data received from the client.
//!
//! Before running this example, ensure the TUN interface and binary are set up
//! by running:
//!
//!     DEBUG=1 ./setup.sh
//!
//! Then, in a separate terminal, start the server with:
//!
//!     cargo r --example echo_tcp
//!
//! To test the server, you can initiate a TCP connection using netcat:
//!
//!     nc -s 10.0.0.1 10.0.0.2 80

use tcp_tun::net::{TcpListener, TcpStream};

use std::io::{self, Read, Write};

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut buf = [0u8; 1024];

    loop {
        let nbytes = stream.read(&mut buf[..])?;
        if nbytes == 0 {
            break;
        }

        let written = stream.write(&buf[..nbytes])?;
        if written == 0 {
            break;
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    // Currently only listens on IP address `10.0.0.1` unless script is
    // configured.
    let listener = TcpListener::bind("10.0.0.1:80")?;

    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::spawn(move || handle_client(stream).unwrap());
    }

    Ok(())
}
