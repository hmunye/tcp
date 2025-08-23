use tcp_core::protocol::socket::Socket;
use tcp_core::{Result, info};
use tcp_tun::net::{TcpListener, TcpStream};

use std::io::{Read, Write};

fn handle_client(mut stream: TcpStream) -> Result<()> {
    let mut buf = [0u8; 1024];

    let sock = Socket {
        src: stream.local_addr(),
        dst: stream.peer_addr(),
    };

    loop {
        let nbytes = stream.read(&mut buf[..])?;
        let data = unsafe { std::str::from_utf8_unchecked(&buf[..nbytes]) };
        info!(
            "[{sock}] read {nbytes} bytes from peer: {}",
            data.escape_debug()
        );

        let written = stream.write(&buf[..nbytes])?;
        info!("[{sock}] wrote {nbytes} bytes to the peer");

        if written == 0 {
            break;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let listener = TcpListener::bind(80)?;

    loop {
        let stream = listener.accept()?;

        let sock = Socket {
            src: stream.local_addr(),
            dst: stream.peer_addr(),
        };

        info!("[{sock}] accepted new connection");

        std::thread::spawn(move || handle_client(stream).unwrap());
    }
}
