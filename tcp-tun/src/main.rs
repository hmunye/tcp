use tcp_core::{Result, info};

use std::io::{Read, Write};

use tcp_tun::net::{TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) -> Result<()> {
    let mut buf = [0u8; 1024];

    loop {
        let nbytes = stream.read(&mut buf[..])?;
        info!("read {nbytes} bytes from peer: {}", unsafe {
            std::str::from_utf8_unchecked(&buf[..])
        });

        let written = stream.write(&buf[..nbytes])?;
        info!("wrote {nbytes} bytes to the peer");

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
        info!("accepted connection from {:?}", stream.peer_addr());
        handle_client(stream)?;
    }
}
