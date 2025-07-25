use std::io;
use std::process;

use tcp::tun_tap;
use tcp::{error, info};

fn main() -> io::Result<()> {
    let nic = tun_tap::Tun::new("tun0").unwrap_or_else(|err| {
        error!("tun: {err}");
        process::exit(1);
    });

    let mut buf = [0u8; 1504];

    info!("interface name: {}", nic.name());

    loop {
        let nbytes = nic.recv(&mut buf[..]).unwrap_or_else(|err| {
            error!("recv: {err}");
            process::exit(1);
        });

        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        info!("(flags: {flags:04x?}, proto: {proto:04x?})");
        info!("read {nbytes} bytes: raw packet: {:x?}", &buf[..nbytes]);
    }
}
