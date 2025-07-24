use std::io;
use std::process;

use tcp::tun_tap;

fn main() -> io::Result<()> {
    // Create a new TUN interface named "tun0".
    let nic = tun_tap::Tun::new("tun0").unwrap_or_else(|err| {
        tcp::log_err(format!("tun: {err}"));
        process::exit(1);
    });

    let mut buf = [0u8; 1504];

    println!("interface name: {}", nic.name());

    loop {
        // Receive an IP packet from the TUN interface.
        let nbytes = nic.recv(&mut buf[..]).unwrap_or_else(|err| {
            tcp::log_err(format!("recv: {err}"));
            process::exit(1);
        });

        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        println!("(flags: {flags:04x?}, proto: {proto:04x?})");
        println!("read {nbytes} bytes: raw packet: {:x?}", &buf[..nbytes]);
    }
}
