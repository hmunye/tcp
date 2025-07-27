use std::io;
use std::process;

use tcp::parse::{IPv4Header, Protocol};
use tcp::tun_tap;
use tcp::{error, info, warn};

fn main() -> io::Result<()> {
    let nic = tun_tap::Tun::without_packet_info("tun0").unwrap_or_else(|err| {
        error!("failed to create TUN interface: {err}");
        process::exit(1);
    });

    let mut buf = [0u8; 1500];

    info!("interface name: {}", nic.name());

    loop {
        let nbytes = nic.recv(&mut buf[..]).unwrap_or_else(|err| {
            error!("failed to read from TUN interface: {err}");
            process::exit(1);
        });

        info!("read {} bytes: {:x?}", nbytes, &buf[..nbytes]);

        match IPv4Header::try_from(&buf[..nbytes]) {
            Ok(p) if p.protocol() == Protocol::TCP => {
                info!(
                    "IPv4 TCP Packet | Ver: {}, IHL: {}, TOS: {}, Total: {}, ID: {}, DF: {}, MF: {}, FragOff: {}, TTL: {}, Proto: {:?}, Chksum: 0x{:04x} (valid: {}), SRC: {:?}, DST: {:?}, Payload: {} bytes",
                    p.version(),
                    p.ihl(),
                    p.tos(),
                    p.total_len(),
                    p.id(),
                    p.dont_fragment(),
                    p.more_fragments(),
                    p.fragment_offset(),
                    p.ttl(),
                    p.protocol(),
                    p.header_checksum(),
                    p.compute_header_checksum() == p.header_checksum(),
                    p.src(),
                    p.dst(),
                    p.payload_len().unwrap_or(u16::MAX)
                );
            }
            Ok(_) => {
                warn!("ignoring non-TCP packet");
            }
            Err(err) => {
                error!("{err}");
            }
        }
    }
}
