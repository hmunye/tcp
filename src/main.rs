use std::io;
use std::process;

use tcp::parse::{IPv4Header, Protocol, TCPHeader};
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
                    "ipv4 datagram | src: {:?}, dst: {:?}, chksum: 0x{:04x} (valid: {}), payload: {} bytes",
                    p.src(),
                    p.dst(),
                    p.header_checksum(),
                    p.compute_header_checksum() == p.header_checksum(),
                    p.payload_len().unwrap_or(u16::MAX)
                );

                match TCPHeader::try_from(&buf[p.header_len()..nbytes]) {
                    Ok(t) => {
                        let payload = &buf[p.header_len() + t.header_len()..nbytes];

                        info!(
                            "tcp segment | src port: {}, dst port: {}, seq num: {}, ack num: {}, data offset: {}, urg: {}, ack: {}, psh: {}, rst: {}, syn: {}, fin: {}, window: {}, chksum: 0x{:04x} (valid: {}), urgent pointer: {}, mss: {:?}, payload: {} bytes",
                            t.src_port(),
                            t.dst_port(),
                            t.seq_number(),
                            t.ack_number(),
                            t.data_offset(),
                            t.urg(),
                            t.ack(),
                            t.psh(),
                            t.rst(),
                            t.syn(),
                            t.fin(),
                            t.window(),
                            t.checksum(),
                            t.compute_checksum(&p, &[]) == t.checksum(),
                            t.urgent_pointer(),
                            t.options().mss(),
                            payload.len()
                        );
                    }
                    Err(err) => {
                        error!("{err}");
                    }
                }
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
