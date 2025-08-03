use std::collections::{HashMap, hash_map::Entry};
use std::process;

use tcp::net::{Ipv4Header, Protocol, TcpHeader};
use tcp::net::{Socket, TCB};
use tcp::tun_tap::{self, MTU_SIZE};
use tcp::{error, info, warn};

fn main() {
    let mut nic = tun_tap::Tun::without_packet_info("tun0").unwrap_or_else(|err| {
        error!("failed to create TUN interface: {err}");
        process::exit(1);
    });

    info!("interface name: {}", nic.name());

    let mut connections: HashMap<Socket, TCB> = Default::default();

    listen_loop(&mut nic, &mut connections);
}

fn listen_loop(nic: &mut tun_tap::Tun, connections: &mut HashMap<Socket, TCB>) -> ! {
    let mut buf = [0u8; MTU_SIZE];

    loop {
        let nbytes = nic.recv(&mut buf[..]).unwrap_or_else(|err| {
            error!("failed to read from TUN interface: {err}");
            process::exit(1);
        });

        match Ipv4Header::try_from(&buf[..nbytes]) {
            Ok(iph) if iph.protocol() == Protocol::TCP => {
                let src = iph.src();
                let dst = iph.dst();

                match TcpHeader::try_from(&buf[iph.header_len()..nbytes]) {
                    Ok(tcph) => {
                        let src_port = tcph.src_port();
                        let dst_port = tcph.dst_port();
                        let payload = &buf[iph.header_len() + tcph.header_len()..nbytes];

                        // Packets are from the peer's perspective, so src/dst
                        // are flipped. Reverse them to match the format used
                        // when initiating connections, ensuring consistent
                        // socket lookup in the connection hash map.
                        let socket = Socket {
                            src: (dst, dst_port),
                            dst: (src, src_port),
                        };

                        match connections.entry(socket) {
                            Entry::Vacant(entry) => match TCB::on_conn_req(nic, &iph, &tcph) {
                                Ok(opt) => {
                                    if let Some(conn) = opt {
                                        entry.insert(conn);
                                    }
                                }
                                Err(err) => {
                                    error!("failed to process incoming TCP segment: {err}");
                                }
                            },
                            Entry::Occupied(mut conn) => {
                                conn.get_mut()
                                    .on_packet(nic, &iph, &tcph, payload)
                                    .unwrap_or_else(|err| {
                                        error!("failed to process incoming TCP segment: {err}");
                                    });
                            }
                        }
                    }
                    Err(err) => {
                        error!("{err}");
                    }
                }
            }
            Ok(p) => {
                warn!("ignoring non-TCP ({:?}) packet", p.protocol());
            }
            Err(err) => {
                error!("{err}");
            }
        }
    }
}
