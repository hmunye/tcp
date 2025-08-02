use std::collections::{HashMap, hash_map::Entry};
use std::io::{self, Write};
use std::{env, process};

use tcp::parse::{Ipv4Header, Protocol, TcpHeader};
use tcp::protocol::{Socket, TCB};
use tcp::tun_tap::{self, MTU_SIZE};
use tcp::{error, info, warn};

const SRC_ADDR: [u8; 4] = [10, 0, 0, 2];
const SRC_PORT: u16 = 44932;

const DST_ADDR: [u8; 4] = [10, 0, 0, 1];
const DST_PORT: u16 = 8080;

fn main() {
    let mut nic = tun_tap::Tun::without_packet_info("tun0").unwrap_or_else(|err| {
        error!("failed to create TUN interface: {err}");
        process::exit(1);
    });

    info!("interface name: {}", nic.name());

    let mut connections: HashMap<Socket, TCB> = Default::default();

    if env::var("CLIENT").is_ok() {
        info!("client ready for connections: send connection request? (press enter)");
        io::stdout().flush().unwrap();

        let mut cont = String::new();
        io::stdin().read_line(&mut cont).unwrap();
        drop(cont);

        let socket = Socket {
            src: (SRC_ADDR, SRC_PORT),
            dst: (DST_ADDR, DST_PORT),
        };

        let conn = TCB::on_conn_init(&mut nic, socket).unwrap_or_else(|err| {
            error!("failed to initiate TCP connection: {err}");
            process::exit(1);
        });

        connections.insert(socket, conn);
    } else {
        info!("server ready for connections");
    }

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
                                Ok(conn) => {
                                    entry.insert(conn);
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
