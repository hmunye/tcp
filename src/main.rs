use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::process;

use tcp::parse::{IPv4Header, Protocol, TCPHeader};
use tcp::protocol::{Socket, TCB};
use tcp::tun_tap::{self, MTU_SIZE};
use tcp::{error, info, warn};

fn main() {
    let mut nic = tun_tap::Tun::without_packet_info("tun0").unwrap_or_else(|err| {
        error!("failed to create TUN interface: {err}");
        process::exit(1);
    });

    let mut connections: HashMap<Socket, TCB> = Default::default();

    listen_loop(&mut nic, &mut connections);
}

/// Runs the main loop for handling incoming TCP connections on the given TUN
/// interface.
///
/// This function continuously reads packets from the TUN interface, parses IPv4
/// and TCP headers, and either initializes new connections or forwards segments
/// to existing ones. It is intended to represent the *listening* (passive) side
/// of a TCP implementation.
///
/// # Panics
///
/// Exits the process if it encounters a failure while reading from the TUN
/// interface.
fn listen_loop(nic: &mut tun_tap::Tun, connections: &mut HashMap<Socket, TCB>) -> ! {
    let mut buf = [0u8; MTU_SIZE];

    info!("interface name: {}", nic.name());

    loop {
        let nbytes = nic.recv(&mut buf[..]).unwrap_or_else(|err| {
            error!("failed to read from TUN interface: {err}");
            process::exit(1);
        });

        match IPv4Header::try_from(&buf[..nbytes]) {
            Ok(iph) if iph.protocol() == Protocol::TCP => {
                let src = iph.src();
                let dst = iph.dst();

                match TCPHeader::try_from(&buf[iph.header_len()..nbytes]) {
                    Ok(tcph) => {
                        let src_port = tcph.src_port();
                        let dst_port = tcph.dst_port();

                        let payload = &buf[iph.header_len() + tcph.header_len()..nbytes];

                        match connections.entry(Socket::new((src, src_port), (dst, dst_port))) {
                            Entry::Vacant(entry) => match TCB::on_conn_req(nic, &iph, &tcph) {
                                Ok(conn) => {
                                    entry.insert(conn);
                                }
                                Err(err) => {
                                    error!(
                                        "failed to process incoming TCP connection request: {err}"
                                    );
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
