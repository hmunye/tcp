#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2018_idioms)]
#![warn(missing_debug_implementations)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::use_self)]
#![allow(clippy::redundant_else)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::unused_self)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::single_match_else)]

mod tun;

#[cfg(not(target_os = "linux"))]
compile_error!("tcp-tun requires a platform with `/dev/net/tun` (Linux)");

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use futures::channel::mpsc;
use futures::{FutureExt, StreamExt};
use rio::io::{AsyncReadExt, AsyncWriteExt};
use tcp::protocol::TCB;
use tcp::wire::{Ipv4Header, Protocol, TcpHeader};
use tcp::{Result, SocketAddrV4, SocketV4};

const SERVER_PORT: u16 = 80;

async fn demux_segment(
    iph: Ipv4Header,
    tcph: TcpHeader,
    _payload: &[u8],
    connections: &mut HashMap<SocketV4, TCB>,
    mut tx: mpsc::Sender<Vec<u8>>,
) {
    let peer = iph.src_addr();
    let peer_port = tcph.src_port();
    let local = iph.dst_addr();
    let local_port = tcph.dst_port();

    // `dst == 10.0.0.1` is guaranteed by the tun interface.
    if local_port == SERVER_PORT {
        // segment arrives as `peer -> local`. normalize it
        // to `local -> peer`.
        let sock = SocketV4 {
            src: SocketAddrV4 {
                addr: local,
                port: local_port,
            },
            dst: SocketAddrV4 {
                addr: peer,
                port: peer_port,
            },
        };

        match connections.entry(sock) {
            Entry::Occupied(_entry) => {}
            Entry::Vacant(entry) => match TCB::passive_open(&iph, &tcph) {
                Ok((maybe_tcb, maybe_seg)) => {
                    if let Some(tcb) = maybe_tcb {
                        entry.insert(tcb);
                    }

                    if let Some(seg) = maybe_seg {
                        let mut bytes = seg.to_bytes();

                        loop {
                            if tx.is_closed() {
                                break;
                            }

                            match tx.try_send(bytes) {
                                Ok(()) => break,
                                Err(err) => {
                                    bytes = err.into_inner();
                                    rio::task::yield_now().await;
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    eprintln!("[tcp-tun]: failed to process incoming TCP segment: {err}");
                }
            },
        }
    } else {
        eprintln!("[tcp-tun]: ignoring TCP segment for port {local_port}");
    }
}

#[rio::main]
async fn main() -> Result<()> {
    let mut nic = tun::TUN::without_packet_info()?;
    nic.set_non_blocking()?;

    let mut connections: HashMap<SocketV4, TCB> = HashMap::default();

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    let mut buf = [0u8; tun::MTU_SIZE];

    loop {
        let read_fut = nic.read(&mut buf).fuse();
        let rx_fut = rx.next().fuse();

        futures::pin_mut!(read_fut);
        futures::pin_mut!(rx_fut);

        futures::select! {
            read_res = read_fut => {
                let n = read_res?;

                match Ipv4Header::try_from(&buf[..n]) {
                    Ok(iph) if iph.protocol() == Protocol::TCP => {
                        if !iph.is_valid_checksum() {
                            eprintln!("[tcp-tun]: invalid IPv4 header checksum");
                            continue;
                        }

                        match TcpHeader::try_from(&buf[iph.header_len()..n]) {
                            Ok(tcph) if iph.header_len() + tcph.header_len() <= n => {
                                let payload = &buf[iph.header_len() + tcph.header_len()..n];

                                if !tcph.is_valid_checksum(&iph, payload) {
                                    eprintln!("[tcp-tun]: invalid TCP checksum");
                                    continue;
                                }

                                demux_segment(iph, tcph, payload, &mut connections, tx.clone()).await;
                            }
                            Ok(_) => {
                                eprintln!("[tcp-tun]: TCP segment truncated or malformed");
                            }
                            Err(err) => {
                                eprintln!("[tcp-tun]: invalid TCP segment received: {err}");
                            }
                        }
                    }
                    Ok(p) => {
                        eprintln!("[tcp-tun]: ignoring non-TCP packet ({:?})", p.protocol());
                    }
                    Err(err) => {
                        eprintln!("[tcp-tun]: invalid IPv4 packet received: {err}");
                    }
                }
            }
            maybe_bytes = rx_fut => {
                if let Some(bytes) = maybe_bytes {
                    let _ = nic.write(&bytes).await?;
                }
            }
        }
    }
}
