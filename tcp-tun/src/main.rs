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
use std::time::Duration;

use futures::channel::mpsc;
use futures::{FutureExt, StreamExt, select};
use rio::io::{AsyncReadExt, AsyncWriteExt};
use rio::{task, time};
use tcp::protocol::{ConnectionState, TCB};
use tcp::wire::{Ipv4Header, Protocol, TcpHeader, TcpSegment};
use tcp::{Result, SocketAddrV4, SocketV4};

const SERVER_PORT: u16 = 80;

#[derive(Debug)]
enum Message {
    Payload(Vec<u8>),
    Closed(SocketV4),
}

/// Sends the given `Message` to the `mpsc::Sender` while handling backpressure.
///
/// Backpressure is a flow-control pattern where downstream components signal
/// upstream ones to slow down or pause transmission when they are overwhelmed.
async fn send_with_backpressure(tx: &mut mpsc::Sender<Message>, mut message: Message) {
    loop {
        match tx.try_send(message) {
            Err(e) if e.is_full() => {
                message = e.into_inner();
                task::yield_now().await;
            }
            _ => break,
        }
    }
}

async fn handle_connection(
    mut tcb: TCB,
    mut rx_in: mpsc::Receiver<TcpSegment>,
    mut tx_out: mpsc::Sender<Message>,
) -> Result<()> {
    let mut duration = Duration::from_millis(1);
    let mut buf = [0u8; tun::MTU_SIZE];

    loop {
        // TODO: Test retransmission using `hping3`.
        let mut sleep_fut = time::sleep(duration).fuse();

        select! {
            maybe_in_segment = rx_in.next().fuse() => {
                if let Some(in_segment) = maybe_in_segment {
                    let out_segment =
                        tcb.process_segment(in_segment.iph(), in_segment.tcph(), in_segment.payload())?;

                    match tcb.state() {
                        ConnectionState::ESTABLISHED => {
                            if let Some(seg) = out_segment {
                                send_with_backpressure(&mut tx_out, Message::Payload(seg.to_bytes())).await;
                            }

                            let n = tcb.recv(&mut buf)?;
                            if n > 0 {
                                if let Some(segments) = tcb.send(&buf[..n])?.0 {
                                    for seg in segments {
                                        send_with_backpressure(&mut tx_out, Message::Payload(seg.to_bytes())).await;
                                    }
                                }
                            }
                        }
                        ConnectionState::CLOSE_WAIT => {
                            if let Some(seg) = tcb.close()? {
                                send_with_backpressure(&mut tx_out, Message::Payload(seg.to_bytes())).await;
                            }
                        }
                        ConnectionState::CLOSED => {
                            if let Some(seg) = out_segment {
                                send_with_backpressure(&mut tx_out, Message::Payload(seg.to_bytes())).await;
                            }

                            send_with_backpressure(&mut tx_out, Message::Closed(tcb.sock())).await;

                            break;
                        }
                        _ => {}
                    }
                }
            }
            () = sleep_fut => {
                if let Some((next_timer, segments)) = tcb.process_retransmissions() {
                    for seg in segments {
                        send_with_backpressure(&mut tx_out, Message::Payload(seg.to_bytes())).await;
                    }

                    duration = next_timer;
                }
            }
        }
    }

    Ok(())
}

#[rio::main]
async fn main() -> Result<()> {
    let mut nic = tun::TUN::without_packet_info()?;
    nic.set_non_blocking()?;

    let mut connections = HashMap::new();

    let (mut tx_out, mut rx_out) = mpsc::channel::<Message>(128);
    let mut buf = [0u8; tun::MTU_SIZE];

    loop {
        select! {
            maybe_read = nic.read(&mut buf).fuse() => {
                let n = maybe_read?;
                if n == 0 {
                    break;
                }

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

                                let peer = iph.src_addr();
                                let peer_port = tcph.src_port();
                                let local = iph.dst_addr();
                                let local_port = tcph.dst_port();

                                if local_port == SERVER_PORT {
                                    // Normalize segment to `local -> peer`.
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
                                        Entry::Occupied(mut entry) => {
                                            let tx_in: &mut mpsc::Sender<TcpSegment> = entry.get_mut();
                                            let mut segment = TcpSegment::new(iph, tcph, payload);

                                            loop {
                                                match tx_in.try_send(segment) {
                                                    Err(e) if e.is_full() => {
                                                        segment = e.into_inner();
                                                        task::yield_now().await;
                                                    }
                                                    _ => break,
                                                }
                                            }
                                        }
                                        Entry::Vacant(entry) => match TCB::passive_open(&iph, &tcph) {
                                            Ok((maybe_tcb, maybe_seg)) => {
                                                let (tx_in, rx_in) = mpsc::channel::<TcpSegment>(8);

                                                if let Some(tcb) = maybe_tcb {
                                                    entry.insert(tx_in);

                                                    if let Some(seg) = maybe_seg {
                                                        send_with_backpressure(&mut tx_out, Message::Payload(seg.to_bytes())).await;
                                                    }

                                                    rio::spawn(handle_connection(tcb, rx_in, tx_out.clone()));
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!("[tcp-tun]: failed to process incoming TCP segment: {err}");
                                            }
                                        },
                                    }
                                } else {
                                    eprintln!("[tcp-tun]: ignoring TCP segment for port: {local_port}");
                                }
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
            maybe_message = rx_out.next().fuse() => {
                if let Some(message) = maybe_message {
                    match message {
                        Message::Payload(bytes) => {
                            let _ = nic.write(&bytes).await?;
                        }
                        Message::Closed(sock) => {
                            eprintln!("[tcp-tun]: [{sock}]: client disconnected");
                            connections.remove(&sock);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
