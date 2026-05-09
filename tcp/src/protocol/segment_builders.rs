use crate::protocol::TCB;
use crate::wire::{Ipv4Header, Protocol, TcpHeader, TcpSegment};
use crate::{Result, SocketV4};

/// Typical MSS for IPv4 over Ethernet (1500 MTU − 40 bytes of IP/TCP headers).
const DEFAULT_SND_TCP_MSS: u16 = 1460;

/// We always set DF=1 and do not fragment, so the ID field is unused for
/// reassembly and can be constant.
const DEFAULT_ID: u16 = 0;

/// Typical IPv4 TTL used by most hosts.
const DEFAULT_TTL: u8 = 64;

/// Creates a TCP `SYN` segment to initiate a connection request.
///
/// # Errors
///
/// Returns an error when either the TCP `MSS` option could not be set or the
/// IPv4 header could not be created.
#[inline]
pub fn syn(tcb: &TCB) -> Result<TcpSegment> {
    let mut seg = build_segment(tcb, tcb.snd.iss, &[], Some(DEFAULT_SND_TCP_MSS))?;

    seg.tcph.set_syn();

    seg.iph.set_header_checksum();
    seg.tcph.set_checksum(&seg.iph, &[]);

    Ok(seg)
}

/// Creates a TCP `SYN+ACK` segment in response to a peer's connection request.
///
/// # Errors
///
/// Returns an error when either the TCP `MSS` option could not be set or the
/// IPv4 header could not be created.
#[inline]
pub fn syn_ack(tcb: &TCB) -> Result<TcpSegment> {
    let mut seg = build_segment(tcb, tcb.snd.iss, &[], Some(DEFAULT_SND_TCP_MSS))?;

    // Acknowledge the peer's `SYN`.
    seg.tcph.set_ack_number(tcb.rcv.nxt);

    seg.tcph.set_syn();
    seg.tcph.set_ack();

    seg.iph.set_header_checksum();
    seg.tcph.set_checksum(&seg.iph, &[]);

    Ok(seg)
}

/// Creates a TCP `ACK` segment in response to a peer's segment or when
/// transmitting data.
///
/// # Errors
///
/// Returns an error if the IPv4 header could not be created.
#[inline]
pub fn ack(tcb: &TCB, payload: &[u8]) -> Result<TcpSegment> {
    let mut seg = build_segment(tcb, tcb.snd.nxt, payload, None)?;

    // Acknowledge the peer's segment.
    seg.tcph.set_ack_number(tcb.rcv.nxt);

    seg.tcph.set_ack();
    if !payload.is_empty() {
        seg.tcph.set_psh();
    }

    seg.iph.set_header_checksum();
    seg.tcph.set_checksum(&seg.iph, payload);

    Ok(seg)
}

/// Creates a TCP `FIN+ACK` segment in response to a graceful connection
/// termination.
///
/// # Errors
///
/// Returns an error if the IPv4 header could not be created.
#[inline]
pub fn fin_ack(tcb: &TCB, payload: &[u8]) -> Result<TcpSegment> {
    let mut seg = build_segment(tcb, tcb.snd.nxt, payload, None)?;

    // Acknowledge the peer's segment.
    seg.tcph.set_ack_number(tcb.rcv.nxt);

    seg.tcph.set_fin();
    seg.tcph.set_ack();

    seg.iph.set_header_checksum();
    seg.tcph.set_checksum(&seg.iph, payload);

    Ok(seg)
}

/// Creates a TCP `RST` segment to terminate the connection.
///
/// # Errors
///
/// Returns an error if the IPv4 header could not be created.
#[inline]
pub fn rst(tcb: &TCB, seq: u32, ack: u32) -> Result<TcpSegment> {
    let mut tcph = TcpHeader::new(tcb.sock.src.port, tcb.sock.dst.port, seq, 0);

    tcph.set_rst();

    if ack != 0 {
        // Acknowledge the peer's segment.
        tcph.set_ack_number(ack);
        tcph.set_ack();
    }

    let mut iph = Ipv4Header::new(
        DEFAULT_ID,
        tcb.sock.src.addr,
        tcb.sock.dst.addr,
        tcph.header_len() as u16,
        DEFAULT_TTL,
        Protocol::TCP,
    )?;

    iph.set_header_checksum();
    tcph.set_checksum(&iph, &[]);

    Ok(TcpSegment::new(iph, tcph, &[]))
}

/// Creates a bare TCP `RST` segment for which a connection does not exist.
///
/// # Errors
///
/// Returns an error if the IPv4 header could not be created.
#[inline]
pub fn rst_bare(sock: SocketV4, seq: u32, ack: u32) -> Result<TcpSegment> {
    let mut tcph = TcpHeader::new(sock.src.port, sock.dst.port, seq, 0);

    tcph.set_rst();

    if ack != 0 {
        // Acknowledge the peer's segment.
        tcph.set_ack_number(ack);
        tcph.set_ack();
    }

    let mut iph = Ipv4Header::new(
        DEFAULT_ID,
        sock.src.addr,
        sock.dst.addr,
        tcph.header_len() as u16,
        DEFAULT_TTL,
        Protocol::TCP,
    )?;

    iph.set_header_checksum();
    tcph.set_checksum(&iph, &[]);

    Ok(TcpSegment::new(iph, tcph, &[]))
}

fn build_segment(tcb: &TCB, seq: u32, payload: &[u8], mss: Option<u16>) -> Result<TcpSegment> {
    let mut tcph = TcpHeader::new(tcb.sock.src.port, tcb.sock.dst.port, seq, tcb.rcv.wnd);

    if let Some(mss) = mss {
        tcph.set_option_mss(mss)?;
    }

    let iph = Ipv4Header::new(
        DEFAULT_ID,
        tcb.sock.src.addr,
        tcb.sock.dst.addr,
        (tcph.header_len() + payload.len()) as u16,
        DEFAULT_TTL,
        Protocol::TCP,
    )?;

    Ok(TcpSegment::new(iph, tcph, payload))
}
