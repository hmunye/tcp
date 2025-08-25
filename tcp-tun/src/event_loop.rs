//! Event loop to monitor for raw packet I/O, manage timers for connection
//! termination and retransmission, and handle user requests synchronously.

use tcp_core::protocol::fsm::{ConnectionState, MAX_RETRANSMIT_LIMIT, MSL, RTO, TCB};
use tcp_core::protocol::headers::{Ipv4Header, Protocol, TcpHeader};
use tcp_core::protocol::{Socket, SocketAddr};
use tcp_core::{Error, Result, debug, error, warn};

use std::collections::{HashMap, VecDeque, hash_map::Entry};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use std::{io, ptr};

use crate::errno;
use crate::net::interface::{Shutdown, State, TcpStream, UserReq};
use crate::tun::{MTU_SIZE, Tun};

type PendingClose = mpsc::Sender<()>;
type PendingSend = (mpsc::Sender<usize>, Vec<u8>);
type PendingRead = (mpsc::Sender<(Vec<u8>, usize)>, usize);
type PendingAccept = mpsc::Sender<TcpStream>;

/// Total number of events returned each tick (event loop cycle).
const EPOLL_MAX_EVENTS: i32 = 3;

/// The number of milliseconds that `epoll_wait()` will block for. -1 will
/// block indefinitely until an event occurs.
const EPOLL_TIMEOUT_MS: i32 = -1;

/// Runs an event loop to establish and maintain a TCP connection with a peer
/// as well as handle user requests.
pub fn connect_loop(state: Arc<State>, socket: Socket) -> Result<()> {
    let nic = Tun::without_packet_info()?;
    nic.set_non_blocking()?;

    let mut connection: (Option<Socket>, Option<TCB>) = Default::default();

    // Stores events for ready file descriptors.
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; EPOLL_MAX_EVENTS as usize];
    // Number of ready file descriptors.
    let mut rdfs;

    let tun_fd = nic.fd();
    let timer_fd = init_timer_fd()?;
    let epoll_fd = match init_epoll_fd([tun_fd, timer_fd, state.handle]) {
        Ok(fd) => fd,
        Err(err) => {
            unsafe {
                let _ = libc::close(timer_fd);
            }
            return Err(err);
        }
    };

    // Initiate a TCP connection.
    {
        let (conn, syn) = TCB::open_conn_active(socket)?;
        nic.send(&syn.to_be_bytes()?[..])?;

        connection.0 = Some(socket);
        connection.1 = Some(conn);
    }

    let mut connection: (Socket, TCB) = (connection.0.unwrap(), connection.1.unwrap());

    let mut pending_close: Option<PendingClose> = None;
    let mut pending_sends: VecDeque<PendingSend> = Default::default();
    let mut pending_reads: VecDeque<PendingRead> = Default::default();

    let mut buf = [0u8; MTU_SIZE];

    'event_loop: loop {
        unsafe {
            rdfs = libc::epoll_wait(
                epoll_fd,
                &mut events as *mut libc::epoll_event,
                EPOLL_MAX_EVENTS,
                EPOLL_TIMEOUT_MS,
            );
        }

        if rdfs == -1 {
            return Err(errno!("failed to wait on epoll"));
        }

        for event in events.iter().take(rdfs as usize) {
            if event.u64 == state.handle as u64 {
                // Clear the `event_fd` counter.
                let mut buf = [0u8; 8];
                let _ = unsafe {
                    libc::read(state.handle, &raw mut buf as *mut libc::c_void, buf.len())
                };

                while let Some(req) = state.user_req_queue.lock().unwrap().pop_front() {
                    match req {
                        UserReq::Send(sock, data, tx) => {
                            if sock == connection.0 {
                                let conn = &mut connection.1;

                                if let ConnectionState::ESTABLISHED | ConnectionState::CLOSE_WAIT =
                                    conn.state()
                                {
                                    let (mut segments, nbytes) = conn.send(&data)?;

                                    while let Some(segment) = segments.pop_front() {
                                        debug!(
                                            "[{sock}] ({:?}) sending {nbytes} bytes to peer",
                                            conn.state()
                                        );
                                        nic.send(&segment.to_be_bytes()?[..])?;
                                    }

                                    let _ = tx.send(nbytes);
                                } else {
                                    pending_sends.push_back((tx, data));
                                }
                            }
                        }
                        UserReq::Read(sock, len, tx) => {
                            if sock == connection.0 {
                                let conn = &mut connection.1;

                                if matches!(
                                    conn.state(),
                                    ConnectionState::ESTABLISHED
                                        | ConnectionState::FIN_WAIT_1
                                        | ConnectionState::FIN_WAIT_2
                                        | ConnectionState::CLOSE_WAIT,
                                ) && conn.recv_buf_len() > 0
                                {
                                    let mut buf = vec![0u8; len];
                                    match conn.recv(&mut buf[..]) {
                                        Ok(nbytes) => {
                                            debug!(
                                                "[{sock}] ({:?}) read {nbytes} from peer",
                                                conn.state()
                                            );
                                            let _ = tx.send((buf, nbytes));
                                        }
                                        Err(err) => {
                                            error!(
                                                "[{sock}] ({:?}) failed to read from socket: {err}",
                                                conn.state()
                                            );
                                            let _ = tx.send((buf, 0));
                                        }
                                    }
                                } else {
                                    pending_reads.push_back((tx, len));
                                }
                            }
                        }
                        UserReq::Close(sock, shutdown, tx) => {
                            if sock == connection.0 {
                                let conn = &mut connection.1;

                                match shutdown {
                                    Shutdown::Close => {
                                        if let Some(seg) = conn.close()? {
                                            nic.send(&seg.to_be_bytes()?[..])?;
                                        }
                                    }
                                    Shutdown::Abort => {
                                        if let Some(seg) = conn.abort()? {
                                            nic.send(&seg.to_be_bytes()?[..])?;
                                        }
                                    }
                                }

                                pending_close = Some(tx);
                            }
                        }
                        UserReq::Accept(_) => {
                            error!(
                                "[{}] ({:?}) invalid user request for TcpStream: UserReq::Accept(...)",
                                connection.0,
                                connection.1.state(),
                            );
                        }
                    }
                }
            }

            if event.u64 == timer_fd as u64 {
                // Read from the timer to clear the expiration count.
                let mut buf = [0u8; 8];
                let _ =
                    unsafe { libc::read(timer_fd, &raw mut buf as *mut libc::c_void, buf.len()) };

                // Keep track of the nearest retransmission segment timer
                // to expire.
                let mut nearest_timer = Duration::MAX;

                let sock = &connection.0;
                let conn = &mut connection.1;

                match conn.state() {
                    ConnectionState::TIME_WAIT => {
                        if conn.time_wait().elapsed() >= Duration::from_secs(MSL * 2) {
                            warn!("[{sock}] (TIME_WAIT) timer expired -- closing connection",);
                            continue 'event_loop;
                        }
                    }
                    state => {
                        let (timer, mut segments) = conn.on_tick();

                        while let Some(seg) = segments.pop_front() {
                            nic.send(&seg.to_be_bytes()?[..])?;
                        }

                        if state == ConnectionState::CLOSED {
                            warn!("[{sock}] (CLOSED) connection closed");
                            break 'event_loop;
                        } else {
                            nearest_timer = timer;
                        }
                    }
                }

                let mut rearm_time = nearest_timer.as_secs();

                // Compared to the largest effective RTO value allowed.
                //
                // `rearm_time` can never be 0, since that will disable the
                // `timerfd`.
                if !(1..=RTO * (1 << MAX_RETRANSMIT_LIMIT)).contains(&rearm_time) {
                    // Default to rearming timer expiring to RTO.
                    rearm_time = RTO;
                }

                // Ensure the timer is re-armed.
                let time_spec = libc::itimerspec {
                    // The interval for periodic expiration.
                    it_interval: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    // The initial expiration time.
                    it_value: libc::timespec {
                        // Should expire when the next retransmission
                        // timeout is expected.
                        tv_sec: rearm_time as i64,
                        tv_nsec: 0,
                    },
                };

                if unsafe {
                    libc::timerfd_settime(timer_fd, 0, &raw const time_spec, ptr::null_mut())
                } == -1
                {
                    return Err(errno!("failed to rearm timer"));
                }
            }

            if event.u64 == tun_fd as u64 {
                let nbytes = match nic.recv(&mut buf[..]) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!("failed to read from TUN interface: {err}");
                        break;
                    }
                };

                match Ipv4Header::try_from(&buf[..nbytes]) {
                    Ok(iph) if iph.protocol() == Protocol::TCP => {
                        if !iph.is_valid_checksum() {
                            warn!("invalid IP packet received: invalid IPv4 header checksum");
                            break;
                        }

                        let src = iph.src();
                        let dst = iph.dst();

                        match TcpHeader::try_from(&buf[iph.header_len()..nbytes]) {
                            Ok(tcph) => {
                                let src_port = tcph.src_port();
                                let dst_port = tcph.dst_port();
                                let payload = &buf[iph.header_len() + tcph.header_len()..nbytes];

                                if !tcph.is_valid_checksum(&iph, payload) {
                                    warn!("invalid IP packet received: invalid TCP checksum");
                                    break;
                                }

                                // Packet's source and destination are from
                                // the peer's perspective.
                                let incoming_sock = Socket {
                                    src: SocketAddr {
                                        addr: dst,
                                        port: dst_port,
                                    },
                                    dst: SocketAddr {
                                        addr: src,
                                        port: src_port,
                                    },
                                };

                                let sock = &connection.0;
                                let conn = &mut connection.1;

                                if *sock == incoming_sock {
                                    match conn.on_segment(&iph, &tcph, payload) {
                                        Ok(segment) => {
                                            if let Some(seg) = segment {
                                                nic.send(&seg.to_be_bytes()?[..])?;
                                            }

                                            // Handle pending send requests.
                                            if let ConnectionState::ESTABLISHED
                                            | ConnectionState::CLOSE_WAIT = conn.state()
                                            {
                                                while let Some((tx, data)) =
                                                    pending_sends.pop_front()
                                                {
                                                    let (mut segments, nbytes) =
                                                        conn.send(&data)?;

                                                    while let Some(segment) = segments.pop_front() {
                                                        debug!(
                                                            "[{sock}] ({:?}) sending {nbytes} bytes to peer",
                                                            conn.state()
                                                        );
                                                        nic.send(&segment.to_be_bytes()?[..])?;
                                                    }

                                                    let _ = tx.send(nbytes);
                                                }
                                            }

                                            // Handle pending read requests.
                                            if matches!(
                                                conn.state(),
                                                ConnectionState::ESTABLISHED
                                                    | ConnectionState::FIN_WAIT_1
                                                    | ConnectionState::FIN_WAIT_2
                                                    | ConnectionState::CLOSE_WAIT,
                                            ) && conn.recv_buf_len() > 0
                                            {
                                                while let Some((tx, len)) =
                                                    pending_reads.pop_front()
                                                {
                                                    if conn.recv_buf_len() == 0 {
                                                        pending_reads.push_front((tx, len));
                                                        break;
                                                    }

                                                    let mut buf = vec![0u8; len];
                                                    match conn.recv(&mut buf[..]) {
                                                        Ok(nbytes) => {
                                                            debug!(
                                                                "[{sock}] ({:?}) read {nbytes} from peer",
                                                                conn.state()
                                                            );
                                                            let _ = tx.send((buf, nbytes));
                                                        }
                                                        Err(err) => {
                                                            error!(
                                                                "[{sock}] ({:?}) failed to read from socket: {err}",
                                                                conn.state()
                                                            );
                                                            let _ = tx.send((buf, 0));
                                                        }
                                                    }
                                                }
                                            }

                                            // Handle pending close request.
                                            if let ConnectionState::TIME_WAIT
                                            | ConnectionState::CLOSED = conn.state()
                                                && let Some(ref tx) = pending_close
                                            {
                                                let _ = tx.send(());
                                            }

                                            if let ConnectionState::CLOSED = conn.state() {
                                                while let Some((tx, _)) = pending_reads.pop_front()
                                                {
                                                    let _ = tx.send((Default::default(), 0));
                                                }

                                                while let Some((tx, _)) = pending_sends.pop_front()
                                                {
                                                    let _ = tx.send(0);
                                                }

                                                debug!("[{sock}] connection closed");
                                                break 'event_loop;
                                            }
                                        }
                                        Err(Error::Io(err)) => match err.kind() {
                                            io::ErrorKind::ConnectionReset
                                            | io::ErrorKind::ConnectionRefused => {
                                                debug!("[{sock}] connection closed");
                                                break 'event_loop;
                                            }
                                            err => {
                                                warn!("{err}");
                                            }
                                        },
                                        Err(err) => {
                                            error!("unexpected error occurred: {err}");
                                        }
                                    }
                                } else {
                                    warn!(
                                        "ignoring TCP segment with mismatched socket address: {incoming_sock}"
                                    );
                                    continue;
                                }
                            }
                            Err(err) => {
                                error!("invalid TCP segment received: {err}");
                            }
                        }
                    }
                    Ok(p) => {
                        warn!("ignoring non-TCP ({:?}) packet", p.protocol());
                    }
                    Err(err) => {
                        error!("invalid IP packet received: {err}");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Runs an event loop to accept and handle incoming TCP connections and user
/// requests.
pub fn listen_loop(state: Arc<State>, listen_addr: SocketAddr) -> Result<()> {
    let nic = Tun::without_packet_info()?;
    nic.set_non_blocking()?;

    let mut connections: HashMap<Socket, TCB> = Default::default();

    // Stores events for ready file descriptors.
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; EPOLL_MAX_EVENTS as usize];
    // Number of ready file descriptors.
    let mut rdfs;

    let tun_fd = nic.fd();
    let timer_fd = init_timer_fd()?;
    let epoll_fd = match init_epoll_fd([tun_fd, timer_fd, state.handle]) {
        Ok(fd) => fd,
        Err(err) => {
            unsafe {
                let _ = libc::close(timer_fd);
            }
            return Err(err);
        }
    };

    let mut pending_closes: HashMap<Socket, PendingClose> = Default::default();
    let mut pending_sends: HashMap<Socket, VecDeque<PendingSend>> = Default::default();
    let mut pending_reads: HashMap<Socket, VecDeque<PendingRead>> = Default::default();
    let mut pending_accepts: VecDeque<PendingAccept> = Default::default();

    let mut backlog: VecDeque<Socket> = Default::default();

    let mut buf = [0u8; MTU_SIZE];

    loop {
        unsafe {
            rdfs = libc::epoll_wait(
                epoll_fd,
                &mut events as *mut libc::epoll_event,
                EPOLL_MAX_EVENTS,
                EPOLL_TIMEOUT_MS,
            );
        }

        if rdfs == -1 {
            return Err(errno!("failed to wait on epoll"));
        }

        for event in events.iter().take(rdfs as usize) {
            if event.u64 == state.handle as u64 {
                // Clear the `event_fd` counter.
                let mut buf = [0u8; 8];
                let _ = unsafe {
                    libc::read(state.handle, &raw mut buf as *mut libc::c_void, buf.len())
                };

                while let Some(req) = state.user_req_queue.lock().unwrap().pop_front() {
                    match req {
                        UserReq::Send(sock, data, tx) => {
                            if let Some(conn) = connections.get_mut(&sock) {
                                if let ConnectionState::ESTABLISHED | ConnectionState::CLOSE_WAIT =
                                    conn.state()
                                {
                                    let (mut segments, nbytes) = conn.send(&data)?;

                                    while let Some(segment) = segments.pop_front() {
                                        debug!(
                                            "[{sock}] ({:?}) sending {nbytes} bytes to peer",
                                            conn.state()
                                        );
                                        nic.send(&segment.to_be_bytes()?[..])?;
                                    }

                                    let _ = tx.send(nbytes);
                                } else {
                                    pending_sends.entry(sock).or_default().push_back((tx, data));
                                }
                            }
                        }
                        UserReq::Read(sock, len, tx) => {
                            if let Some(conn) = connections.get_mut(&sock) {
                                if matches!(
                                    conn.state(),
                                    ConnectionState::ESTABLISHED
                                        | ConnectionState::FIN_WAIT_1
                                        | ConnectionState::FIN_WAIT_2
                                        | ConnectionState::CLOSE_WAIT,
                                ) && conn.recv_buf_len() > 0
                                {
                                    let mut buf = vec![0u8; len];
                                    match conn.recv(&mut buf[..]) {
                                        Ok(nbytes) => {
                                            debug!(
                                                "[{sock}] ({:?}) read {nbytes} from peer",
                                                conn.state()
                                            );
                                            let _ = tx.send((buf, nbytes));
                                        }
                                        Err(err) => {
                                            error!(
                                                "[{sock}] ({:?}) failed to read from socket: {err}",
                                                conn.state()
                                            );
                                            let _ = tx.send((buf, 0));
                                        }
                                    }
                                } else {
                                    pending_reads.entry(sock).or_default().push_back((tx, len));
                                }
                            }
                        }
                        UserReq::Close(sock, shutdown, tx) => {
                            if let Some(conn) = connections.get_mut(&sock) {
                                match shutdown {
                                    Shutdown::Close => {
                                        if let Some(seg) = conn.close()? {
                                            nic.send(&seg.to_be_bytes()?[..])?;
                                        }
                                    }
                                    Shutdown::Abort => {
                                        if let Some(seg) = conn.abort()? {
                                            nic.send(&seg.to_be_bytes()?[..])?;
                                        }
                                    }
                                }

                                pending_closes.entry(sock).or_insert(tx);
                            }
                        }
                        UserReq::Accept(tx) => {
                            if let Some(sock) = backlog.pop_front() {
                                let stream = TcpStream::new(
                                    state.clone(),
                                    mpsc::channel(),
                                    mpsc::channel(),
                                    sock,
                                );

                                let _ = tx.send(stream);
                            } else {
                                pending_accepts.push_back(tx);
                            }
                        }
                    }
                }
            }

            if event.u64 == timer_fd as u64 {
                // Read from the timer to clear the expiration count.
                let mut buf = [0u8; 8];
                let _ =
                    unsafe { libc::read(timer_fd, &raw mut buf as *mut libc::c_void, buf.len()) };

                // Keep track of the nearest retransmission segment timer
                // to expire.
                let mut nearest_timer = Duration::MAX;

                // Remove connections that are ready to be closed or
                // aborted.
                connections.retain(|socket, conn| match conn.state() {
                    ConnectionState::TIME_WAIT => {
                        if conn.time_wait().elapsed() >= Duration::from_secs(MSL * 2) {
                            warn!(
                                "[{}] (TIME_WAIT) timer expired -- removing connection",
                                socket
                            );
                            false
                        } else {
                            true
                        }
                    }
                    state => {
                        let (timer, mut segments) = conn.on_tick();

                        while let Some(seg) = segments.pop_front() {
                            if let Ok(bytes) = seg.to_be_bytes() {
                                nic.send(&bytes[..]).unwrap_or_else(|err| {
                                    error!("[{socket}] ({state:?}) {err}");
                                    0
                                });
                            }
                        }

                        if state == ConnectionState::CLOSED {
                            warn!("[{}] (CLOSED) removing connection", socket);
                            false
                        } else {
                            if timer < nearest_timer {
                                nearest_timer = timer;
                            }
                            true
                        }
                    }
                });

                let mut rearm_time = nearest_timer.as_secs();

                // Compared to the largest effective RTO value allowed.
                //
                // `rearm_time` can never be 0, since that will disable the
                // `timerfd`.
                if !(1..=RTO * (1 << MAX_RETRANSMIT_LIMIT)).contains(&rearm_time) {
                    // Default to rearming timer expiring to RTO.
                    rearm_time = RTO;
                }

                // Ensure the timer is re-armed.
                let time_spec = libc::itimerspec {
                    // The interval for periodic expiration.
                    it_interval: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    // The initial expiration time.
                    it_value: libc::timespec {
                        // Should expire when the next retransmission
                        // timeout is expected.
                        tv_sec: rearm_time as i64,
                        tv_nsec: 0,
                    },
                };

                if unsafe {
                    libc::timerfd_settime(timer_fd, 0, &raw const time_spec, ptr::null_mut())
                } == -1
                {
                    return Err(errno!("failed to rearm timer"));
                }
            }

            if event.u64 == tun_fd as u64 {
                let nbytes = match nic.recv(&mut buf[..]) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!("failed to read from TUN interface: {err}");
                        break;
                    }
                };

                match Ipv4Header::try_from(&buf[..nbytes]) {
                    Ok(iph) if iph.protocol() == Protocol::TCP => {
                        if !iph.is_valid_checksum() {
                            warn!("invalid IP packet received: invalid IPv4 header checksum");
                            break;
                        }

                        let src = iph.src();
                        let dst = iph.dst();

                        match TcpHeader::try_from(&buf[iph.header_len()..nbytes]) {
                            Ok(tcph) => {
                                let src_port = tcph.src_port();
                                let dst_port = tcph.dst_port();
                                let payload = &buf[iph.header_len() + tcph.header_len()..nbytes];

                                if !tcph.is_valid_checksum(&iph, payload) {
                                    warn!("invalid IP packet received: invalid TCP checksum");
                                    break;
                                }

                                // Packet's source and destination are from
                                // the peer's perspective.
                                let incoming_sock = Socket {
                                    src: SocketAddr {
                                        addr: dst,
                                        port: dst_port,
                                    },
                                    dst: SocketAddr {
                                        addr: src,
                                        port: src_port,
                                    },
                                };

                                if listen_addr.port == dst_port {
                                    match connections.entry(incoming_sock) {
                                        Entry::Vacant(entry) => {
                                            match TCB::open_conn_passive(&iph, &tcph) {
                                                Ok((tcb, segment)) => match (tcb, segment) {
                                                    (Some(conn), Some(seg)) => {
                                                        entry.insert(conn);
                                                        nic.send(&seg.to_be_bytes()?[..])?;
                                                    }
                                                    (None, Some(seg)) => {
                                                        nic.send(&seg.to_be_bytes()?[..])?;
                                                    }
                                                    _ => {}
                                                },
                                                Err(err) => {
                                                    error!(
                                                        "failed to process incoming TCP segment: {err}"
                                                    );
                                                }
                                            }
                                        }
                                        Entry::Occupied(mut conn) => {
                                            let maybe_reply =
                                                conn.get_mut().on_segment(&iph, &tcph, payload);

                                            let conn_state = conn.get().state();

                                            match maybe_reply {
                                                Ok(segment) => {
                                                    if let Some(seg) = segment {
                                                        nic.send(&seg.to_be_bytes()?[..])?;
                                                    }

                                                    // Handle pending send requests.
                                                    if let ConnectionState::ESTABLISHED
                                                    | ConnectionState::CLOSE_WAIT = conn_state
                                                        && let Some(queue) =
                                                            pending_sends.get_mut(&incoming_sock)
                                                    {
                                                        while let Some((tx, data)) =
                                                            queue.pop_front()
                                                        {
                                                            let (mut segments, nbytes) =
                                                                conn.get_mut().send(&data)?;

                                                            while let Some(segment) =
                                                                segments.pop_front()
                                                            {
                                                                debug!(
                                                                    "[{incoming_sock}] ({:?}) sending {nbytes} bytes to peer",
                                                                    conn_state
                                                                );
                                                                nic.send(
                                                                    &segment.to_be_bytes()?[..],
                                                                )?;
                                                            }

                                                            let _ = tx.send(nbytes);
                                                        }
                                                    }

                                                    // Handle pending read requests.
                                                    if matches!(
                                                        conn_state,
                                                        ConnectionState::ESTABLISHED
                                                            | ConnectionState::FIN_WAIT_1
                                                            | ConnectionState::FIN_WAIT_2
                                                            | ConnectionState::CLOSE_WAIT,
                                                    ) && conn.get().recv_buf_len() > 0
                                                        && let Some(queue) =
                                                            pending_reads.get_mut(&incoming_sock)
                                                    {
                                                        while let Some((tx, len)) =
                                                            queue.pop_front()
                                                        {
                                                            if conn.get().recv_buf_len() == 0 {
                                                                queue.push_front((tx, len));
                                                                break;
                                                            }

                                                            let mut buf = vec![0u8; len];
                                                            match conn.get_mut().recv(&mut buf[..])
                                                            {
                                                                Ok(nbytes) => {
                                                                    debug!(
                                                                        "[{incoming_sock}] ({:?}) read {nbytes} from peer",
                                                                        conn_state
                                                                    );
                                                                    let _ = tx.send((buf, nbytes));
                                                                }
                                                                Err(err) => {
                                                                    error!(
                                                                        "[{incoming_sock}] ({:?}) failed to read from socket: {err}",
                                                                        conn_state
                                                                    );
                                                                    let _ = tx.send((buf, 0));
                                                                }
                                                            }
                                                        }

                                                        if queue.is_empty() {
                                                            pending_reads.remove(&incoming_sock);
                                                        }
                                                    }

                                                    // Handle pending accept requests.
                                                    if conn_state == ConnectionState::ESTABLISHED {
                                                        if let Some(tx) =
                                                            pending_accepts.pop_front()
                                                        {
                                                            let stream = TcpStream::new(
                                                                state.clone(),
                                                                mpsc::channel(),
                                                                mpsc::channel(),
                                                                incoming_sock,
                                                            );

                                                            let _ = tx.send(stream);
                                                        } else {
                                                            backlog.push_back(incoming_sock);
                                                        }
                                                    }

                                                    // Handle pending close requests.
                                                    if let ConnectionState::TIME_WAIT
                                                    | ConnectionState::CLOSED = conn_state
                                                        && let Some(tx) =
                                                            pending_closes.get_mut(&incoming_sock)
                                                    {
                                                        let _ = tx.send(());
                                                        pending_closes.remove(&incoming_sock);
                                                    }

                                                    if conn_state == ConnectionState::CLOSED {
                                                        if let Some(queue) =
                                                            pending_reads.get_mut(&incoming_sock)
                                                        {
                                                            while let Some((tx, _)) =
                                                                queue.pop_front()
                                                            {
                                                                let _ = tx
                                                                    .send((Default::default(), 0));
                                                            }
                                                        }

                                                        if let Some(queue) =
                                                            pending_sends.get_mut(&incoming_sock)
                                                        {
                                                            while let Some((tx, _)) =
                                                                queue.pop_front()
                                                            {
                                                                let _ = tx.send(0);
                                                            }
                                                        }

                                                        connections.remove(&incoming_sock);

                                                        debug!(
                                                            "[{incoming_sock}] removed connection, active connections remaining: {}",
                                                            connections.len(),
                                                        );
                                                    }
                                                }
                                                Err(Error::Io(err)) => match err.kind() {
                                                    io::ErrorKind::ConnectionReset
                                                    | io::ErrorKind::ConnectionRefused => {
                                                        connections.remove(&incoming_sock);

                                                        debug!(
                                                            "[{incoming_sock}] removed connection, active connections remaining: {}",
                                                            connections.len(),
                                                        );
                                                    }
                                                    err => {
                                                        warn!("{err}");
                                                    }
                                                },
                                                Err(err) => {
                                                    error!("unexpected error occurred: {err}");
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    warn!(
                                        "[{incoming_sock}] ignoring TCP segment with incorrect destination port {dst_port}, listening on port: {}",
                                        listen_addr.port
                                    );
                                    continue;
                                }
                            }
                            Err(err) => {
                                error!("invalid TCP segment received: {err}");
                            }
                        }
                    }
                    Ok(p) => {
                        warn!("ignoring non-TCP ({:?}) packet", p.protocol());
                    }
                    Err(err) => {
                        error!("invalid IP packet received: {err}");
                    }
                }
            }
        }
    }
}

/// Creates a non-blocking `timer_fd` armed with an initial expiration of [RTO].
fn init_timer_fd() -> Result<RawFd> {
    unsafe {
        let timer_fd = libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK);
        if timer_fd == -1 {
            return Err(errno!("failed to create timer_fd"));
        }

        // Ensure the timer is armed before entering the loop.
        let time_spec = libc::itimerspec {
            // The interval for periodic expiration.
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            // The initial expiration time.
            it_value: libc::timespec {
                tv_sec: RTO as i64,
                tv_nsec: 0,
            },
        };

        if libc::timerfd_settime(timer_fd, 0, &raw const time_spec, ptr::null_mut()) == -1 {
            return Err(errno!("failed to initialize timer"));
        }

        Ok(timer_fd.as_raw_fd())
    }
}

/// Creates a non-blocking `epoll_fd` and registers the given file descriptors.
fn init_epoll_fd(fds: [RawFd; 3]) -> Result<RawFd> {
    unsafe {
        let mut ev = libc::epoll_event { events: 0, u64: 0 };

        // `epoll()` is used to efficiently monitor multiple file descriptors
        // for I/O. Instead of blocking on each socket sequentially,
        // this approach (with non-blocking sockets) allows blocking on all
        // simultaneously, processing only the file descriptors that are ready
        // for I/O.
        let epoll_fd = libc::epoll_create1(0);
        if epoll_fd == -1 {
            return Err(errno!("failed to create epoll_fd"));
        }

        for fd in fds {
            ev.events = libc::EPOLLIN as u32;
            ev.u64 = fd as u64;
            // Add the file descriptor to the epoll interest list to be
            // notified on ready events.
            if libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &raw mut ev) == -1 {
                return Err(errno!("failed to add to epoll interest list"));
            }
        }

        Ok(epoll_fd.as_raw_fd())
    }
}
