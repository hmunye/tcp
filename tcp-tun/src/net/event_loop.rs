//! Event loop to manage the TCP, monitor for raw packet I/O through the TUN
//! virtual network device, timers for connection cleanup and retransmission,
//! and signals for graceful shutdown.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use std::{io, mem, ptr};

use crate::errno;
use crate::tun_tap::tun::{MTU_SIZE, Tun};

use tcp_core::protocol::fsm::{
    ConnectionState, MAX_RETRANSMIT_LIMIT, MSL, RTO, Socket, SocketAddr, TCB,
};
use tcp_core::protocol::headers::{Ipv4Header, Protocol, TcpHeader};
use tcp_core::{Error, Result};
use tcp_core::{debug, error, info, warn};

/// Maximum Transmission Unit.
const MTU_SIZE: usize = 1504;

/// Total number of events returned each tick (event loop cycle).
const EPOLL_MAX_EVENTS: i32 = 3;

/// The number of milliseconds that `epoll_wait()` will block for. -1 will
/// block indefinitely until an event occurs.
const EPOLL_TIMEOUT_MS: i32 = -1;

/// Runs an event loop to monitor for and process incoming IP packets from the
/// TUN virtual network device. This function runs continuously until receiving
/// a shutdown signal (e.g., SIGINT, SIGTERM) or encountering an error.
pub fn packet_loop(nic: &mut Tun, connections: &mut HashMap<Socket, TCB>) -> Result<()> {
    // Stores events for ready file descriptors.
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; EPOLL_MAX_EVENTS as usize];
    // Number of ready file descriptors.
    let mut rdfs;

    let tun_fd = nic.fd();
    let signal_fd = init_signal_fd()?;

    let timer_fd = match init_timer_fd() {
        Ok(fd) => fd,
        Err(err) => {
            unsafe {
                let _ = libc::close(signal_fd);
            }
            return Err(err);
        }
    };

    let epoll_fd = match init_epoll_fd([tun_fd, signal_fd, timer_fd]) {
        Ok(fd) => fd,
        Err(err) => {
            unsafe {
                let _ = libc::close(signal_fd);
                let _ = libc::close(timer_fd);
            }
            return Err(err);
        }
    };

    let mut buf = [0u8; MTU_SIZE];

    'event_loop: loop {
        unsafe {
            rdfs = libc::epoll_wait(
                epoll_fd,
                &mut events as *mut libc::epoll_event,
                EPOLL_MAX_EVENTS,
                EPOLL_TIMEOUT_MS,
            );

            if rdfs == -1 {
                return Err(errno!("failed to wait on epoll"));
            }

            for event in events.iter().take(rdfs as usize) {
                // A signal was caught (SIGINT or SIGTERM).
                if event.u64 == signal_fd as u64 {
                    // TODO: Do something on SIGINT or SIGTERM.
                    info!(
                        "signal caught -- shutting down, active connections remaining: {}",
                        connections.len()
                    );

                    break 'event_loop;
                }

                // Timer expired, check active connections.
                if event.u64 == timer_fd as u64 {
                    // Read from the timer to clear the expiration count.
                    let mut buf = [0u8; 8];
                    let _ = libc::read(timer_fd, &raw mut buf as *mut libc::c_void, buf.len());

                    // Keep track of the nearest retransmission segment timer to
                    // expire.
                    let mut nearest_timer = Duration::MAX;

                    // Remove connections that are ready to be closed or aborted.
                    connections.retain(|socket, conn| {
                        match conn.state {
                            ConnectionState::TIME_WAIT => {
                                if conn.time_wait.elapsed() >= Duration::from_secs(MSL * 2) {
                                    warn!(
                                        "[{}] (TIME_WAIT) timer expired -- removing connection",
                                        socket
                                    );

                                    let buf = &conn.usr_buf.make_contiguous();
                                    debug!(
                                        "[{}] bytes received during connection lifetime: {}",
                                        socket,
                                        std::str::from_utf8_unchecked(buf).replace("\n", "\\n")
                                    );

                                    conn.state = ConnectionState::CLOSED;

                                    false
                                } else {
                                    true
                                }
                            }
                            _ => {
                                // If the maximum number of retransmissions is
                                // reached, the connection's state transitions
                                // to CLOSED.
                                match conn.on_conn_tick() {
                                    Ok(timer) => {
                                        if conn.state == ConnectionState::CLOSED {
                                            let buf = &conn.usr_buf.make_contiguous();

                                            debug!(
                                                "[{}] removing connection",
                                                socket,
                                            );

                                            debug!(
                                                "[{}] bytes received during connection lifetime: {}",
                                                socket,
                                                std::str::from_utf8_unchecked(buf).escape_default().collect::<String>()
                                            );

                                            false
                                        } else {
                                            if timer < nearest_timer {
                                                nearest_timer = timer;
                                            }
                                            true
                                        }
                                    }
                                    Err(err) => {
                                        error!(
                                            "[{}] ({:?}) failed to retransmit segment: {err}",
                                            socket, conn.state
                                        );
                                        false
                                    }
                                }
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
                        // The interval for periodic expirations.
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

                    if libc::timerfd_settime(timer_fd, 0, &raw const time_spec, ptr::null_mut())
                        == -1
                    {
                        return Err(errno!("failed to rearm timer"));
                    }
                }

                // Received an IP packet.
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
                                    let payload =
                                        &buf[iph.header_len() + tcph.header_len()..nbytes];

                                    if !tcph.is_valid_checksum(&iph, payload) {
                                        warn!("invalid IP packet received: invalid TCP checksum");
                                        break;
                                    }

                                    // Packet's source and destination are from
                                    // the peer's perspective. Stored in the
                                    // reverse order.
                                    let socket = Socket {
                                        src: SocketAddr {
                                            addr: dst,
                                            port: dst_port,
                                        },
                                        dst: SocketAddr {
                                            addr: src,
                                            port: src_port,
                                        },
                                    };

                                    match connections.entry(socket) {
                                        Entry::Vacant(entry) => {
                                            match TCB::on_conn_req(&iph, &tcph) {
                                                Ok(opt) => {
                                                    if let Some(conn) = opt {
                                                        entry.insert(conn);
                                                    }
                                                }
                                                Err(err) => {
                                                    error!(
                                                        "failed to process incoming TCP segment: {err}"
                                                    );
                                                }
                                            }
                                        }
                                        Entry::Occupied(mut conn) => {
                                            if let Err(Error::Io(err)) =
                                                conn.get_mut().on_conn_packet(&iph, &tcph, payload)
                                            {
                                                match err.kind() {
                                                    io::ErrorKind::ConnectionReset
                                                    | io::ErrorKind::ConnectionRefused => {
                                                        let buf = &conn
                                                            .get_mut()
                                                            .usr_buf
                                                            .make_contiguous();
                                                        debug!(
                                                            "[{}] bytes received during connection lifetime: {}",
                                                            socket,
                                                            std::str::from_utf8_unchecked(buf)
                                                                .escape_default()
                                                                .collect::<String>()
                                                        );

                                                        connections.remove(&socket);

                                                        debug!(
                                                            "[{}] removed connection, active connections remaining: {}",
                                                            socket,
                                                            connections.len(),
                                                        );
                                                    }
                                                    _ => {
                                                        warn!("{err}");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    error!("invalid IP packet received: {err}");
                                }
                            }
                        }
                        Ok(p) => {
                            debug!("ignoring non-TCP ({:?}) packet", p.protocol());
                        }
                        Err(err) => {
                            error!("invalid IP packet received: {err}");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Creates a non-blocking `signal_fd` for SIGINT and SIGTERM signals.
fn init_signal_fd() -> Result<RawFd> {
    unsafe {
        let mut mask: libc::sigset_t = mem::zeroed();

        // Initialize the signal set, excluding all signals.
        if libc::sigemptyset(&raw mut mask) == -1 {
            return Err(errno!("failed to initialize signal set"));
        }

        // Add both SIGINT and SIGTERM to the set.
        if libc::sigaddset(&raw mut mask, libc::SIGINT) == -1
            || libc::sigaddset(&raw mut mask, libc::SIGTERM) == -1
        {
            return Err(errno!("failed to update signal set"));
        }

        // Blocks SIGINT and SIGTERM from being intercepted by default handlers.
        if libc::sigprocmask(libc::SIG_BLOCK, &raw const mask, ptr::null_mut()) == -1 {
            return Err(errno!("failed to block signals on signal set"));
        }

        // Ensure it is set as non-blocking.
        let signal_fd = libc::signalfd(-1, &raw const mask, libc::SFD_NONBLOCK);
        if signal_fd == -1 {
            return Err(errno!("failed to create signal_fd"));
        }

        Ok(signal_fd.as_raw_fd())
    }
}

/// Creates a non-blocking `timer_fd` armed with an initial expiration of `RTO`.
fn init_timer_fd() -> Result<RawFd> {
    unsafe {
        let timer_fd = libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK);
        if timer_fd == -1 {
            return Err(errno!("failed to create timer_fd"));
        }

        // Ensure the timer is armed before entering the loop.
        let time_spec = libc::itimerspec {
            // The interval for periodic expirations.
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

        // `epoll()` is used to efficiently monitor multiple file descriptors for
        // I/O. Instead of blocking on each socket sequentially, this approach
        // (with non-blocking sockets) allows blocking on all simultaneously,
        // processing only the file descriptors that are ready for I/O.
        let epoll_fd = libc::epoll_create1(0);
        if epoll_fd == -1 {
            return Err(errno!("failed to create epoll_fd"));
        }

        for fd in fds {
            ev.events = libc::EPOLLIN as u32;
            ev.u64 = fd as u64;
            // Add the file descriptor to the epoll interest list to be notified
            // on ready events.
            if libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &raw mut ev) == -1 {
                return Err(errno!("failed to add to epoll interest list"));
            }
        }

        Ok(epoll_fd.as_raw_fd())
    }
}
