use std::collections::{HashMap, hash_map::Entry};
use std::{io, mem, ptr};

use crate::net::{ConnectionState, Ipv4Header, MSL, Protocol, RTO, Socket, TCB, TcpHeader};
use crate::tun_tap::{self, MTU_SIZE};
use crate::{debug, error, warn};

/// Total number of events returned each tick (event loop cycle).
const EPOLL_MAX_EVENTS: i32 = 3;

/// The number of milliseconds that `epoll_wait()` will block for. -1 will
/// block indefinitely until an event occurs.
const EPOLL_TIMEOUT_MS: i32 = -1;

/// Runs an event loop to monitor for and process incoming IP frames from the
/// TUN device. This function runs continuously until receiving a shutdown
/// signal (e.g., SIGINT, SIGTERM).
///
/// # Notes
///
/// It is the users responsibility to ensure the TUN device provided is set
/// to non-blocking before calling this function.
///
/// # Errors
///
/// Returns an error if the event loop could not be successfully initialized.
pub fn packet_loop(
    nic: &mut tun_tap::Tun,
    connections: &mut HashMap<Socket, TCB>,
) -> io::Result<()> {
    let mut ev = libc::epoll_event { events: 0, u64: 0 };

    // Array of events for ready file descriptors.
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; EPOLL_MAX_EVENTS as usize];

    let mut mask: libc::sigset_t = unsafe { mem::zeroed() };

    let tun_fd = nic.fd();
    let signal_fd;
    let timer_fd;
    let epoll_fd;
    let mut rdfs;

    unsafe {
        // Initialize the signal set, excluding all signals.
        if libc::sigemptyset(&raw mut mask) == -1 {
            return Err(io::Error::last_os_error());
        }

        // Add both SIGINT and SIGTERM to the set.
        if libc::sigaddset(&raw mut mask, libc::SIGINT) == -1
            || libc::sigaddset(&raw mut mask, libc::SIGTERM) == -1
        {
            return Err(io::Error::last_os_error());
        }

        // Blocks SIGINT and SIGTERM from being intercepted by default handlers.
        if libc::sigprocmask(libc::SIG_BLOCK, &raw const mask, ptr::null_mut()) == -1 {
            return Err(io::Error::last_os_error());
        }

        signal_fd = libc::signalfd(-1, &raw const mask, 0);
        if signal_fd == -1 {
            return Err(io::Error::last_os_error());
        }

        timer_fd = libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK);
        if timer_fd == -1 {
            libc::close(signal_fd);

            return Err(io::Error::last_os_error());
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
            libc::close(signal_fd);
            libc::close(timer_fd);

            return Err(io::Error::last_os_error());
        }

        // `epoll()` is used to efficiently monitor multiple file descriptors
        // for I/O. Instead of blocking on each socket sequentially, this
        // approach (with non-blocking sockets) allows blocking on all
        // simultaneously, processing only the file descriptors that are ready
        // for I/O.
        epoll_fd = libc::epoll_create1(0);
        if epoll_fd == -1 {
            libc::close(signal_fd);
            libc::close(timer_fd);

            return Err(io::Error::last_os_error());
        }

        ev.events = libc::EPOLLIN as u32;
        ev.u64 = tun_fd as u64;
        // Add the TUN's file descriptor to the epoll interest list to be
        // notified when it becomes ready for reading (e.g., incoming IP frame).
        if libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, tun_fd, &raw mut ev) == -1 {
            libc::close(signal_fd);
            libc::close(timer_fd);
            libc::close(epoll_fd);

            return Err(io::Error::last_os_error());
        }

        ev.events = libc::EPOLLIN as u32;
        ev.u64 = signal_fd as u64;
        // Also add the signal file descriptors to be notified on SIGINT or
        // SIGTERM.
        if libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, signal_fd, &raw mut ev) == -1 {
            libc::close(signal_fd);
            libc::close(timer_fd);
            libc::close(epoll_fd);

            return Err(io::Error::last_os_error());
        }

        ev.events = libc::EPOLLIN as u32;
        ev.u64 = timer_fd as u64;
        // Timer that signals when retransmission queue should be checked.
        if libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, timer_fd, &raw mut ev) == -1 {
            libc::close(signal_fd);
            libc::close(timer_fd);
            libc::close(epoll_fd);

            return Err(io::Error::last_os_error());
        }
    }

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
                libc::close(signal_fd);
                libc::close(timer_fd);
                libc::close(epoll_fd);

                return Err(io::Error::last_os_error());
            }

            for event in events.iter().take(rdfs as usize) {
                // A signal was caught (SIGINT or SIGTERM).
                if event.u64 == signal_fd as u64 {
                    debug!("signal caught");

                    libc::close(signal_fd);
                    libc::close(timer_fd);
                    libc::close(epoll_fd);

                    break 'event_loop;
                }

                // Timer went off.
                if event.u64 == timer_fd as u64 {
                    // Read from the timer to clear the expiration count and
                    // prevent event overflow.
                    let mut buf = [0u8; 8];

                    let _ = libc::read(timer_fd, &raw mut buf as *mut libc::c_void, buf.len());

                    // Iterate over all active connection to check whether
                    // retransmissions are necessary.
                    for (_socket, conn) in connections.iter_mut() {
                        match conn.state() {
                            ConnectionState::CLOSED | ConnectionState::LISTEN => {}
                            ConnectionState::TIME_WAIT => {
                                // The timer has expired
                                if conn.time_wait().elapsed()
                                    >= std::time::Duration::from_secs(MSL * 2)
                                {
                                    // TODO: Connection needs to be cleaned up.
                                    conn.set_state(ConnectionState::CLOSED);
                                }
                            }
                            _ => {
                                if let Err(err) = conn.on_conn_tick(nic) {
                                    error!("{err}");
                                }
                            }
                        }
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
                            tv_sec: RTO as i64,
                            tv_nsec: 0,
                        },
                    };

                    if libc::timerfd_settime(timer_fd, 0, &raw const time_spec, ptr::null_mut())
                        == -1
                    {
                        libc::close(signal_fd);
                        libc::close(timer_fd);
                        libc::close(epoll_fd);

                        return Err(io::Error::last_os_error());
                    }
                }

                // The TUN interface is ready for I/O.
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
                            let src = iph.src();
                            let dst = iph.dst();

                            match TcpHeader::try_from(&buf[iph.header_len()..nbytes]) {
                                Ok(tcph) => {
                                    let src_port = tcph.src_port();
                                    let dst_port = tcph.dst_port();
                                    let payload =
                                        &buf[iph.header_len() + tcph.header_len()..nbytes];

                                    // Packets are from the peer's perspective, so src/dst
                                    // are flipped. Reverse them to match the format used
                                    // when initiating connections, ensuring consistent
                                    // socket lookup in the connection hash map.
                                    let socket = Socket {
                                        src: (dst, dst_port),
                                        dst: (src, src_port),
                                    };

                                    match connections.entry(socket) {
                                        Entry::Vacant(entry) => {
                                            match TCB::on_conn_req(nic, &iph, &tcph) {
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
                                            conn.get_mut()
                                    .on_conn_packet(nic, &iph, &tcph, payload)
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
        }
    }

    Ok(())
}
