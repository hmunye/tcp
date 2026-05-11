//! TUN/TAP provides packet reception and transmission for user-space programs.
//!
//! It can be seen as a simple Point-to-Point or Ethernet device, which, instead
//! of receiving packets from physical media, receives them from the user space
//! program and instead of sending packets via physical media writes them to the
//! user space program.

use std::fs::{File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::{io, ptr};

use rio::io::{AsyncRead, AsyncWrite, Interest, IoHandle};
use rio::task::coop;
use tcp::Result;

/// Maximum transmission unit (`MTU`) for the TUN interface, accounting for
/// extra packet information if configured.
pub const MTU_SIZE: usize = 1504;

macro_rules! os_error {
    ($($tt:tt)+) => {{
        let e = ::std::io::Error::last_os_error();
        let prefix = format!($($tt)+);
        tcp::Error::Io(::std::io::Error::new(e.kind(), format!("{prefix}: {e}")))
    }}
}

/// TUN (network `TUNnel`) device.
///
/// Virtual network device that acts as a software loopback for transferring IP
/// packets between user space and the kernel, operating at layer 3 of the OSI
/// model.
#[derive(Debug)]
pub struct TUN {
    // NOTE: Defined first to ensure it is dropped before `fd`.
    handle: Option<IoHandle>,
    fd: File,
}

impl TUN {
    /// Creates a new `TUN` with packet information.
    ///
    /// Packets received on this device will have the following structure:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType]
    /// - Raw protocol (IP, IPv6, etc.) packet
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened (e.g., due to the
    /// absence of `CAP_NET_ADMIN` privilege).
    ///
    /// [EtherType]: https://en.wikipedia.org/wiki/EtherType
    #[inline]
    #[allow(unused)]
    pub fn with_packet_info() -> Result<Self> {
        Self::open_tun(true)
    }

    /// Creates a new `TUN` without packet information.
    ///
    /// Packets received on this device will exclude the leading 4 bytes of
    /// packet information:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType]
    ///
    /// and only contain the raw protocol (IP, IPv6, etc.) packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened (e.g., due to the
    /// absence of `CAP_NET_ADMIN` privilege).
    ///
    /// [EtherType]: https://en.wikipedia.org/wiki/EtherType
    #[inline]
    pub fn without_packet_info() -> Result<Self> {
        Self::open_tun(false)
    }

    /// Configures the `TUN` to be non-blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if the `TUN` device could not be configured.
    pub fn set_non_blocking(&self) -> Result<()> {
        let fd = self.as_raw_fd();

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(os_error!("failed to get file descriptor flags"));
        }

        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(os_error!("failed to set O_NONBLOCK"));
        }

        Ok(())
    }

    fn open_tun(with_packet_info: bool) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr = MaybeUninit::<libc::ifreq>::zeroed();
        let ifr = unsafe { &mut *ifr.as_mut_ptr() };

        // Flags for TUN device:
        //
        // IFF_TUN   - TUN device (no Ethernet headers)
        // IFF_NO_PI - Do not provide packet information
        ifr.ifr_ifru.ifru_flags = if with_packet_info {
            libc::IFF_TUN
        } else {
            libc::IFF_TUN | libc::IFF_NO_PI
        } as i16;

        // Name the TUN device
        let dev = b"tun0";

        unsafe {
            ptr::copy_nonoverlapping(dev.as_ptr(), ifr.ifr_name.as_mut_ptr().cast(), dev.len());
        }

        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, ifr) } == -1 {
            return Err(os_error!("failed to configure TUN device"));
        }

        Ok(Self { handle: None, fd })
    }
}

impl AsRawFd for TUN {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsyncRead for TUN {
    /// Reads an IP packet from the TUN device.
    ///
    /// The provided buffer should be at least `MTU_SIZE` bytes to ensure the
    /// full packet can be received, including any optional packet metadata if
    /// configured.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Read;

        let mut read = 0;
        let coop = ready!(coop::poll_proceed());

        loop {
            match self.fd.read(&mut buf[read..]) {
                Ok(0) => {
                    coop.made_progress();
                    return Poll::Ready(Ok(read));
                }
                Ok(n) => {
                    read += n;

                    if read == buf.len() {
                        coop.made_progress();
                        return Poll::Ready(Ok(read));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.handle.as_mut() {
                        Some(handle) => {
                            if !handle.is_readable() {
                                handle.add_interest(Interest::EDGE_TRIGGERED | Interest::READ);
                            }
                        }
                        None => {
                            self.handle = Some(rio::io::register_io_source(
                                self.as_raw_fd(),
                                Interest::EDGE_TRIGGERED | Interest::READ,
                                cx.waker().clone(),
                            ));
                        }
                    }

                    if read > 0 {
                        coop.made_progress();
                        return Poll::Ready(Ok(read));
                    } else {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    coop.made_progress();
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl AsyncWrite for TUN {
    /// Writes an IP packet to the TUN device.
    ///
    /// The packet must not exceed `MTU_SIZE` and is expected to include a valid
    /// IP header. The kernel may silently drop packets for reasons such as
    /// checksum failures, invalid routing, or rate limiting, even if the write
    /// call succeeds.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;

        let mut written = 0;
        let coop = ready!(coop::poll_proceed());

        loop {
            match self.fd.write(&buf[written..]) {
                Ok(0) => {
                    coop.made_progress();
                    return Poll::Ready(Ok(written));
                }
                Ok(n) => {
                    written += n;

                    if written == buf.len() {
                        coop.made_progress();
                        return Poll::Ready(Ok(written));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.handle.as_mut() {
                        Some(handle) => {
                            if !handle.is_writable() {
                                handle.add_interest(Interest::EDGE_TRIGGERED | Interest::WRITE);
                            }
                        }
                        None => {
                            self.handle = Some(rio::io::register_io_source(
                                self.as_raw_fd(),
                                Interest::EDGE_TRIGGERED | Interest::WRITE,
                                cx.waker().clone(),
                            ));
                        }
                    }

                    if written > 0 {
                        coop.made_progress();
                        return Poll::Ready(Ok(written));
                    } else {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    coop.made_progress();
                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TUN devices do not have a formal shutdown; dropping the FD closes it.
        Poll::Ready(Ok(()))
    }
}
