//! TUN/TAP provides packet reception and transmission for user space programs.
//!
//! It can be seen as a simple Point-to-Point or Ethernet device, which, instead
//! of receiving packets from physical media, receives them from the user space
//! program and instead of sending packets via physical media writes them to the
//! user space program.

use tcp_core::Result;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::{mem, ptr};

use crate::errno;

/// Maximum Transmission Unit (`MTU`) for the TUN interface.
///
/// Accounts for extra packet information if configured.
pub const MTU_SIZE: usize = 1504;

/// TUN (network TUNnel) device.
///
/// A virtual network device that acts as a software loopback for transferring
/// IP packets between user space and the kernel, operating at layer 3 of the
/// OSI model.
#[derive(Debug)]
pub struct Tun {
    fd: File,
}

impl Tun {
    /// Creates a new `TUN`.
    ///
    /// Packets received on this device will have the following structure:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType]
    /// - Raw protocol (IP, IPv6, etc) packet
    ///
    /// [EtherType]: https://en.wikipedia.org/wiki/EtherType
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened, for example, due
    /// to the absence of `CAP_NET_ADMIN` privilege.
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
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
    /// and only contain the raw protocol (IP, IPv6, etc) packet.
    ///
    /// [EtherType]: https://en.wikipedia.org/wiki/EtherType
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened, for example, due
    /// to the absence of `CAP_NET_ADMIN` privilege.
    pub fn without_packet_info() -> Result<Self> {
        Self::open_tun(false)
    }

    /// Returns the raw file descriptor of the `TUN`.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Receives an IP packet from the `TUN`.
    ///
    /// By default, this call blocks until an IP packet is available for
    /// reading.
    ///
    /// The caller must ensure the buffer is large enough, `MTU_SIZE`, to
    /// accommodate the packet and any leading header data, if configured.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        (&self.fd).read(buf).map_err(|err| err.into())
    }

    /// Sends an IP packet to the `TUN`.
    ///
    /// The caller must ensure the packet size does not exceed `MTU_SIZE` and
    /// that it is properly formatted with the necessary headers.
    ///
    /// Many errors are handled silently by the OS kernel, which may lead to
    /// dropped packets. Although the packet might appear successfully sent, it
    /// could be discarded by the kernel due to issues like checksum validation
    /// failure, high send frequency, or unassigned destination addresses.
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        (&self.fd).write(buf).map_err(|err| err.into())
    }

    /// Configures the `TUN` to be non-blocking.
    ///
    /// This affects the behavior of the [Tun::send] and [Tun::recv] methods if
    /// configured.
    pub fn set_non_blocking(&self) -> Result<()> {
        let fd = self.as_raw_fd();

        // Get the current flags so they can be combined with `O_NONBLOCK`.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(errno!("failed to get flags for TUN file handle"));
        }

        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(errno!(
                "failed to configure TUN file handle as non-blocking"
            ));
        }

        Ok(())
    }

    fn open_tun(with_packet_info: bool) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };

        // IFF_TUN   - TUN device (no Ethernet headers)
        // IFF_NO_PI - Do not provide packet information
        let flags = if with_packet_info {
            libc::IFF_TUN
        } else {
            libc::IFF_TUN | libc::IFF_NO_PI
        };

        // Name given to the TUN device in `setup.sh`.
        let dev = "tun0";

        unsafe {
            ptr::copy_nonoverlapping(
                dev.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                dev.len(),
            );
        }

        ifr.ifr_ifru.ifru_flags = flags as i16;

        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &ifr) } == -1 {
            return Err(errno!(
                "failed to configure packet information for TUN file handle "
            ));
        }

        Ok(Self { fd })
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
