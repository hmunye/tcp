//! TUN (network TUNnel) virtual network device.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::{mem, ptr};

use crate::{Error, Result, errno};

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
    name: String,
}

impl Tun {
    /// Creates a new TUN virtual network device.
    ///
    /// Packets received on this device will have the following structure:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType]
    /// - Raw protocol (IP, IPv6, etc) frame
    ///
    /// [EtherType]: https://en.wikipedia.org/wiki/EtherType
    ///
    /// The caller must ensure that the provided device name does not include
    /// any null (`\0`) bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened, for example, due to
    /// an invalid name or the absence of `CAP_NET_ADMIN` privilege.
    pub fn new(dev: &str) -> Result<Self> {
        Self::create_tun(dev, true)
    }

    /// Creates a new TUN virtual network device without packet information.
    ///
    /// Packets received on this device will EXCLUDE the leading 4 bytes of
    /// packet info:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType]
    ///
    /// and only contain the raw protocol (IP, IPv6, etc) frame.
    ///
    /// [EtherType]: https://en.wikipedia.org/wiki/EtherType
    ///
    /// The caller must ensure that the provided device name does not include
    /// any null (`\0`) bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened, for example, due to
    /// an invalid name or the absence of `CAP_NET_ADMIN` privilege.
    pub fn without_packet_info(dev: &str) -> Result<Self> {
        Self::create_tun(dev, false)
    }

    /// Returns the raw file descriptor of the TUN virtual network device.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Returns the assigned name of the TUN virtual network device.
    ///
    /// The name provided for the TUN device is a suggestion to the kernel, so
    /// the assigned name may differ from the one given.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receives an IP packet from the TUN virtual network device.
    ///
    /// By default, this call blocks until a packet is available for reading.
    ///
    /// The caller must ensure the buffer is large enough, `MTU_SIZE`, to
    /// accommodate the packet and any leading header data, if configured.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        (&self.fd).read(buf).map_err(|err| err.into())
    }

    /// Sends a network packet to the TUN virtual network device.
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

    /// Configures the TUN virtual network device to be non-blocking.
    ///
    /// This affects the behavior of the [Tun::send] and [Tun::recv] methods if
    /// configured.
    pub fn set_non_blocking(&self) -> Result<()> {
        let fd = self.as_raw_fd();

        // Get the current flags so they can be combined with `O_NONBLOCK`.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(errno!("failed to get flags of TUN file handle"));
        }

        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(errno!("failed to set TUN file handle to non-blocking"));
        }

        Ok(())
    }

    fn create_tun(dev: &str, with_packet_info: bool) -> Result<Self> {
        // `IFNAMSIZ` is the size of `ifreq.ifr_name`, including null
        // terminator.
        if dev.len() >= libc::IFNAMSIZ {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            )));
        }

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };

        // IFF_TUN   - TUN device (no Ethernet headers)
        //
        // IFF_NO_PI - Do not provide packet information
        let flags = if with_packet_info {
            libc::IFF_TUN
        } else {
            libc::IFF_TUN | libc::IFF_NO_PI
        };

        unsafe {
            // SAFETY: `dev.len()` is less than `IFNAMSIZ`.
            ptr::copy_nonoverlapping(
                dev.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                dev.len(),
            );

            ifr.ifr_ifru.ifru_flags = flags as i16;
        }

        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &ifr) } == -1 {
            return Err(errno!(
                "failed to bind network interface with TUN file handle"
            ));
        }

        // SAFETY: `ifr_name` remains null-terminated after copying `dev.len()`
        // bytes.
        let name = unsafe {
            CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        Ok(Self { fd, name })
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
