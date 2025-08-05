use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::{mem, ptr};

use crate::{Error, Result, errno};

/// The Maximum Transmission Unit (MTU) for the TUN interface. Does NOT account
/// for leading packet information bytes if configured.
pub const MTU_SIZE: usize = 1500;

/// Represents a TUN (network TUNnel) interface, a virtual network device that
/// acts as a software loopback for transferring IP packets between user space
/// and the kernel, operating at layer 3 of the OSI model.
#[derive(Debug)]
pub struct Tun {
    fd: File,
    name: String,
}

impl Tun {
    /// Creates a new TUN virtual network device.
    ///
    /// Packets received on this device will follow this structure:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType](https://en.wikipedia.org/wiki/EtherType)
    /// - Raw protocol (IP, IPv6, etc) frame
    ///
    /// # Notes
    ///
    /// It is the caller's responsibility to ensure that the provided device
    /// name does not contain any null (`\0`) bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened, if there's a
    /// problem with the provided name, or if the process does not have the
    /// required `CAP_NET_ADMIN` privilege.    
    pub fn new(dev: &str) -> Result<Self> {
        Self::create_tun(dev, true)
    }

    /// Creates a new TUN virtual network device without packet information.
    ///
    /// Packets received on this device will EXCLUDE the leading 4 bytes of
    /// packet info:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType](https://en.wikipedia.org/wiki/EtherType)
    ///
    /// and only contain the raw protocol (IP, IPv6, etc) frame.
    ///
    /// # Notes
    ///
    /// It is the caller's responsibility to ensure that the provided device
    /// name does not contain any null (`\0`) bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the TUN device cannot be opened, if there's a
    /// problem with the provided name, or if the process does not have the
    /// required `CAP_NET_ADMIN` privilege.    
    pub fn without_packet_info(dev: &str) -> Result<Self> {
        Self::create_tun(dev, false)
    }

    /// Returns the raw file descriptor of the TUN virtual network device.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Returns the assigned name of the TUN virtual network device.
    ///
    /// The name given for creating the TUN device is more of a suggestion
    /// to the kernel rather than a requirement, so the assigned name may be
    /// different than the one originally provided.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receives an IP packet from the TUN virtual network device.
    ///
    /// By default, this call blocks until a packet is sent to the virtual
    /// network device.
    ///
    /// # Notes
    ///
    /// It is the caller's responsibility to ensure the buffer used is large
    /// enough. It's size should be MTU_SIZE + 4 bytes for the leading packet
    /// information if configured.
    ///
    /// # Errors
    ///
    /// Returns an error if data could not be read from the TUN device.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        (&self.fd).read(buf).map_err(|err| err.into())
    }

    /// Sends a network packet to the TUN virtual network interface.
    ///
    /// # Notes
    ///
    /// It is the caller's responsibility to ensure that the packet size does
    /// not exceed the MTU of the interface, and the packet is properly
    /// formatted with all appropriate headers.
    ///
    /// Many errors are silently handled by the OS kernel, often resulting in
    /// dropped packets. While packets may appear to be sent successfully, they
    /// could be discarded by the kernel due to checksum validation failure,
    /// high send frequency, or unassigned destination addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if data could not be written to the TUN device.
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        (&self.fd).write(buf).map_err(|err| err.into())
    }

    /// Sets the TUN virtual network interface to be non-blocking.
    ///
    /// # Notes
    ///
    /// This function changes the behavior of the [Tun::send] and [Tun::recv]
    /// methods.
    ///
    /// # Errors
    ///
    /// Returns an error if the file handle could not be set to non-blocking.
    pub fn set_non_blocking(&self) -> Result<()> {
        let fd = self.as_raw_fd();

        // Get current flags so they can be combined with `O_NONBLOCK`.
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
        // The interface name, if provided, must be less than `IFNAMSIZ` bytes.
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

        // SAFETY: `ifr_name` remains null-terminated after copying `dev`.
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
