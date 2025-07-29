use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::ptr;

/// The Maximum Transmission Unit (MTU) for the TUN interface.
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
    /// - Raw protocol (IP, IPv6, etc) frame [MTU bytes]
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues with the specified name or if the
    /// process lacks the necessary privileges (CAP_NET_ADMIN).
    ///
    /// # Notes
    ///
    /// It is the caller's responsibility to ensure that the provided device
    /// name does not contain any null (`\0`) bytes, to avoid unexpected
    /// behavior.
    pub fn new(dev: &str) -> io::Result<Self> {
        Self::create_tun(dev, true)
    }

    /// Creates a new TUN virtual network device without packet information.
    ///
    /// Packets received on this device will exclude the leading 4 bytes of
    /// packet info:
    ///
    /// - Flags [2 bytes]
    /// - Proto [2 bytes] [EtherType](https://en.wikipedia.org/wiki/EtherType)
    ///
    /// and only contain the raw protocol (IP, IPv6, etc) frame [MTU bytes].
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues with the specified name or if the
    /// process lacks the necessary privileges (CAP_NET_ADMIN).
    ///
    /// # Notes
    ///
    /// It is the caller's responsibility to ensure that the provided device
    /// name does not contain any null (`\0`) bytes, to avoid unexpected
    /// behavior.
    pub fn without_packet_info(dev: &str) -> io::Result<Self> {
        Self::create_tun(dev, false)
    }

    /// Returns the assigned name of the TUN virtual network device.
    ///
    /// # Notes
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
    /// enough. It's size should be the MTU of the interface (typically 1500 bytes) + 4 bytes
    /// for the prepended packet information if configured, otherwise the packet will be
    /// truncated to fit the buffer.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.fd).read(buf)
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
    /// could be discarded by the kernel due to validation failure, high send
    /// frequency, or unassigned destination addresses.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        (&self.fd).write(buf)
    }

    fn create_tun(dev: &str, with_packet_info: bool) -> io::Result<Self> {
        // `IFNAMSIZ` defines the length of `ifr_name` field.
        if dev.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };

        // Flags: IFF_TUN   - TUN device (no Ethernet headers)
        //
        //        IFF_NO_PI - Do not provide packet information
        let flags = if with_packet_info {
            libc::IFF_TUN
        } else {
            libc::IFF_TUN | libc::IFF_NO_PI
        };

        unsafe {
            ptr::copy_nonoverlapping(
                dev.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                dev.len(),
            );

            ifr.ifr_ifru.ifru_flags = flags as i16;
        }

        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &ifr) } == -1 {
            return Err(io::Error::last_os_error());
        }

        // Read back assigned interface name, as it may be different.
        let name = unsafe {
            CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        Ok(Self { fd, name })
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
