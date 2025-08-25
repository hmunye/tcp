//! [std::net]-like API for TCP communication.
//!
//! [std::net]: https://doc.rust-lang.org/std/net/index.html

// TODO: implement incoming iterator

use tcp_core::Error;
use tcp_core::protocol::{Socket, SocketAddr};

use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::iter::FusedIterator;
use std::mem;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use crate::errno;
use crate::event_loop;

/// Atomic counter for the local port number, incremented for each new TCP
/// connection initiated.
static LOCAL_PORT: AtomicU16 = AtomicU16::new(10000);

/// Possible values which can be passed to the [`TcpStream::shutdown`] method.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Shutdown {
    /// Attempts to gracefully close the connection.
    Close,
    /// Forcefully resets the connection.
    Abort,
}

/// Possible requests which can be passed to the event loop.
///
/// Channels are used to simulate blocking calls for `read`, `write`, `close`,
/// and `accept`.
#[derive(Debug)]
pub(crate) enum UserReq {
    /// Request to send data to the peer of the connection.
    ///
    /// Channel used to communicate number of bytes written.
    Send(Socket, Vec<u8>, mpsc::Sender<usize>),
    /// Request to read data from the peer of the connection, providing the size
    /// of the user buffer.
    ///
    /// Channel used to communicate the data read as well as the number of bytes
    /// read.
    Read(Socket, usize, mpsc::Sender<(Vec<u8>, usize)>),
    /// Request to close the connection corresponding to the `Socket`.
    ///
    /// Channel used to block until the connection has been fully closed.
    Close(Socket, Shutdown, mpsc::Sender<()>),
    /// Request to accept a pending peer connection.
    ///
    /// Channel used to communicate the next accepted, established TCP
    /// connection.
    Accept(mpsc::Sender<TcpStream>),
}

/// Shared state for user request handling.
#[derive(Debug)]
pub(crate) struct State {
    /// Handle to notify the event loop of new user requests.
    pub(crate) handle: i32,
    /// Queue of user requests.
    pub(crate) user_req_queue: Mutex<VecDeque<UserReq>>,
}

/// Iterator that infinitely [`accept`]s connections on a [`TcpListener`].
///
/// This `struct` is created by the [`TcpListener::incoming`] method.
/// See its documentation for more.
///
/// [`accept`]: TcpListener::accept
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a TcpListener,
}

impl FusedIterator for Incoming<'_> {}

impl<'a> Iterator for Incoming<'a> {
    type Item = io::Result<TcpStream>;
    fn next(&mut self) -> Option<io::Result<TcpStream>> {
        Some(self.listener.accept().map(|p| p.0))
    }
}

/// A TCP socket server, listening for connections.
///
/// # Examples
///
/// ```no_run
/// use tcp_tun::net::{TcpListener, TcpStream};
///
/// fn handle_client(stream: TcpStream) {
///     // ...
/// }
///
/// fn main() -> std::io::Result<()> {
///     let listener = TcpListener::bind("10.0.0.1:80")?;
///
///     // Accept connections and process them serially.
///     for stream in listener.incoming() {
///         handle_client(stream?);
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct TcpListener {
    /// Shared state between the user application and event loop.
    state: Arc<State>,
    /// Channel used to accept established TCP connections.
    accept_channel: (mpsc::Sender<TcpStream>, mpsc::Receiver<TcpStream>),
    /// Address being listened on for incoming TCP connections.
    listen_addr: SocketAddr,
}

impl TcpListener {
    /// Creates a new `TcpListener` which will be bound to the specified
    /// address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// # Note
    ///
    /// Each `TcpListener` will spawn it's own event loop on a separate thread.
    ///
    /// # Examples
    ///
    /// Creates a TCP listener bound to `10.0.0.1:80`:
    ///
    /// ```no_run
    /// use tcp_tun::net::TcpListener;
    ///
    /// let listener = TcpListener::bind("10.0.0.1:80").unwrap();
    /// ```
    pub fn bind(addr: impl TryInto<SocketAddr, Error = io::Error>) -> io::Result<Self> {
        let listen_addr: SocketAddr = addr.try_into()?;

        let event_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        if event_fd == -1 {
            let err = match errno!("failed to create event_fd") {
                Error::Io(err) => err,
                _ => unreachable!(),
            };
            return Err(err);
        }

        let state = Arc::new(State {
            handle: event_fd,
            user_req_queue: Default::default(),
        });

        let state_clone = Arc::clone(&state);

        // Spawn event loop that listens for incoming TCP connections.
        std::thread::spawn(move || event_loop::listen_loop(state_clone, listen_addr));

        Ok(Self {
            state,
            accept_channel: mpsc::channel(),
            listen_addr,
        })
    }

    /// Accept a new incoming connection from this listener.
    ///
    /// This function will block the calling thread until a new TCP connection
    /// is established. When established, the corresponding `TcpStream` and the
    /// remote peer’s address will be returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcp_tun::net::TcpListener;
    ///
    /// let listener = TcpListener::bind("10.0.0.1:8080").unwrap();
    /// match listener.accept() {
    ///     Ok((_stream, addr)) => println!("new client: {addr:?}"),
    ///     Err(err) => println!("couldn't get client: {err:?}"),
    /// }
    /// ```
    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Accept(self.accept_channel.0.clone()))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.handle,
                &raw const x as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };

        // Blocks until a connection has been accepted.
        let stream = self.accept_channel.1.recv().unwrap();

        let peer_addr = stream.peer_addr();

        Ok((stream, peer_addr))
    }

    /// Returns an iterator over the connections being received on this
    /// listener.
    ///
    /// The returned iterator will never return [None] and will also not yield
    /// the peer’s [SocketAddr] structure. Iterating over it is equivalent to
    /// calling [TcpListener::accept] in a loop.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcp_tun::net::{TcpListener, TcpStream};
    ///
    /// fn handle_connection(stream: TcpStream) {
    ///    //...
    /// }
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let listener = TcpListener::bind("10.0.0.1:80")?;
    ///
    ///     for stream in listener.incoming() {
    ///         match stream {
    ///             Ok(stream) => {
    ///                 handle_connection(stream);
    ///             }
    ///             Err(e) => { /* connection failed */ }
    ///         }
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Returns the local socket address of this listener.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcp_tun::net::{SocketAddr, TcpListener};
    ///
    /// let listener = TcpListener::bind("10.0.0.1:8080").unwrap();
    /// assert_eq!(
    ///     listener.local_addr(),
    ///     SocketAddr {
    ///         addr: [10, 0, 0, 1],
    ///         port: 8080
    ///     }
    /// );
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.state.handle);
        }
    }
}

type SendChannel = (mpsc::Sender<usize>, mpsc::Receiver<usize>);
type ReadChannel = (
    mpsc::Sender<(Vec<u8>, usize)>,
    mpsc::Receiver<(Vec<u8>, usize)>,
);

/// A TCP stream between a local and a remote socket.
///
/// The connection will be closed when the value is dropped.
///
/// # Examples
///
/// ```no_run
/// use std::io::prelude::*;
/// use tcp_tun::net::TcpStream;
///
/// fn main() -> std::io::Result<()> {
///     let mut stream = TcpStream::connect("10.0.0.1:8080")?;
///
///     stream.write(&[1])?;
///     stream.read(&mut [0; 128])?;
///
///     Ok(())
/// } // the stream is closed here
/// ```
#[derive(Debug)]
pub struct TcpStream {
    /// Shared state between the user application and event loop.
    state: Arc<State>,
    /// Channel used to send application data to the peer.
    send_channel: SendChannel,
    /// Channel used to read data from the peer.
    read_channel: ReadChannel,
    /// Local and peer socket addresses of the connection.
    sock: Socket,
    /// Value set to `true` if the `TcpStream` was created from a
    /// [TcpStream::connect] call.
    is_connect: bool,
}

impl TcpStream {
    pub(crate) fn new(
        state: Arc<State>,
        send_channel: SendChannel,
        read_channel: ReadChannel,
        sock: Socket,
    ) -> Self {
        Self {
            state,
            send_channel,
            read_channel,
            sock,
            is_connect: false,
        }
    }

    /// Opens a TCP connection to a remote host.
    ///
    /// # Note
    ///
    /// Each call to `TcpStream::connect` will spawn it's own event loop on a
    /// separate thread. An error is returned if all available local port
    /// numbers have been exhausted.
    ///
    /// # Examples
    ///
    /// Open a TCP connection to `10.0.0.1:8080`:
    ///
    /// ```no_run
    /// use tcp_tun::net::TcpStream;
    ///
    /// if let Ok(stream) = TcpStream::connect("10.0.0.1:8080") {
    ///     println!("Connected to the server!");
    /// } else {
    ///     println!("Couldn't connect to server...");
    /// }
    /// ```
    pub fn connect(addr: impl TryInto<SocketAddr, Error = io::Error>) -> io::Result<Self> {
        let peer_addr: SocketAddr = addr.try_into()?;
        let port = LOCAL_PORT.fetch_add(1, Ordering::SeqCst);

        // Port number wrapped around - no more ports available.
        if port == u16::MAX {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "all available port numbers have been exhausted",
            ));
        }

        // IP addresses for initiating connections are currently hard-coded.
        let local_addr = SocketAddr {
            addr: [10, 0, 0, 2],
            port,
        };

        let event_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        if event_fd == -1 {
            let err = match errno!("failed to create event_fd") {
                Error::Io(err) => err,
                _ => unreachable!(),
            };
            return Err(err);
        }

        let state = Arc::new(State {
            handle: event_fd,
            user_req_queue: Default::default(),
        });

        let state_clone = Arc::clone(&state);
        std::thread::spawn(move || {
            event_loop::connect_loop(
                state_clone,
                Socket {
                    src: local_addr,
                    dst: peer_addr,
                },
            )
        });

        Ok(Self {
            state,
            send_channel: mpsc::channel(),
            read_channel: mpsc::channel(),
            sock: Socket {
                src: local_addr,
                dst: peer_addr,
            },
            is_connect: true,
        })
    }

    /// Returns the socket address of the local half of this TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcp_tun::net::{SocketAddr, TcpStream};
    ///
    /// let stream = TcpStream::connect("10.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// assert_eq!(
    ///     stream.local_addr(),
    ///     SocketAddr {
    ///         addr: [10, 0, 0, 2],
    ///         port: 47892
    ///     }
    /// );
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.sock.src
    }

    /// Returns the socket address of the remote peer of this TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcp_tun::net::{SocketAddr, TcpStream};
    ///
    /// let stream = TcpStream::connect("10.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// assert_eq!(
    ///     stream.peer_addr(),
    ///     SocketAddr {
    ///         addr: [10, 0, 0, 1],
    ///         port: 8080
    ///     }
    /// );
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.sock.dst
    }

    /// Shuts down the read and write halves or resets this connection.
    ///
    /// This function blocks until the connection is either gracefully or
    /// forcefully terminated and will cause all pending and future I/O to
    /// return immediately.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcp_tun::net::{Shutdown, TcpStream};
    ///
    /// let stream = TcpStream::connect("10.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.shutdown(Shutdown::Abort).expect("shutdown call failed");
    /// ```
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();

        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Close(self.sock, how, tx))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.handle,
                &raw const x as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };

        // Blocks until the connection is closed.
        let _ = rx.recv();

        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = self.shutdown(Shutdown::Abort);

        // If the `TcpStream` created the `event_fd`, then close the file
        // descriptor.
        if self.is_connect {
            unsafe {
                let _ = libc::close(self.state.handle);
            }
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Read(
                self.sock,
                buf.len(),
                self.read_channel.0.clone(),
            ))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.handle,
                &raw const x as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };

        // Blocks until data is read.
        let (mut bytes, nbytes) = self.read_channel.1.recv().unwrap();

        let drained = bytes.drain(..nbytes);
        buf[..nbytes].copy_from_slice(drained.as_slice());

        Ok(nbytes)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Send(
                self.sock,
                buf.to_vec(),
                self.send_channel.0.clone(),
            ))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.handle,
                &raw const x as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };

        // Blocks until the data is written.
        Ok(self.send_channel.1.recv().unwrap())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for &TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Read(
                self.sock,
                buf.len(),
                self.read_channel.0.clone(),
            ))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.handle,
                &raw const x as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };

        // Blocks until data is read.
        let (mut bytes, nbytes) = self.read_channel.1.recv().unwrap();

        let drained = bytes.drain(..nbytes);
        buf.copy_from_slice(drained.as_slice());

        Ok(nbytes)
    }
}

impl Write for &TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Send(
                self.sock,
                buf.to_vec(),
                self.send_channel.0.clone(),
            ))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.handle,
                &raw const x as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };

        // Blocks until the data is written.
        Ok(self.send_channel.1.recv().unwrap())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
