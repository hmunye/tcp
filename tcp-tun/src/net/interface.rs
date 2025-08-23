//! [std::net]-like API for TCP communication.
//!
//! [std::net]: https://doc.rust-lang.org/std/net/index.html

/// Local socket address when making TCP connections.
pub const LOCAL_ADDR: SocketAddr = SocketAddr {
    addr: [10, 0, 0, 2],
    port: 12345,
};

use tcp_core::Result;
use tcp_core::protocol::fsm::OpenKind;
use tcp_core::protocol::socket::{Socket, SocketAddr};

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, mpsc};

use crate::errno;
use crate::event_loop::event_loop;

/// Possible requests which can be passed to the current event loop.
#[derive(Debug)]
pub enum UserReq {
    /// Request to send data to the peer of the connection.
    Send(Socket, Vec<u8>, mpsc::Sender<usize>),
    /// Request to read data from the peer of the connection providing the user
    /// buffer size.
    Read(Socket, usize, mpsc::Sender<(Vec<u8>, usize)>),
    /// Request to close the connection corresponding to the `Socket`.
    Close(Socket, mpsc::Sender<()>),
    /// Request to accept a pending peer connection.
    Accept(mpsc::Sender<TcpStream>),
}

/// Shared state for user request handling.
#[derive(Debug)]
pub struct State {
    /// Handle to notify the event loop of new user requests.
    pub user_handle: i32,
    /// Queue of user requests.
    pub user_req_queue: Mutex<VecDeque<UserReq>>,
}

/// A TCP socket server, listening for connections.
#[derive(Debug)]
pub struct TcpListener {
    state: Arc<State>,
    channel: (mpsc::Sender<TcpStream>, mpsc::Receiver<TcpStream>),
    addr: SocketAddr,
}

impl TcpListener {
    /// Creates a new `TcpListener` which will be bound to the specified
    /// port.
    ///
    /// The returned listener is ready for accepting connections.
    pub fn bind(port: u16) -> Result<Self> {
        let event_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        if event_fd == -1 {
            return Err(errno!("failed to create event_fd"));
        }

        let state = Arc::new(State {
            user_handle: event_fd,
            user_req_queue: Default::default(),
        });
        let state_clone = Arc::clone(&state);

        let addr = SocketAddr {
            addr: [10, 0, 0, 1],
            port,
        };

        std::thread::spawn(move || event_loop(state_clone, OpenKind::PASSIVE_OPEN, addr));

        Ok(Self {
            state,
            channel: mpsc::channel(),
            addr,
        })
    }

    /// Accept a new incoming connection from this listener.
    pub fn accept(&self) -> Result<TcpStream> {
        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Accept(self.channel.0.clone()))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.user_handle,
                &raw const x as *const libc::c_void,
                8,
            )
        };

        let stream = self.channel.1.recv().unwrap();

        Ok(stream)
    }

    /// Returns the local socket address of this listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

type SendChannel = (mpsc::Sender<usize>, mpsc::Receiver<usize>);

type ReadChannel = (
    mpsc::Sender<(Vec<u8>, usize)>,
    mpsc::Receiver<(Vec<u8>, usize)>,
);

/// A TCP stream between a local and a remote socket.
#[derive(Debug)]
pub struct TcpStream {
    /// TODO
    pub state: Arc<State>,
    /// TODO
    pub send_channel: SendChannel,
    /// TODO
    pub read_channel: ReadChannel,
    /// TODO
    pub sock: Socket,
}

impl TcpStream {
    /// Opens a TCP connection to a remote host.
    pub fn connect(port: u16) -> io::Result<Self> {
        let event_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        //         if event_fd == -1 {
        //             return Err(errno!("failed to create event_fd"));
        //         }

        let state = Arc::new(State {
            user_handle: event_fd,
            user_req_queue: Default::default(),
        });
        let state_clone = Arc::clone(&state);

        let peer = SocketAddr {
            addr: [10, 0, 0, 1],
            port,
        };

        std::thread::spawn(move || event_loop(state_clone, OpenKind::ACTIVE_OPEN, peer));

        Ok(Self {
            state,
            send_channel: mpsc::channel(),
            read_channel: mpsc::channel(),
            sock: Socket {
                src: LOCAL_ADDR,
                dst: peer,
            },
        })
    }

    /// Returns the socket address of the local half of this TCP connection.
    pub fn local_addr(&self) -> SocketAddr {
        self.sock.src
    }

    /// Returns the socket address of the remote peer of this TCP connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.sock.dst
    }

    /// Shuts down the read and write halves of this connection.
    pub fn shutdown(&self) -> Result<()> {
        let (tx, rx) = mpsc::channel();

        {
            let mut queue = self.state.user_req_queue.lock().unwrap();
            queue.push_back(UserReq::Close(self.sock, tx))
        }

        // Notify the event loop.
        let x: u64 = 1;
        unsafe {
            libc::write(
                self.state.user_handle,
                &raw const x as *const libc::c_void,
                8,
            )
        };

        rx.recv().unwrap();

        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = self.shutdown();
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
                self.state.user_handle,
                &raw const x as *const libc::c_void,
                8,
            )
        };

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
                self.state.user_handle,
                &raw const x as *const libc::c_void,
                8,
            )
        };

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
                self.state.user_handle,
                &raw const x as *const libc::c_void,
                8,
            )
        };

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
                self.state.user_handle,
                &raw const x as *const libc::c_void,
                8,
            )
        };

        Ok(self.send_channel.1.recv().unwrap())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
