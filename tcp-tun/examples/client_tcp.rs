//! A simple client that opens a TCP stream, sends a message received from
//! `stdin` to the peer, and closes the connection upon receiving an "exit"
//! message.
//!
//! Before running this example, ensure the TUN interface and binary are set up
//! by running:
//!
//!     ./setup.sh
//!
//! To start a server that this client can talk to on port 6142, you can use
//! this command:
//!
//!     nc -s 10.0.0.1 -l -p 6142
//!
//! And then in another terminal run:
//!
//!     cargo r --release --example client_tcp

fn main() {
    println!("hello, world");
}
