//! A simple echo server that listens for incoming TCP connections on
//! `10.0.0.1:80`. It spawns a separate thread for each connection and echoes
//! back any data received from the client.
//!
//! Before running this example, ensure the TUN interface and binary are set up
//! by running:
//!
//!     DEBUG=1 ./setup.sh
//!
//! Then, in a separate terminal, start the server with:
//!
//!     cargo r --example echo_tcp
//!
//! To test the server, you can initiate a TCP connection using netcat:
//!
//!     nc -s 10.0.0.1 10.0.0.2 80

fn main() {
    println!("hello, world");
}
