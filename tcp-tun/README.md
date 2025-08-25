# tcp-tun

Linux-only crate enabling TUN/TAP networking for user-space TCP via [tcp-core], exposing a 
[std::net]-like API for TCP communication.

[tcp-core]: https://github.com/hmunye/tcp/tree/main/tcp-core
[std::net]: https://doc.rust-lang.org/std/net/index.html

## TOC
* [Limitations](#limitations)
* [Quick Start](#quick-start)
* [License](#license)
* [References](#references)

## Limitations

This currently omits, but is not limited to, the following features and behaviors:

- Assumes IP packets are fully reassembled (no handling of IP fragmentation)
- No user-timeout support
- No asynchronous operations (methods on TCP streams are blocking)
- No proper demultiplexing (without an intermediary, multiple connections read directly from the TUN, 
  causing packet to be misrouted or dropped)
- No connection-idle timeout (e.g., peer sends a `FIN+ACK` segment, local side of the connection 
  transitions to `CLOSE_WAIT`, and connection remains idle)
- Incomplete pending `send`/`recv` request handling
- Pending operations are not guaranteed to return when expected (may linger for longer)

## Quick Start

This crate is Linux-only due to dependencies on:

- **`epoll`** for efficient single-threaded, non-blocking I/O
- **`/dev/net/tun`** for handling raw IP network traffic

To build the program and set up the TUN device, run:

```bash
./setup.sh
```
> Root privileges are required.

The script will:

- Compile the crate in release mode by default
- Set `CAP_NET_ADMIN` privileges for the binary
- Create a TUN device (`tun0`) and bring it up
- Assign the local IP `10.0.0.1/32` to the TUN device and configure a peer IP of `10.0.0.2`

To build the program with logging enabled for TCP events, run the script with the `DEBUG=1` 
environment variable set:

```bash
DEBUG=1 ./setup.sh
```

To run the prepared binary, use one of the following commands:

Built in release mode (default):

```bash
cargo r --release
```

Built in debug mode with logging enabled:

```bash
cargo r
```

You can now use `10.0.0.1` as the source IP address and `10.0.0.2` as the destination to initiate or 
accept TCP connections.

Examples can be found [here](https://github.com/hmunye/tcp/tree/main/tcp-tun/examples).

To delete the TUN device after use, run the cleanup script:

```bash
./cleanup.sh
```
> Root privileges are required.

This will remove the `tun0` interface and its associated configuration.

## License

This project is licensed under the [MIT License].

[MIT License]: https://github.com/hmunye/tcp/blob/main/LICENSE

## References
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
