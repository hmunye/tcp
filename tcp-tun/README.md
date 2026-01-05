# tcp-tun

Linux-only crate enabling TUN/TAP networking for user-space TCP, exposing a 
[std::net]-like API.

[std::net]: https://doc.rust-lang.org/std/net/index.html

> [!WARNING]  
> This project is experimental and not intended for production use.

## TOC
* [Limitations](#limitations)
* [Quick Start](#quick-start)
* [License](#license)
* [References](#references)

## Limitations

Current limitations include, but are not limited to:

- Assuming IP packets are fully reassembled (no handling of IP fragmentation)
- No user-timeout support
- No asynchronous operations (blocking-only API)
- No proper demultiplexing (multiple connections read directly from the TUN, 
  causing packets to be misrouted or dropped)
- No connection-idle timeout (e.g., peer sends a `FIN+ACK` segment, local side of the connection 
  transitions to `CLOSE_WAIT`, and connection remains idle)
- Incomplete pending `send`/`recv` user request handling
- Pending operations are not guaranteed to return when expected (may linger for longer)

## Quick Start

This crate is Linux-only due to dependencies on:

- **`epoll`** for efficient single-threaded, non-blocking I/O
- **`/dev/net/tun`** for handling raw IP network traffic

To setup the program, run the following command:

```bash
./setup.sh
```
> Note: `root` privileges are required.

Alternatively, run the command below to setup with logging enabled:

```bash
DEBUG=1 ./setup.sh
```
> Note: `root` privileges are required.

The script will:

- Compile the crate in release/debug mode
- Set `CAP_NET_ADMIN` privileges for the binary
- Create a TUN device (`tun0`)
- Assign the local IP `10.0.0.1/32` to the TUN device and configure a peer IP `10.0.0.2`

Choose one of the following commands based on the script mode:

- Release mode (default):

```bash
../target/release/tcp-tun
```

- Debug mode:

```bash
../target/debug/tcp-tun
```

You can now use `10.0.0.1` as the source IP address and `10.0.0.2` as the destination 
to initiate or accept TCP connections.

Examples can be found [here](https://github.com/hmunye/tcp/tree/main/tcp-tun/examples).

When finished, run the provided cleanup script:

```bash
./cleanup.sh
```
> Note: `root` privileges are required.

This will remove the `tun0` interface and its configuration.

## License

This project is licensed under the [MIT License].

[MIT License]: https://github.com/hmunye/tcp/blob/main/LICENSE

## References
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
