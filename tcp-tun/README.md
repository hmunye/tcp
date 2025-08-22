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

This currently omits the following features and behaviors:

- Assumes IP packets are fully reassembled (no handling of IP fragmentation)
- No user-timeout support

## Quick Start

This crate is Linux-only due to dependencies on:

- `epoll` for efficient single-threaded, non-blocking I/O
- `/dev/net/tun` for handling raw IP network traffic

To build the program and set up the TUN device, run:

```bash
./setup.sh
```
> Root privileges are required.

The script will:

- Create a TUN device (`tun0`) and bring it up
- Assign the local IP `10.0.0.1/32` to the TUN device and configure a peer IP of `10.0.0.2`
- Compile the crate in release mode
- Set `CAP_NET_ADMIN` privileges for the binary

If you want to build the program with logging enabled for TCP events, run the script with the 
`DEBUG=1` environment variable set:

```bash
DEBUG=1 ./setup.sh
```

To run the prepared binary, use one of the following commands:

If you built in release mode (default):

```bash
cargo r --release
```

If you built in debug mode with `DEBUG=1`:

```bash
cargo r
```

You can then use `10.0.0.1` as the source and `10.0.0.2` as the destination to initiate or accept TCP 
connections.

Examples:

```bash
curl --interface 10.0.0.1 http://10.0.0.2
```

```bash
nc -s 10.0.0.1 10.0.0.2 80
```

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
