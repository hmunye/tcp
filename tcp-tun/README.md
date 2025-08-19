# tcp-tun

Linux-only crate enabling TUN/TAP networking for user-space TCP via `tcp-core`, exposing a 
[std::net]-like API for TCP communication.

[std::net]: https://doc.rust-lang.org/std/net/index.html

## TOC
* [Limitations](#limitations)
* [Quick Start](#quick-start)
* [License](#license)
* [References](#references)

## Limitations

This implementation currently omits the following features and behaviors:

- Assumes IP packets are fully reassembled (no handling of IP fragmentation)
- No user-timeout support

## Quick Start

This crate is Linux-only due to dependencies on:

- `epoll` for efficient single-threaded, non-blocking I/O
- `/dev/net/tun` for handling raw IP network traffic

To build and start the program, run:

```bash
./run.sh
```
> Root privileges are required. Review the script before running.

The script will:

- Build and run the crate in release mode with `CAP_NET_ADMIN` privileges as a background process
- Bring up the `tun0` interface
- Assign the local IP `10.0.0.1/32` to the TUN device, with a peer IP of `10.0.0.2`
- Wait for the process to complete, handling cleanup on SIGINT or SIGTERM

You can then use `10.0.0.1` as the source and `10.0.0.2` as the destination to initiate or accept TCP 
connections.

Examples:

```bash
curl --interface 10.0.0.1 http://10.0.0.2
```

```bash
nc -s 10.0.0.1 10.0.0.2 80
```

## License

This project is licensed under the [MIT License].

[MIT License]: https://github.com/hmunye/tcp/blob/main/LICENSE

## References
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
