# tcp

A **user-space Transmission Control Protocol (TCP) implementation**, designed for 
experimentation and learning.

[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hmunye/tcp/blob/main/LICENSE)
[![Build Status](https://github.com/hmunye/tcp/workflows/CI/badge.svg)](https://github.com/hmunye/tcp/actions?query=workflow%3ACI+branch%3Amain)
[![Dependency Status](https://deps.rs/repo/github/hmunye/tcp/status.svg)](https://deps.rs/repo/github/hmunye/tcp)

This project is organized as a Cargo workspace:

- **`tcp-core`**: A lightweight TCP crate (primarily RFC 793) that handles the state 
machine, packet parsing/serialization, and segment construction

- **`tcp-tun`**: Linux-only crate that integrates with the network stack via TUN/TAP, using `epoll` 
for single-threaded, non-blocking I/O

## Quick Start

To include the `tcp-core` crate as a dependency in your project, run the following command:

```bash
cargo add --git https://github.com/hmunye/tcp.git tcp-core
```

To get started with `tcp-tun`, clone the repository and navigate to the directory:

```bash
git clone https://github.com/hmunye/tcp.git
cd tcp/tcp-tun
```

Refer to the [quick start] guide for further steps.

[quick start]: https://github.com/hmunye/tcp/tree/main/tcp-tun#quick-start

## License

This project is licensed under the [MIT License].

[MIT License]: https://github.com/hmunye/tcp/blob/main/LICENSE

## References
- [Jon Gjengset - Implementing TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
- [Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [Assigned Numbers](https://www.rfc-editor.org/rfc/rfc1700)
- [Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323) 
- [Requirements for Internet Hosts -- Communication Layers](https://www.rfc-editor.org/rfc/rfc1122)
- [Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)
