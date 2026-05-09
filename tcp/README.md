# tcp

User-space **Transmission Control Protocol (TCP)** implementation built to explore 
how the protocol works in practice, based primarily on [RFC 793].

[RFC 793]: https://www.rfc-editor.org/rfc/rfc793

> [!WARNING]
> This project is experimental and not intended for production use.

[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hmunye/tcp/blob/main/LICENSE)
[![Build Status](https://github.com/hmunye/tcp/workflows/CI/badge.svg)](https://github.com/hmunye/tcp/actions?query=workflow%3ACI+branch%3Amain)
[![Dependency Status](https://deps.rs/repo/github/hmunye/tcp/status.svg)](https://deps.rs/repo/github/hmunye/tcp)

## Features

- **RFC 793 State Machine**: Explicit entry points for `active` and `passive` 
connection setup, bidirectional data transfer, and termination/reset
- **Retransmission Logic**: Exponential backoff, per-segment timers, and a fixed 
retry limit
- **In-order Delivery**: Out-of-order segment buffering and payload reassembly
- **Flow Control**: Sliding send/receive windows, peer `MSS` negotiation, and 
zero-window probing
- **Wire-format Handling**: Serialization and deserialization of IPv4 headers, 
TCP headers, and TCP segments, including end-to-end checksum validation and 
limited support for TCP options (e.g, `MSS`)

## Quick Start

Add `tcp` to your project as a dependency:

```bash
cargo add --git https://github.com/hmunye/tcp.git tcp
```

Or in `Cargo.toml`:

```bash
[dependencies]
tcp = { git = "https://github.com/hmunye/tcp.git", version = "0.1.0" }
```

An example of the TCP implementation over a Linux `TUN` interface can be found 
[here](https://github.com/hmunye/tcp/tree/main/tcp-tun).

## License

This project is licensed under the [MIT License].

[MIT License]: https://github.com/hmunye/tcp/blob/main/LICENSE

## References
- [Jon Gjengset - Implementing TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [Assigned Numbers](https://www.rfc-editor.org/rfc/rfc1700)
- [Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323) 
- [Requirements for Internet Hosts -- Communication Layers](https://www.rfc-editor.org/rfc/rfc1122)
- [Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)
