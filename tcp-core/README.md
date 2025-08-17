# tcp-core

A minimal, third-party-free implementation of the Transmission Control Protocol (TCP), based on
[RFC 793](https://www.rfc-editor.org/rfc/rfc793).

> [!WARNING]  
> This project is experimental and not intended for production use.

## TOC
* [Features](#features)
* [Testing](#testing)
* [Limitations](#limitations)
* [License](#license)
* [References](#references)

## Features

- Full TCP connection lifecycle: initiation (SYN), termination (FIN), and reset (RST)
- Bidirectional connection establishment
- TIME-WAIT state handling
- Retransmission tracking with exponential backoff and retry limit
- Out-of-order segment reordering and payload reassembly
- Flow control via SND/RCV windows and peer MSS
- Raw IPv4/TCP header parsing and construction with checksum validation

## Testing

Run unit tests for IPv4/TCP header parsing/serialization and state machine logic with:

```bash
cargo t
```

## Limitations

This implementation currently omits several features and behaviors, including:

- Assumes IP packets are fully reassembled (no handling of IP fragmentation)
- No congestion control algorithms (e.g., slow start, fast retransmit)
- No support for Selective Acknowledgment (SACK)
- No window scaling
- TCP Fast Open is not implemented
- No delayed acknowledgments
- IPv4 options are not supported
- Only MSS is supported in TCP options (others are ignored; parser is stubbed)

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
