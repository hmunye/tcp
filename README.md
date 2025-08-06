# tcp

TCP implementation in user-space designed for learning purposes, using the 
TUN/TAP interface.

> [!WARNING]
> Not suitable for production use.

## Features

- IPv4 Header Parsing
    - Full support for IPv4 headers (excluding options, per [RFC 791](https://www.rfc-editor.org/rfc/rfc791))
    - Header checksum validation

- TCP Header Parsing
    - Full support for TCP headers (parses TCP options but only detects MSS option, per [RFC 793](https://www.rfc-editor.org/rfc/rfc793))
    - Checksum validation

- Full TCP Finite State Machine
    - All connection states per [RFC 793](https://www.rfc-editor.org/rfc/rfc793)
    - SYN, SYN-ACK, ACK, FIN, and RST handling
    - Connection establishment, teardown, and reset

- Receive Buffer and Segment Management
    - Correct handling of expected and old/duplicate segments
    - Out-of-window segments handled 
    - Data is reassembled in order without duplicates

- Send Buffer and Retransmission Queue
    - Timer-based retransmission using `timerfd`
    - Exponential backoff and max retry logic
    - Retransmission for SYN, SYN-ACK, data segments, and FIN

- TIME-WAIT Handling
    - Track connections in TIME-WAIT state using `timerfd`

- Logging/Tracing
    - Basic logging module with severity levels
    - Logging all state transitions and incoming segment details

- Event Loop
    - Uses `epoll` for multiplexing I/O
    - Timer, socket, and signal events monitored for readiness

## Testing

Testing combines unit tests for header parsing with manual integration tests for
protocol behavior. The goal is to verify protocol correctness at the packet and 
state machine levels.

### Unit Tests

Unit tests validate serialization and parsing logic for both IPv4 and TCP 
(including options) headers.

Run all unit tests with:

```bash
cargo t
```

### Manual Testing

Manual tests validate the full TCP implementation under more realistic scenarios,
including connection establishment, teardown, retransmission, segment reordering,
timeout, and malformed packets. 

Tools used include:

- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [netcat](https://netcat.sourceforge.net/)
- [hping3](https://www.kali.org/tools/hping3/).

## References
- [Jon Gjengset - Implementing TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
- [Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [Assigned Numbers](https://www.rfc-editor.org/rfc/rfc1700)
- [Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323) 
- [Requirements for Internet Hosts -- Communication Layers](https://www.rfc-editor.org/rfc/rfc1122)
- [Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)
