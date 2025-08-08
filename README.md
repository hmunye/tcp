# tcp

TCP implementation in user-space, built for learning purposes, using the TUN/TAP interface.

> [!WARNING]
> Not suitable for production use.

This project is a minimal but functional TCP implementation written from scratch in Rust,
based primarily on [RFC 793](https://www.rfc-editor.org/rfc/rfc793). It supports enough of the 
protocol to interoperate with tools like [tshark](https://www.wireshark.org/docs/man-pages/tshark.html), 
[netcat](https://netcat.sourceforge.net/), and [hping3](https://www.kali.org/tools/hping3/) using 
raw packet I/O over a TUN interface.

## TOC

* [Features](#features)
* [Testing](#testing)
    * [Example Test: Out-of-Order Payload Handling](#example-test-out-of-order-payload-handling)
* [What's Not Included](#whats-not-included)
* [Quick Start](#quick-start)
* [References](#references)

## Features

- Full TCP state machine implemented (including SYN, FIN, and RST handling)

- Supports client and server connection establishment (3-way handshake)

- Graceful connection teardown and TIME-WAIT timer logic

- Full retransmission queue with exponential backoff and max-attempt handling

- Out-of-order segment buffering and in-order reassembly

- Window tracking: RCV.WND, SND.WND, and peer MSS

- `epoll`-driven event loop:
    - `timerfd` for retransmission and TIME-WAIT connection cleanup
    - `signal_fd` for clean shutdown
    - TUN device for packet I/O

- Manual parsing and construction of IPv4 and TCP headers (with checksum validation)

## Testing

Tested using:

- `netcat` for both inbound and outbound TCP connections
- `hping3` for crafting spoofed TCP packets
- `tshark` to inspect and validate sequence numbers, ACKs, flags, window sizes, etc.

Unit tests for parsing and serialization of headers can be run with:

```bash
cargo t
```

### Example Test: Out-of-Order Payload Handling

This test verifies that payloads from out-of-order segments are properly managed and reassembled in-order.

To ensure that RST segments are blocked before reaching the TUN interface and do not interfere with the test, 
use the following `iptables` rule:

```bash
sudo iptables -I OUTPUT 1 -d 10.0.0.2 -p tcp --tcp-flags RST RST -j DROP
```

This can be reverted using:

```bash
sudo iptables -D OUTPUT -d 10.0.0.2 -p tcp --tcp-flags RST RST -j DROP
```

Next, run the provided script:

```bash
./run.sh
```
> Requires root privileges. Review script code before execution.

(Optional) To monitor network traffic, run `tshark` in a separate terminal window:

```bash
tshark -i tun0
```
> User must be a member of the `wireshark` group to avoid needing `sudo`.

In another terminal window, use `netcat` to initiate a TCP connection:

```bash
nc -s 10.0.0.1 10.0.0.2 80
```
> Traffic must originate from `10.0.0.1`.

`tshark` Output:

```
1 0.000000000     10.0.0.1 → 10.0.0.2     TCP 60 37195 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2862074875 TSecr=0 WS=128
2 0.000094687     10.0.0.2 → 10.0.0.1     TCP 44 80 → 37195 [SYN, ACK] Seq=0 Ack=1 Win=4096 Len=0 MSS=1460
3 0.000108483     10.0.0.1 → 10.0.0.2     TCP 40 37195 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0
```

Program Logs:

```
[2025-08-08 14:29:49] INFO  [tcp] interface name: tun0
[2025-08-08 14:29:54] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 60, id: 20988, DF: true, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0xd4bd (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:29:54] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812292, ack num: 0, data offset: 10, urg: false, ack: false, psh: false, rst: false, syn: true, fin: false, window: 64240, chksum: 0xfbe8 (valid: true), mss: Some(1460)
[2025-08-08 14:29:54] DEBUG [tcp] received 0 bytes of payload: []
[2025-08-08 14:29:54] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (LISTEN) received SYN, sending SYN_ACK: LISTEN/PASSIVE_OPEN -> SYN_RECEIVED
[2025-08-08 14:29:54] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 40, id: 20989, DF: true, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0xd4d0 (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:29:54] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812293, ack num: 1, data offset: 5, urg: false, ack: true, psh: false, rst: false, syn: false, fin: false, window: 64240, chksum: 0xda4e (valid: true), mss: None
[2025-08-08 14:29:54] DEBUG [tcp] received 0 bytes of payload: []
[2025-08-08 14:29:54] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (SYN_RECEIVED) received valid ACK: SYN_RECEIVED -> ESTABLISHED
[2025-08-08 14:29:54] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) updated send window, new size: 64240
```

The following payloads will be sent:

- "first"

- " third" (sent out of order, but will be reassembled in-order)

- " second"

Send the first payload ("first") using `netcat`.

`tshark` Output:

```
4 223.001890145     10.0.0.1 → 10.0.0.2     TCP 46 37195 → 80 [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=6
5 223.001976927     10.0.0.2 → 10.0.0.1     TCP 40 80 → 37195 [ACK] Seq=1 Ack=7 Win=4090 Len=0
```

Program Logs:

```
[2025-08-08 14:33:37] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 46, id: 20990, DF: true, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0xd4c9 (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:33:37] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812293, ack num: 1, data offset: 5, urg: false, ack: true, psh: true, rst: false, syn: false, fin: false, window: 64240, chksum: 0x8d59 (valid: true), mss: None
[2025-08-08 14:33:37] DEBUG [tcp] received 6 bytes of payload: [66, 69, 72, 73, 74, a]
[2025-08-08 14:33:37] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received expected payload: buffering in-order
[2025-08-08 14:33:37] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received data: sending ACK
```

Use `hping3` to spoof an out-of-order segment containing the payload (" third"):

```bash
sudo hping3 10.0.0.2 --spoof 10.0.0.1 --baseport 37195 --destport 80 --setseq 2196812306 --setack 1 --win 64240 --ack --push --sign " third" -c 1
```

`tshark` Output:

```
6 470.260933279     10.0.0.1 → 10.0.0.2     TCP 46 [TCP Previous segment not captured] 37195 → 80 [PSH, ACK] Seq=14 Ack=1 Win=64240 Len=6
7 470.261027285     10.0.0.2 → 10.0.0.1     TCP 40 [TCP Dup ACK 5#1] 80 → 37195 [ACK] Seq=1 Ack=7 Win=4090 Len=0
```

Program Logs:

```
[2025-08-08 14:37:45] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 46, id: 47489, DF: false, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0xad46 (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:37:45] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812306, ack num: 1, data offset: 5, urg: false, ack: true, psh: true, rst: false, syn: false, fin: false, window: 64240, chksum: 0xdef1 (valid: true), mss: None
[2025-08-08 14:37:45] DEBUG [tcp] received 6 bytes of payload: [20, 74, 68, 69, 72, 64]
[2025-08-08 14:37:45] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received out-of-order payload: buffering out-of-order
[2025-08-08 14:37:45] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received data: sending ACK
```

Next, spoof another segment with the payload (" second"), using the actual expected sequence number:

```bash
sudo hping3 10.0.0.2 --spoof 10.0.0.1 --baseport 34915 --destport 80 --setseq 2785579383 --setack 1 --win 64240 --ack --push --sign " second" -c 1
```

`tshark` Output:

```
8 593.653984913     10.0.0.1 → 10.0.0.2     TCP 47 [TCP Retransmission] 37195 → 80 [PSH, ACK] Seq=7 Ack=1 Win=64240 Len=7
9 593.654069491     10.0.0.2 → 10.0.0.1     TCP 40 80 → 37195 [ACK] Seq=1 Ack=20 Win=4077 Len=0
```

Program Logs:

```
[2025-08-08 14:39:48] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 47, id: 54451, DF: false, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0x9213 (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:39:48] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812299, ack num: 1, data offset: 5, urg: false, ack: true, psh: true, rst: false, syn: false, fin: false, window: 64240, chksum: 0x80f4 (valid: true), mss: None
[2025-08-08 14:39:48] DEBUG [tcp] received 7 bytes of payload: [20, 73, 65, 63, 6f, 6e, 64]
[2025-08-08 14:39:48] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received expected payload: buffering in-order
[2025-08-08 14:39:48] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received data: sending ACK
```

Spoof a FIN segment to begin the graceful connection termination process:

```bash
sudo hping3 10.0.0.2 --spoof 10.0.0.1 --baseport 37195 --destport 80 --setseq 2196812312 --setack 1 --win 64240 --ack --fin -c 1
```

`tshark` Output (notice the retransmission of the FIN-ACK segment from the server):

```
10 788.034917929     10.0.0.1 → 10.0.0.2     TCP 40 37195 → 80 [FIN, ACK] Seq=20 Ack=1 Win=64240 Len=0
11 788.035000344     10.0.0.2 → 10.0.0.1     TCP 40 80 → 37195 [FIN, ACK] Seq=1 Ack=21 Win=4077 Len=0
12 790.029828075     10.0.0.2 → 10.0.0.1     TCP 40 [TCP Retransmission] 80 → 37195 [FIN, ACK] Seq=1 Ack=21 Win=4077 Len=0
13 792.030000728     10.0.0.2 → 10.0.0.1     TCP 40 [TCP Retransmission] 80 → 37195 [FIN, ACK] Seq=1 Ack=21 Win=4077 Len=0
14 796.030463433     10.0.0.2 → 10.0.0.1     TCP 40 [TCP Retransmission] 80 → 37195 [FIN, ACK] Seq=1 Ack=21 Win=4077 Len=0
```

Program Logs (notice the retransmission of the FIN-ACK segment from the server):

```
[2025-08-08 14:43:02] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 40, id: 53641, DF: false, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0x9544 (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:43:02] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812312, ack num: 1, data offset: 5, urg: false, ack: true, psh: false, rst: false, syn: false, fin: true, window: 64240, chksum: 0xda3a (valid: true), mss: None
[2025-08-08 14:43:02] DEBUG [tcp] received 0 bytes of payload: []
[2025-08-08 14:43:02] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (ESTABLISHED) received FIN: ESTABLISHED -> CLOSE_WAIT
[2025-08-08 14:43:02] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (CLOSE_WAIT) sending FIN_ACK: CLOSE_WAIT -> LAST_ACK
[2025-08-08 14:43:04] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (LAST_ACK) segment retransmitted, updated transmit count: 1
[2025-08-08 14:43:06] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (LAST_ACK) segment retransmitted, updated transmit count: 2
[2025-08-08 14:43:10] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (LAST_ACK) segment retransmitted, updated transmit count: 3
```

Finally, send the final ACK segment to close the connection:

```bash
sudo hping3 10.0.0.2 --spoof 10.0.0.1 --baseport 37195 --destport 80 --setseq 2196812313 --setack 2 --win 64240 --ack -c 1
```

`tshark` Output:

```
15 802.113876117     10.0.0.1 → 10.0.0.2     TCP 40 37195 → 80 [ACK] Seq=21 Ack=2 Win=64240 Len=0
```

Program Logs:

```
[2025-08-08 14:43:16] DEBUG [tcp] received ipv4 datagram | version: 4, ihl: 5, tos: 0, total_len: 40, id: 934, DF: false, MF: false, frag_offset: 0, ttl: 64, protocol: TCP, chksum: 0x6328 (valid: true), src: [10, 0, 0, 1], dst: [10, 0, 0, 2]
[2025-08-08 14:43:16] DEBUG [tcp] received tcp segment   | src port: 37195, dst port: 80, seq num: 2196812313, ack num: 2, data offset: 5, urg: false, ack: true, psh: false, rst: false, syn: false, fin: false, window: 64240, chksum: 0xda39 (valid: true), mss: None
[2025-08-08 14:43:16] DEBUG [tcp] received 0 bytes of payload: []
[2025-08-08 14:43:16] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (LAST_ACK) updated send window, new size: 64240
[2025-08-08 14:43:16] WARN  [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] (LASK_ACK) received ACK for FIN: LAST_ACK -> CLOSED
[2025-08-08 14:43:16] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] bytes received during connection lifetime: first\n second third
[2025-08-08 14:43:16] DEBUG [tcp] [10.0.0.2:80 -> 10.0.0.1:37195] removed connection, active connections remaining: 0
```

Although the payloads were sent out of order, the implementation successfully buffers and reorders them, 
displaying the expected in-order output:

```
first\n second third
```

## What's Not Included

This implementation is minimal by design, and omits many modern TCP features and interfaces including:

- Congestion control (slow start, fast retransmit, etc.)

- Selective Acknowledgment (SACK)

- Window Scaling

- Zero-window Probing

- TCP Fast Open

- Delayed ACKs

- TCP options besides MSS (though options parsing is stubbed in)

- User-facing API (read, write, connect, listen, etc.)

## Quick Start

Currently a Linux-only crate due to the use of:

- `epoll` for the event loop

- `/dev/net/tun` interface for raw IP traffic

Running the following script:

```bash
./run.sh
```
> Requires root privileges. Review script code before execution.

- Builds and runs the crate in release mode with the `CAP_NET_ADMIN` privilege as a background process

- Brings the `tun0` interface up

- Assigns the local IP address `10.0.0.1/32` to the TUN device with a peer address `10.0.0.2`

- Waits on the process to complete and cleans up on SIGINT and SIGTERM signals

You can now use `10.0.0.1` as the source address and `10.0.0.2` as the destination 
to establish or listen for connections.

Example:

```bash
curl --interface 10.0.0.1 http://10.0.0.2
```

## References
- [Jon Gjengset - Implementing TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
- [Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [Assigned Numbers](https://www.rfc-editor.org/rfc/rfc1700)
- [Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323) 
- [Requirements for Internet Hosts -- Communication Layers](https://www.rfc-editor.org/rfc/rfc1122)
- [Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)
