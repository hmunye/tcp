# tcp

TCP implementation in user-space designed for learning purposes, using the 
TUN/TAP interface.

## Features

## Testing

Testing is done through a combination of unit tests and manual integration 
tests to validate the correctness of both header parsing and core protocol logic.

### Unit Tests

Unit tests cover the parsing and serialization of IPv4 and TCP headers and can 
be run with the following command:

```bash
cargo t
```

### Manual and Integration Testing

Stateful protocol logic (e.g., the TCP three-way handshake, FIN/ACK flows, etc.) 
is tested manually using [tshark](https://www.wireshark.org/docs/man-pages/tshark.html), [netcat](https://netcat.sourceforge.net/), and [hping3](https://www.kali.org/tools/hping3/).
These tools allows for the observation and manipulation of packets during live 
TCP connections.

#### Example Commands

Capture packets from the TUN interface (`tun0`) using `tshark`:

```bash
tshark -i tun0
```
> To run without `sudo`, add your user to the `wireshark` group.


Initiating a TCP connection using `netcat`:

```bash
nc -s 10.0.0.1 10.0.0.2 443
```

Inject a spoofed FIN-ACK segment using `hping3`:

```bash
sudo hping3 10.0.0.2 \
  --spoof 10.0.0.1 \
  --destport 443 \
  --baseport <client_port> \
  --setseq <RCV.NXT> \
  --setack <SND.NXT> \
  --win <SND.WND> \
  --ack --fin -c 1
```

#### Preventing Interference from Kernel RST Packets

To suppress any RST segments that may be sent by the kernel and prevent them 
from interfering with testing:

```bash
sudo iptables -I OUTPUT 1 -d <destination> -p tcp --tcp-flags RST RST -j DROP
```
> This rule drops any outgoing TCP packet with the RST flag set destined for <destination>.

To revert it, use:

```bash
sudo iptables -D OUTPUT -d <destination> -p tcp --tcp-flags RST RST -j DROP
```

## References
- [Jon Gjengset - Implementing TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA)
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
- [Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [Assigned Numbers](https://www.rfc-editor.org/rfc/rfc1700)
- [Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323) 
- [Requirements for Internet Hosts -- Communication Layers](https://www.rfc-editor.org/rfc/rfc1122)
