# hping3 Testing Reference

## Traffic Monitoring

Capture TCP traffic on `tun0`:

```bash
tshark -i tun0 -f "tcp and host 10.0.0.1" -P -x
```

## Preventing TCP RST Injection

`hping3` may emit TCP RST packets when terminating. To prevent this behavior, 
drop outbound RST packets to the server (`10.0.0.1`):

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 10.0.0.1 -j DROP
```

To remove the rule:

```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -d 10.0.0.1 -j DROP
```

## 1. Basic SYN / Retransmission Behavior

Verify server-side SYN handling and retransmission logic when no handshake 
completion occurs.

```bash
sudo hping3 -c 1 -S -p 80 10.0.0.1
```

Expected behavior:

- Server responds with SYN+ACK
- No final ACK is received
- Server performs repeated retransmissions of SYN+ACK before closing the connection

## 2. Out-of-Order Data Delivery and Reassembly

Validate out-of-order buffering, in-order reassembly, and correct ACK progression 
after reassembly with the target payload `hello from hping3` split into three 
segments: "hello " (bytes 1–6), "from" (bytes 7–10), and " hping3" (bytes 11–18).

Step 1: Complete the TCP handshake (SYN, SYN+ACK, ACK)

```bash
# Send SYN
sudo hping3 -c 1 -s 51623 --win 512 -S --setseq 0 -p 80 10.0.0.1

# Send ACK
sudo hping3 -c 1 \
    -s 51623 \
    -A \
    --win 512 \
    --setseq 1 \
    --setack <iss + 1> \
    -p 80 10.0.0.1
```

Step 2: Send last fragment (out-of-order)

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A -P \
    --win 512 \
    --setseq 11 \
    --setack <base_ack_num> \
    --sign " hping3" \
    -p 80 10.0.0.1
```

Step 3: Send the middle fragment

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A -P \
    --win 512 \
    --setseq 7 \
    --setack <base_ack_num> \
    --sign "from" \
    -p 80 10.0.0.1
```

Step 4: Send first fragment

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A -P \
    --win 512 \
    --setseq 1 \
    --setack <base_ack_num> \
    --sign "hello " \
    -p 80 10.0.0.1
```

Expected behavior:

- Out-of-order segments are buffered
- `rcv.nxt` does not advance until missing data arrives
- Data is reassembled and server delivers `hello from hping3`

Step 5: ACK final reassembled data

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A \
    --win 512 \
    --setseq 18 \
    --setack <base_ack_num + 17> \
    -p 80 10.0.0.1
```

## 3. Zero-Window Probing (Flow Control Stall and Recovery)

Verify the server stalls when peer advertises zero window, buffers application 
data correctly, transmits zero-window probes, and resumes transmission when 
peer window opens.

Step 1: Complete the TCP handshake (SYN, SYN+ACK, ACK)

```bash
# Send SYN
sudo hping3 -c 1 -s 51623 --win 512 -S --setseq 0 -p 80 10.0.0.1

# Send ACK
sudo hping3 -c 1 \
    -s 51623 \
    -A \
    --win 512 \
    --setseq 1 \
    --setack <iss + 1> \
    -p 80 10.0.0.1
```

Step 2: Advertise zero window (stall server)

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A -P \
    --win 0 \
    --setseq 1 \
    --setack <base_ack_num> \
    --sign "hello" \
    -p 80 10.0.0.1
```

Step 3: Transmit additional data (forces probe scheduling)

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A -P \
    --win 0 \
    --setseq 6 \
    --setack <base_ack_num> \
    --sign ", world" \
    -p 80 10.0.0.1
```

Step 4: Window update (probe ACK/recovery)

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A \
    --win 64240 \
    --setseq 13 \
    --setack <base_ack_num + 1> \
    -p 80 10.0.0.1
```

Step 5: Final ACK of delivered data

```bash
sudo hping3 -c 1 \
    -s 51623 \
    -A \
    --win 512 \
    --setseq 18 \
    --setack <base_ack_num + 12> \
    -p 80 10.0.0.1
```

Expected behavior:

- Out-of-order segments buffered without advancing `rcv.nxt` and reassembled only 
when contiguous data is available
- Server does not transmit application data with zero-window and issues zero-window 
probes until window update arrives
- Window update triggers a flush of buffered application data
