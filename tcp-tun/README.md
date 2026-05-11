# tcp-tun

Linux-only echo server built with a user-space [TCP](https://github.com/hmunye/tcp/tree/main/tcp)
stack over a TUN interface.

## Quick Start

This is Linux-only due to its dependency on:

- **`/dev/net/tun`** for handling raw IP network traffic

To build the binary, configure the TUN interface, and run the server:

```bash
./run.sh
```
> Note: `root` privileges are required for network configuration steps.

The script will:

- Compile the crate in release mode
- Grant `CAP_NET_ADMIN` privileges to the binary
- Create a TUN device (`tun0`)
- Assign the local IP `10.0.0.1/32`

`tun0` interface is automatically deleted when the script exits.

## License

This project is licensed under the [MIT License].

[MIT License]: https://github.com/hmunye/tcp/blob/main/LICENSE

## References
- [Universal TUN/TAP Device Driver](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
