use std::collections::HashMap;
use std::process;

use tcp::net::{Socket, TCB};
use tcp::tun_tap;
use tcp::{error, info};

fn main() {
    let mut nic = tun_tap::Tun::without_packet_info("tun0").unwrap_or_else(|err| {
        error!("failed to create TUN interface: {err}");
        process::exit(1);
    });

    info!("interface name: {}", nic.name());

    nic.set_non_blocking().unwrap_or_else(|err| {
        error!("failed to set TUN to non-blocking: {err}");
        process::exit(1);
    });

    let mut connections: HashMap<Socket, TCB> = Default::default();

    tcp::net::packet_loop(&mut nic, &mut connections).unwrap_or_else(|err| {
        error!("packet loop failed: {err}");
        process::exit(1);
    });
}
