use std::collections::HashMap;

use tcp_core::protocol::fsm::{Socket, TCB};
use tcp_core::{Result, info};

use tcp_tun::net::event_loop;
use tcp_tun::tun_tap::tun;

fn main() -> Result<()> {
    let mut nic = tun::Tun::without_packet_info("tun0")?;
    nic.set_non_blocking()?;

    let mut connections: HashMap<Socket, TCB> = Default::default();

    info!("interface name: {}", nic.name());

    event_loop::packet_loop(&mut nic, &mut connections)?;

    Ok(())
}
