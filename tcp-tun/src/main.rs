use tcp_core::Result;
use tcp_core::protocol::fsm::TCB;
use tcp_core::protocol::socket::Socket;

use std::collections::HashMap;

use tcp_tun::net::event_loop;
use tcp_tun::tun_tap::tun;

fn main() -> Result<()> {
    let mut nic = tun::Tun::without_packet_info()?;
    nic.set_non_blocking()?;

    let mut conns: HashMap<Socket, TCB> = Default::default();

    event_loop(&mut nic, &mut conns)?;

    Ok(())
}
