//    use std::io::Write;
//    use tcp::net::protocol::fsm::SocketAddr;
use std::collections::HashMap;

use tcp::net::protocol::event_loop;
use tcp::net::protocol::fsm::{Socket, TCB};
use tcp::tun_tap::tun;
use tcp::{Result, info};

fn main() -> Result<()> {
    let mut nic = tun::Tun::without_packet_info("tun0")?;
    nic.set_non_blocking()?;

    let mut connections: HashMap<Socket, TCB> = Default::default();

    info!("interface name: {}", nic.name());

    // For acting as the client...

    //    info!("press (enter) to continue...");
    //    std::io::stdout().flush()?;
    //    let mut buf = String::new();
    //    std::io::stdin().read_line(&mut buf)?;
    //    drop(buf);
    //
    //    let socket = Socket {
    //        src: SocketAddr {
    //            addr: [10, 0, 0, 2],
    //            port: 34567,
    //        },
    //        dst: SocketAddr {
    //            addr: [10, 0, 0, 1],
    //            port: 12345,
    //        },
    //    };
    //
    //    let conn = TCB::on_conn_init(&mut nic, socket)?;
    //
    //    connections.insert(socket, conn);

    event_loop::packet_loop(&mut nic, &mut connections)?;

    Ok(())
}
