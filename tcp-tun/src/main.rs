#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2018_idioms)]
#![warn(missing_debug_implementations)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::use_self)]
#![allow(clippy::redundant_else)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::unused_self)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::single_match_else)]

mod tun;

#[cfg(not(target_os = "linux"))]
compile_error!("tcp-tun requires a platform with `/dev/net/tun` (Linux)");

use std::collections::HashMap;

use rio::io::AsyncReadExt;
use tcp::protocol::TCB;
use tcp::{Result, SocketV4};

#[rio::main]
async fn main() -> Result<()> {
    let mut nic = tun::TUN::without_packet_info()?;
    nic.set_non_blocking()?;

    let mut _connections: HashMap<SocketV4, TCB> = HashMap::default();

    let mut buf = [0u8; tun::MTU_SIZE];

    let n = nic.read(&mut buf).await?;
    println!("read: {:?}", &buf[..n]);

    Ok(())
}
