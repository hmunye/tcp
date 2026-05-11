#[cfg(not(target_os = "linux"))]
compile_error!("tcp-tun requires a platform with `/dev/net/tun` (Linux)");

#[rio::main]
async fn main() {
    println!("hello, world");
}
