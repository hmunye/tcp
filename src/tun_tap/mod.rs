//! TUN/TAP provides packet reception and transmission for user space programs.
//!
//! It can be seen as a simple Point-to-Point or Ethernet device, which, instead
//! of receiving packets from physical media, receives them from the user space
//! program and instead of sending packets via physical media writes them to the
//! user space program.

pub mod tun;
