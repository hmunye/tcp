#!/usr/bin/env bash

set -euo pipefail

BINARY="../target/release/tcp-tun"

trap "sudo ip tuntap del dev tun0 mode tun 2>/dev/null || true" EXIT

cargo build --release

# CAP_NET_ADMIN is required for creating network devices or for connecting to 
# network devices which are not owned by the user.
#
# Flags:
#
# `e` (effective): makes the capability active when the process starts.
# `p` (permitted): adds the capability to the permitted set.
sudo setcap CAP_NET_ADMIN=ep "$BINARY"

sudo ip tuntap add dev tun0 mode tun

# Brings up the TUN interface and assigns a local IP address.
#
# The /32 mask creates a single-host interface, with no subnet routing. 10.0.0.1 
# is the address the server binds to and receives traffic on.
sudo ip link set dev tun0 up
sudo ip addr add 10.0.0.1/32 dev tun0

echo "[tcp-tun]: listening on 10.0.0.1"

"$BINARY"
