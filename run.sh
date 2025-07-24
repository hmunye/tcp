#!/usr/bin/env bash

set -euo pipefail

cargo b --release

# CAP_NET_ADMIN is required for creating network devices or for connecting to 
# network devices which aren’t owned by the user.
sudo setcap CAP_NET_ADMIN=eip target/release/tcp
target/release/tcp &
pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap "kill $pid" INT TERM

wait $pid
