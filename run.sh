#!/usr/bin/env bash

set -euo pipefail

cargo b --release

# CAP_NET_ADMIN is required for creating network devices or for connecting to 
# network devices which are not owned by the user.
#
# Flags:
#
# `p` (permitted) adds the capability to the permitted set.
# `e` (effective) makes the capability active when the process starts.
sudo setcap CAP_NET_ADMIN=ep target/release/tcp
target/release/tcp &
pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap "kill $pid" INT TERM

wait $pid
