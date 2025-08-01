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

if [ -z "${CLIENT-}" ]; then
    target/release/tcp < /dev/tty &
else
    CLIENT=$CLIENT target/release/tcp < /dev/tty &
fi

pid=$!

# Sets up a point-to-point connection between 10.0.0.1 and 10.0.0.2. The /32 
# subnet mask isolates these two endpoints, allowing direct communication 
# between them while preventing connections to or from other hosts. 10.0.0.1 is 
# the locally assigned IP address, meaning any process can bind to it.
sudo ip link set dev tun0 up
sudo ip addr add 10.0.0.1/32 peer 10.0.0.2 dev tun0

if [ -n "${CLIENT-}" ]; then
    # Listening server (netcat).
    nc -l -s 10.0.0.1 -p 8080 &
fi

trap "kill $pid" INT TERM

wait $pid
