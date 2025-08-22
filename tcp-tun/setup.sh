#!/usr/bin/env bash

set -euo pipefail

# Debug builds will include logs.
if [[ "${DEBUG:-0}" == "1" ]]; then
    BUILD_MODE="debug"
else
    BUILD_MODE="release"
fi

cargo b $( [[ "${BUILD_MODE}" == "debug" ]] && echo "" || echo "--release" )

# CAP_NET_ADMIN is required for creating network devices or for connecting to 
# network devices which are not owned by the user.
#
# Flags:
#
# `p` (permitted) adds the capability to the permitted set.
# `e` (effective) makes the capability active when the process starts.
sudo setcap CAP_NET_ADMIN=ep ../target/$BUILD_MODE/tcp-tun

sudo ip tuntap add mode tun tun0

# Sets up a point-to-point connection between 10.0.0.1 and 10.0.0.2. The /32 
# subnet mask isolates these two endpoints, allowing for direct communication 
# between them while preventing connections from other hosts. 10.0.0.1 is the 
# locally assigned IP address processes can bind to.
sudo ip link set dev tun0 up
sudo ip addr add 10.0.0.1/32 peer 10.0.0.2 dev tun0
