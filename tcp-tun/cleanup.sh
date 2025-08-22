#!/usr/bin/env bash

set -euo pipefail

# Removes `tun0` interface and its associated configuration.
sudo ip tuntap del dev tun0 mode tun
