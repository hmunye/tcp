#!/usr/bin/env bash

set -euo pipefail

# Compile library into `.wasm` binary
cargo b --target wasm32-unknown-unknown --release

# Runs `wasm-bindgen` to generate JavaScript bindings
wasm-bindgen ../target/wasm32-unknown-unknown/release/tcp_wasm.wasm \
  --out-dir ./frontend/pkg \
  --out-name tcp_wasm \
  --target web \
  --remove-name-section \
  --remove-producers-section
