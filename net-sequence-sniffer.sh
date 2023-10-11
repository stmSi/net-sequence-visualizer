#!/bin/bash

# Run cargo build
cargo build

# Check if cargo build was successful
if [ $? -eq 0 ]; then
  # Define the path to the built binary
  netbin=~/.cargo/target_build_dir/debug/net-sequence-sniffer
  
  # Run the built binary with sudo
  sudo $netbin
fi
