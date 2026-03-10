#!/bin/bash

# Lightning Onion Packet Visualizer - Web Server Launcher
# Usage: ./run.sh [--port PORT]

PORT=${1:-3000}

if [ "$1" == "--port" ] && [ -n "$2" ]; then
    PORT=$2
fi

cwd=$(pwd)
final_path=$cwd"/backend/Cargo.toml"
cargo run --manifest-path $final_path -- --web --port $PORT
