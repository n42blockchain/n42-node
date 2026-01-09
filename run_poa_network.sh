#!/bin/bash
#
# POA Network Launcher
# Starts 3 POA validator nodes for demonstration
#
# Usage:
#   ./run_poa_network.sh          # Run all 3 nodes in separate terminals
#   ./run_poa_network.sh node0    # Run only node 0
#   ./run_poa_network.sh node1    # Run only node 1
#   ./run_poa_network.sh node2    # Run only node 2

set -e

# Build first
#echo "Building poa_node..."
#cargo build -p example-custom-node-types --bin poa_node --release 2>/dev/null || \
#cargo build -p example-custom-node-types --bin poa_node

BIN="./poa_node"

# Shared genesis time (10 seconds from now)
GENESIS=$(($(date +%s) + 10))

# Validator addresses
V0="0x0101010101010101010101010101010101010101"
V1="0x0202020202020202020202020202020202020202"
V2="0x0303030303030303030303030303030303030303"

# Ports
P0=30303
P1=30304
P2=30305

run_node0() {
    echo "Starting Node 0 (V0)..."
    echo "  Port: $P0"
    echo "  Coinbase: $V0"
    echo ""
    $BIN --port $P0 --coinbase $V0 --genesis-time $GENESIS
}

run_node1() {
    echo "Starting Node 1 (V1)..."
    echo "  Port: $P1"
    echo "  Coinbase: $V1"
    echo "  Bootnode: 127.0.0.1:$P0"
    echo ""
    $BIN --port $P1 --coinbase $V1 --genesis-time $GENESIS --bootnode "127.0.0.1:$P0"
}

run_node2() {
    echo "Starting Node 2 (V2)..."
    echo "  Port: $P2"
    echo "  Coinbase: $V2"
    echo "  Bootnode: 127.0.0.1:$P0"
    echo ""
    $BIN --port $P2 --coinbase $V2 --genesis-time $GENESIS --bootnode "127.0.0.1:$P0"
}

case "${1:-all}" in
    node0)
        run_node0
        ;;
    node1)
        run_node1
        ;;
    node2)
        run_node2
        ;;
    all)
        echo "=== POA Network Launcher ==="
        echo ""
        echo "Genesis time: $GENESIS (in 10 seconds)"
        echo ""
        echo "To run all 3 nodes, open 3 terminals and run:"
        echo ""
        echo "  Terminal 1: $0 node0"
        echo "  Terminal 2: $0 node1"
        echo "  Terminal 3: $0 node2"
        echo ""
        echo "Or use the following commands directly:"
        echo ""
        echo "  # Terminal 1 - Node 0 (validator V0)"
        echo "  $BIN -p $P0 -c $V0 -g $GENESIS"
        echo ""
        echo "  # Terminal 2 - Node 1 (validator V1)"
        echo "  $BIN -p $P1 -c $V1 -g $GENESIS -b 127.0.0.1:$P0"
        echo ""
        echo "  # Terminal 3 - Node 2 (validator V2)"
        echo "  $BIN -p $P2 -c $V2 -g $GENESIS -b 127.0.0.1:$P0"
        echo ""
        ;;
    *)
        echo "Usage: $0 [node0|node1|node2|all]"
        exit 1
        ;;
esac
