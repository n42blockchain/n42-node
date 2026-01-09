#!/bin/bash
# Test script for POA eth66 block propagation with 3 nodes
# Usage: ./test_poa_eth66.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETH_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$RETH_ROOT/target/release/poa_eth66"

# Configuration
NUM_NODES=3
BASE_PORT=30303
BLOCK_TIME=5
WAIT_TIME=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "POA eth66 Block Propagation Test"
echo "Number of nodes: $NUM_NODES"
echo "=========================================="

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${YELLOW}Binary not found. Building...${NC}"
    cd "$RETH_ROOT"
    cargo build --release --bin poa_eth66
fi

# Kill any existing instances
pkill -f poa_eth66 2>/dev/null || true
sleep 1

# Create temp log directory
LOG_DIR="/tmp/poa_eth66_test_$$"
mkdir -p "$LOG_DIR"
echo "Log directory: $LOG_DIR"

# Array to store PIDs
declare -a NODE_PIDS

# Start Node 0 (bootstrap node)
echo ""
echo -e "${YELLOW}Starting Node 0 (Validator 0) on port $BASE_PORT...${NC}"
RUST_LOG="info" "$BINARY" \
    --port $BASE_PORT \
    --validator-index 0 \
    --block-time $BLOCK_TIME \
    > "$LOG_DIR/node0.log" 2>&1 &
NODE_PIDS[0]=$!
echo "Node 0 PID: ${NODE_PIDS[0]}"

# Wait for node 0 to start
sleep 3

# Get enode from node 0
ENODE=$(grep -o 'enode://[^ ]*' "$LOG_DIR/node0.log" | head -1)
if [ -z "$ENODE" ]; then
    echo -e "${RED}Failed to get enode from Node 0${NC}"
    cat "$LOG_DIR/node0.log"
    kill ${NODE_PIDS[0]} 2>/dev/null
    exit 1
fi
echo "Node 0 enode: $ENODE"

# Start remaining nodes
for i in $(seq 1 $((NUM_NODES - 1))); do
    PORT=$((BASE_PORT + i))
    echo ""
    echo -e "${YELLOW}Starting Node $i (Validator $i) on port $PORT...${NC}"
    RUST_LOG="info" "$BINARY" \
        --port $PORT \
        --validator-index $i \
        --block-time $BLOCK_TIME \
        --bootnode "$ENODE" \
        > "$LOG_DIR/node$i.log" 2>&1 &
    NODE_PIDS[$i]=$!
    echo "Node $i PID: ${NODE_PIDS[$i]}"
    sleep 1
done

# Wait for connection and block exchange
echo ""
echo -e "${YELLOW}Waiting $WAIT_TIME seconds for nodes to connect and exchange blocks...${NC}"
for i in $(seq 1 $WAIT_TIME); do
    echo -n "."
    sleep 1
done
echo ""

# Analyze results
echo ""
echo "=========================================="
echo "Test Results"
echo "=========================================="

# Check peer connections
echo ""
echo -e "${BLUE}=== Peer Connections ===${NC}"
TOTAL_PEERS=0
for i in $(seq 0 $((NUM_NODES - 1))); do
    PEERS=$(grep -c "Peer connected" "$LOG_DIR/node$i.log" 2>/dev/null || echo "0")
    echo "  Node $i connected peers: $PEERS"
    TOTAL_PEERS=$((TOTAL_PEERS + PEERS))
done

# Check block broadcasts
echo ""
echo -e "${BLUE}=== Block Broadcasts ===${NC}"
TOTAL_BROADCASTS=0
for i in $(seq 0 $((NUM_NODES - 1))); do
    BROADCASTS=$(grep -c "Broadcasting block via eth66" "$LOG_DIR/node$i.log" 2>/dev/null || echo "0")
    echo "  Node $i broadcasts: $BROADCASTS"
    TOTAL_BROADCASTS=$((TOTAL_BROADCASTS + BROADCASTS))
done

# Check block receives
echo ""
echo -e "${BLUE}=== Block Receives ===${NC}"
TOTAL_RECEIVES=0
NODES_WITH_RECEIVES=0
for i in $(seq 0 $((NUM_NODES - 1))); do
    RECEIVES=$(grep -c "Received NewBlock via eth66" "$LOG_DIR/node$i.log" 2>/dev/null || echo "0")
    echo "  Node $i received: $RECEIVES blocks"
    TOTAL_RECEIVES=$((TOTAL_RECEIVES + RECEIVES))
    if [ "$RECEIVES" -gt 0 ]; then
        NODES_WITH_RECEIVES=$((NODES_WITH_RECEIVES + 1))
    fi
done

# Check for decode errors
echo ""
echo -e "${BLUE}=== Decode Errors ===${NC}"
DECODE_ERRORS=0
for i in $(seq 0 $((NUM_NODES - 1))); do
    ERRORS=$(grep -c "failed to decode" "$LOG_DIR/node$i.log" 2>/dev/null || echo "0")
    if [ "$ERRORS" -gt 0 ]; then
        echo -e "  ${RED}Node $i: $ERRORS errors${NC}"
        DECODE_ERRORS=$((DECODE_ERRORS + ERRORS))
    fi
done
if [ "$DECODE_ERRORS" -eq 0 ]; then
    echo -e "  ${GREEN}No decode errors${NC}"
fi

# Summary
echo ""
echo "=========================================="
echo -e "${BLUE}Summary${NC}"
echo "=========================================="
echo "  Total peer connections: $TOTAL_PEERS"
echo "  Total blocks broadcast: $TOTAL_BROADCASTS"
echo "  Total blocks received: $TOTAL_RECEIVES"
echo "  Nodes receiving blocks: $NODES_WITH_RECEIVES / $NUM_NODES"
echo "  Decode errors: $DECODE_ERRORS"

# Final verdict
echo ""
echo "=========================================="
if [ "$NODES_WITH_RECEIVES" -ge $((NUM_NODES - 1)) ] && [ "$DECODE_ERRORS" -eq 0 ]; then
    echo -e "${GREEN}TEST PASSED!${NC}"
    echo "All nodes successfully exchanged blocks via eth66 protocol."
elif [ "$NODES_WITH_RECEIVES" -gt 0 ] && [ "$DECODE_ERRORS" -eq 0 ]; then
    echo -e "${YELLOW}TEST PARTIAL SUCCESS${NC}"
    echo "$NODES_WITH_RECEIVES out of $NUM_NODES nodes received blocks."
else
    echo -e "${RED}TEST FAILED!${NC}"
    if [ "$NODES_WITH_RECEIVES" -eq 0 ]; then
        echo "No block propagation occurred."
    fi
    if [ "$DECODE_ERRORS" -gt 0 ]; then
        echo "RLP decode errors occurred."
    fi
fi
echo "=========================================="

# Show recent activity from each node
echo ""
echo -e "${YELLOW}Recent activity from each node:${NC}"
for i in $(seq 0 $((NUM_NODES - 1))); do
    echo ""
    echo -e "${BLUE}--- Node $i ---${NC}"
    grep -E "Broadcasting block|Received NewBlock|Peer connected" "$LOG_DIR/node$i.log" 2>/dev/null | tail -5
done

# Cleanup
echo ""
echo "Stopping nodes..."
for pid in "${NODE_PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

echo ""
echo "Full logs available at: $LOG_DIR"
for i in $(seq 0 $((NUM_NODES - 1))); do
    echo "  - Node $i: $LOG_DIR/node$i.log"
done
