#!/bin/bash
# Test script for POA sync node - downloads blocks from 3 validators
# Usage: ./test_sync_node.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETH_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VALIDATOR_BINARY="$RETH_ROOT/target/release/poa_eth66"
SYNC_BINARY="$RETH_ROOT/target/release/poa_sync_node"

# Configuration
NUM_VALIDATORS=3
BASE_PORT=30303
SYNC_PORT=30400
BLOCK_TIME=5
VALIDATOR_RUN_TIME=30    # How long validators run before sync node joins
SYNC_RUN_TIME=30         # How long sync node runs

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "=========================================="
echo "POA Sync Node Test"
echo "Validators: $NUM_VALIDATORS"
echo "Block time: ${BLOCK_TIME}s"
echo "=========================================="

# Check if binaries exist
if [ ! -f "$VALIDATOR_BINARY" ]; then
    echo -e "${YELLOW}Validator binary not found. Building...${NC}"
    cd "$RETH_ROOT"
    cargo build --release -p example-custom-node-types --bin poa_eth66
fi

if [ ! -f "$SYNC_BINARY" ]; then
    echo -e "${YELLOW}Sync binary not found. Building...${NC}"
    cd "$RETH_ROOT"
    cargo build --release -p example-custom-node-types --bin poa_sync_node
fi

# Kill any existing instances
pkill -f poa_eth66 2>/dev/null || true
pkill -f poa_sync_node 2>/dev/null || true
sleep 1

# Create temp log directory
LOG_DIR="/tmp/poa_sync_test_$$"
mkdir -p "$LOG_DIR"
echo "Log directory: $LOG_DIR"

# Array to store PIDs
declare -a NODE_PIDS

# Start Validator 0 (bootstrap node)
echo ""
echo -e "${YELLOW}=== Phase 1: Starting Validators ===${NC}"
echo ""
echo -e "${CYAN}Starting Validator 0 on port $BASE_PORT...${NC}"
RUST_LOG="info" "$VALIDATOR_BINARY" \
    --port $BASE_PORT \
    --validator-index 0 \
    --block-time $BLOCK_TIME \
    > "$LOG_DIR/validator0.log" 2>&1 &
NODE_PIDS[0]=$!
echo "Validator 0 PID: ${NODE_PIDS[0]}"

# Wait for validator 0 to start
sleep 3

# Get enode from validator 0
ENODE=$(grep -o 'enode://[^ ]*' "$LOG_DIR/validator0.log" | head -1)
if [ -z "$ENODE" ]; then
    echo -e "${RED}Failed to get enode from Validator 0${NC}"
    cat "$LOG_DIR/validator0.log"
    kill ${NODE_PIDS[0]} 2>/dev/null
    exit 1
fi
echo "Validator 0 enode: $ENODE"

# Start remaining validators
for i in $(seq 1 $((NUM_VALIDATORS - 1))); do
    PORT=$((BASE_PORT + i))
    echo ""
    echo -e "${CYAN}Starting Validator $i on port $PORT...${NC}"
    RUST_LOG="info" "$VALIDATOR_BINARY" \
        --port $PORT \
        --validator-index $i \
        --block-time $BLOCK_TIME \
        --bootnode "$ENODE" \
        > "$LOG_DIR/validator$i.log" 2>&1 &
    NODE_PIDS[$i]=$!
    echo "Validator $i PID: ${NODE_PIDS[$i]}"
    sleep 1
done

# Wait for validators to produce some blocks
echo ""
echo -e "${YELLOW}=== Phase 2: Waiting for Validators to Produce Blocks ===${NC}"
echo "Waiting $VALIDATOR_RUN_TIME seconds for validators to produce blocks..."
echo ""

for i in $(seq 1 $VALIDATOR_RUN_TIME); do
    # Show progress
    if [ $((i % 5)) -eq 0 ]; then
        TOTAL_BLOCKS=0
        for v in $(seq 0 $((NUM_VALIDATORS - 1))); do
            BLOCKS=$(grep -c "Produced block" "$LOG_DIR/validator$v.log" 2>/dev/null || echo "0")
            TOTAL_BLOCKS=$((TOTAL_BLOCKS + BLOCKS))
        done
        echo "  [$i/$VALIDATOR_RUN_TIME] Total blocks produced: $TOTAL_BLOCKS"
    fi
    sleep 1
done

# Count blocks before sync
echo ""
echo -e "${BLUE}Blocks produced by validators before sync:${NC}"
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    BLOCKS=$(grep -c "Produced block" "$LOG_DIR/validator$i.log" 2>/dev/null || echo "0")
    echo "  Validator $i: $BLOCKS blocks"
done

# Start sync node
echo ""
echo -e "${YELLOW}=== Phase 3: Starting Sync Node ===${NC}"
echo ""
echo -e "${GREEN}Starting sync node on port $SYNC_PORT...${NC}"
RUST_LOG="info" "$SYNC_BINARY" \
    --port $SYNC_PORT \
    --block-time $BLOCK_TIME \
    --bootnode "$ENODE" \
    > "$LOG_DIR/sync_node.log" 2>&1 &
SYNC_PID=$!
echo "Sync node PID: $SYNC_PID"

# Wait for sync node to download blocks
echo ""
echo "Waiting $SYNC_RUN_TIME seconds for sync node to download blocks..."
echo ""

for i in $(seq 1 $SYNC_RUN_TIME); do
    if [ $((i % 5)) -eq 0 ]; then
        SYNCED=$(grep -c "Synced new block" "$LOG_DIR/sync_node.log" 2>/dev/null || echo "0")
        PEERS=$(grep "Connected to peer" "$LOG_DIR/sync_node.log" 2>/dev/null | wc -l || echo "0")
        echo "  [$i/$SYNC_RUN_TIME] Sync node: $SYNCED blocks synced, $PEERS peers"
    fi
    sleep 1
done

# Analyze results
echo ""
echo "=========================================="
echo -e "${BLUE}Test Results${NC}"
echo "=========================================="

# Validator stats
echo ""
echo -e "${BLUE}=== Validator Statistics ===${NC}"
TOTAL_PRODUCED=0
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    PRODUCED=$(grep -c "Produced block" "$LOG_DIR/validator$i.log" 2>/dev/null || echo "0")
    RECEIVED=$(grep -c "Received NewBlock" "$LOG_DIR/validator$i.log" 2>/dev/null || echo "0")
    echo "  Validator $i: produced=$PRODUCED, received=$RECEIVED"
    TOTAL_PRODUCED=$((TOTAL_PRODUCED + PRODUCED))
done

# Sync node stats
echo ""
echo -e "${BLUE}=== Sync Node Statistics ===${NC}"
SYNCED=$(grep -c "Synced new block" "$LOG_DIR/sync_node.log" 2>/dev/null || echo "0")
CONNECTED=$(grep "Connected to peer" "$LOG_DIR/sync_node.log" 2>/dev/null | wc -l || echo "0")
REJECTED=$(grep -c "validation failed" "$LOG_DIR/sync_node.log" 2>/dev/null || echo "0")

echo "  Peers connected: $CONNECTED"
echo "  Blocks synced: $SYNCED"
echo "  Blocks rejected: $REJECTED"

# Show last sync status
echo ""
echo -e "${BLUE}=== Last Sync Status ===${NC}"
grep "Sync status" "$LOG_DIR/sync_node.log" 2>/dev/null | tail -1 || echo "  No sync status available"

# Final verdict
echo ""
echo "=========================================="
if [ "$SYNCED" -gt 0 ] && [ "$REJECTED" -eq 0 ]; then
    echo -e "${GREEN}TEST PASSED!${NC}"
    echo "Sync node successfully downloaded $SYNCED blocks from validators."
    echo "Total blocks produced by validators: $TOTAL_PRODUCED"
elif [ "$SYNCED" -gt 0 ] && [ "$REJECTED" -gt 0 ]; then
    echo -e "${YELLOW}TEST PARTIAL SUCCESS${NC}"
    echo "Sync node downloaded $SYNCED blocks but rejected $REJECTED."
elif [ "$CONNECTED" -gt 0 ] && [ "$SYNCED" -eq 0 ]; then
    echo -e "${YELLOW}TEST PARTIAL SUCCESS${NC}"
    echo "Sync node connected to peers but didn't sync any new blocks."
    echo "This might be because validators produced blocks before sync node connected."
else
    echo -e "${RED}TEST FAILED!${NC}"
    if [ "$CONNECTED" -eq 0 ]; then
        echo "Sync node failed to connect to any validators."
    fi
fi
echo "=========================================="

# Show recent sync node activity
echo ""
echo -e "${YELLOW}Recent sync node activity:${NC}"
grep -E "Synced new block|Connected to peer|Sync status" "$LOG_DIR/sync_node.log" 2>/dev/null | tail -10

# Cleanup
echo ""
echo "Stopping all nodes..."
for pid in "${NODE_PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done
kill $SYNC_PID 2>/dev/null || true

echo ""
echo "Full logs available at: $LOG_DIR"
echo "  - Validators: $LOG_DIR/validator{0,1,2}.log"
echo "  - Sync node:  $LOG_DIR/sync_node.log"
echo ""
echo "To view sync progress:"
echo "  grep 'Synced new block' $LOG_DIR/sync_node.log"
