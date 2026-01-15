#
# POA Network Launcher (Windows PowerShell)
# Starts 3 POA validator nodes for demonstration
#
# Usage:
#   .\run_poa_network.ps1          # Show instructions for all 3 nodes
#   .\run_poa_network.ps1 node0    # Run only node 0
#   .\run_poa_network.ps1 node1    # Run only node 1
#   .\run_poa_network.ps1 node2    # Run only node 2
#

param(
    [string]$NodeType = "all"
)

$ErrorActionPreference = "Stop"

$BIN = ".\target\release\poa_node.exe"

# Check if binary exists
if (-not (Test-Path $BIN)) {
    $BIN = ".\target\debug\poa_node.exe"
    if (-not (Test-Path $BIN)) {
        Write-Host "Binary not found. Building..." -ForegroundColor Yellow
        cargo build --release --bin poa_node
        $BIN = ".\target\release\poa_node.exe"
    }
}

# Shared genesis time (10 seconds from now)
$GENESIS = [int][double]::Parse((Get-Date -UFormat %s)) + 10

# Validator addresses
$V0 = "0x0101010101010101010101010101010101010101"
$V1 = "0x0202020202020202020202020202020202020202"
$V2 = "0x0303030303030303030303030303030303030303"

# Ports
$P0 = 30303
$P1 = 30304
$P2 = 30305

function Run-Node0 {
    Write-Host "Starting Node 0 (V0)..." -ForegroundColor Green
    Write-Host "  Port: $P0"
    Write-Host "  Coinbase: $V0"
    Write-Host ""
    & $BIN --port $P0 --coinbase $V0 --genesis-time $GENESIS
}

function Run-Node1 {
    Write-Host "Starting Node 1 (V1)..." -ForegroundColor Green
    Write-Host "  Port: $P1"
    Write-Host "  Coinbase: $V1"
    Write-Host "  Bootnode: 127.0.0.1:$P0"
    Write-Host ""
    & $BIN --port $P1 --coinbase $V1 --genesis-time $GENESIS --bootnode "127.0.0.1:$P0"
}

function Run-Node2 {
    Write-Host "Starting Node 2 (V2)..." -ForegroundColor Green
    Write-Host "  Port: $P2"
    Write-Host "  Coinbase: $V2"
    Write-Host "  Bootnode: 127.0.0.1:$P0"
    Write-Host ""
    & $BIN --port $P2 --coinbase $V2 --genesis-time $GENESIS --bootnode "127.0.0.1:$P0"
}

switch ($NodeType) {
    "node0" {
        Run-Node0
    }
    "node1" {
        Run-Node1
    }
    "node2" {
        Run-Node2
    }
    "all" {
        Write-Host "=== POA Network Launcher ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Genesis time: $GENESIS (in 10 seconds)"
        Write-Host ""
        Write-Host "To run all 3 nodes, open 3 PowerShell terminals and run:"
        Write-Host ""
        Write-Host "  Terminal 1: .\run_poa_network.ps1 node0" -ForegroundColor Yellow
        Write-Host "  Terminal 2: .\run_poa_network.ps1 node1" -ForegroundColor Yellow
        Write-Host "  Terminal 3: .\run_poa_network.ps1 node2" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Or use the following commands directly:"
        Write-Host ""
        Write-Host "  # Terminal 1 - Node 0 (validator V0)"
        Write-Host "  $BIN -p $P0 -c $V0 -g $GENESIS" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  # Terminal 2 - Node 1 (validator V1)"
        Write-Host "  $BIN -p $P1 -c $V1 -g $GENESIS -b 127.0.0.1:$P0" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  # Terminal 3 - Node 2 (validator V2)"
        Write-Host "  $BIN -p $P2 -c $V2 -g $GENESIS -b 127.0.0.1:$P0" -ForegroundColor Gray
        Write-Host ""
    }
    default {
        Write-Host "Usage: .\run_poa_network.ps1 [node0|node1|node2|all]"
        exit 1
    }
}
