# Fork Scenario Integration Test for Windows PowerShell
#
# This script creates a fork scenario by:
#   1. Starting 3 validators, but V2 starts LATER (misses initial blocks)
#   2. V0 and V1 produce blocks and sync with each other
#   3. V2 joins late, may produce competing blocks before syncing
#   4. Observe how fork choice resolves
#
# Usage: powershell -ExecutionPolicy Bypass -File test_fork_scenario.ps1

$ErrorActionPreference = "Continue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   Fork Scenario Integration Test" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$BLOCK_TIME = 3
$PHASE1_TIME = 20  # V0+V1 run alone
$PHASE2_TIME = 30  # All 3 nodes run
$BASE_PORT = 31303  # Use 31xxx to avoid conflict with existing Ethereum nodes
$BINARY = "target\release\poa_eth66.exe"

# Create log directory
$LOG_DIR = Join-Path $env:TEMP "poa_fork_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
Write-Host "Log directory: $LOG_DIR"
Write-Host ""

# Check binary
if (-not (Test-Path $BINARY)) {
    Write-Host "Building poa_eth66 in release mode..." -ForegroundColor Yellow
    cargo build --release --bin poa_eth66
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed!" -ForegroundColor Red
        exit 1
    }
}
Write-Host "Binary: $BINARY"
Write-Host ""

# Kill any existing instances
Write-Host "Cleaning up old processes..."
Get-Process -Name "poa_eth66" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Deterministic enode for V0
# Deterministic enode for V0 - pubkey is fixed based on validator key
$ENODE_V0 = "enode://fcca973818536e2990300a88ef560fdb887deb69000c7675bd40bfc063ad33271f12113fbeef6bc84a0067bfbb9665a313393fde09d4a09dc476a8e304d2ef4a@127.0.0.1:${BASE_PORT}"

Write-Host "==========================================" -ForegroundColor Green
Write-Host " Phase 1: Start V0 + V1 ($PHASE1_TIME seconds)" -ForegroundColor Green
Write-Host " V2 will join LATER to create fork opportunity" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Start V0
$PORT_V0 = $BASE_PORT
Write-Host "Starting V0 on port $PORT_V0..."
$V0_LOG = Join-Path $LOG_DIR "node0.log"
$proc_V0 = Start-Process -FilePath $BINARY -ArgumentList "--port $PORT_V0 --validator-index 0 --block-time $BLOCK_TIME" -PassThru -WindowStyle Hidden -RedirectStandardOutput $V0_LOG -RedirectStandardError (Join-Path $LOG_DIR "node0_err.log")
Write-Host "V0 started (PID: $($proc_V0.Id))"
Start-Sleep -Seconds 5

# Start V1
$PORT_V1 = $BASE_PORT + 1
Write-Host "Starting V1 on port $PORT_V1..."
$V1_LOG = Join-Path $LOG_DIR "node1.log"
$proc_V1 = Start-Process -FilePath $BINARY -ArgumentList "--port $PORT_V1 --validator-index 1 --block-time $BLOCK_TIME --bootnode `"$ENODE_V0`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $V1_LOG -RedirectStandardError (Join-Path $LOG_DIR "node1_err.log")
Write-Host "V1 started (PID: $($proc_V1.Id))"
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "V0 and V1 are now producing blocks..." -ForegroundColor Yellow
Write-Host "V2 has NOT started yet - this creates the fork opportunity!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Waiting $PHASE1_TIME seconds for V0+V1 to build their chain..."
Write-Host ""

for ($i = 1; $i -le $PHASE1_TIME; $i++) {
    if ($i % 5 -eq 0) {
        Write-Host "  [$i/$PHASE1_TIME] V0+V1 building chain..."
        if (Test-Path $V0_LOG) {
            $v0_blocks = (Select-String -Path $V0_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    V0 produced: $v0_blocks blocks"
        }
        if (Test-Path $V1_LOG) {
            $v1_blocks = (Select-String -Path $V1_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    V1 produced: $v1_blocks blocks"
        }
    }
    Start-Sleep -Seconds 1
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Green
Write-Host " Phase 2: V2 Joins Late ($PHASE2_TIME seconds)" -ForegroundColor Green
Write-Host " V2 may produce competing blocks before syncing!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Start V2 (connects to V0)
$PORT_V2 = $BASE_PORT + 2
Write-Host "Starting V2 on port $PORT_V2..."
Write-Host "V2 will start from genesis and try to sync with V0+V1"
Write-Host ""
$V2_LOG = Join-Path $LOG_DIR "node2.log"
$proc_V2 = Start-Process -FilePath $BINARY -ArgumentList "--port $PORT_V2 --validator-index 2 --block-time $BLOCK_TIME --bootnode `"$ENODE_V0`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $V2_LOG -RedirectStandardError (Join-Path $LOG_DIR "node2_err.log")
Write-Host "V2 started (PID: $($proc_V2.Id)) - now syncing and potentially creating forks!"
Write-Host ""

Write-Host "Waiting $PHASE2_TIME seconds for sync and potential fork resolution..."
Write-Host ""

for ($i = 1; $i -le $PHASE2_TIME; $i++) {
    if ($i % 5 -eq 0) {
        Write-Host "  [$i/$PHASE2_TIME] Network activity..."
        if (Test-Path $V0_LOG) {
            $v0_blocks = (Select-String -Path $V0_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    V0 produced: $v0_blocks blocks"
        }
        if (Test-Path $V1_LOG) {
            $v1_blocks = (Select-String -Path $V1_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    V1 produced: $v1_blocks blocks"
        }
        if (Test-Path $V2_LOG) {
            $v2_blocks = (Select-String -Path $V2_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count
            $v2_received = (Select-String -Path $V2_LOG -Pattern "Received NewBlock" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    V2 produced: $v2_blocks blocks, received: $v2_received blocks"
        }
    }
    Start-Sleep -Seconds 1
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Test Results Analysis" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "=== Block Production ===" -ForegroundColor Yellow
Write-Host ""

$V0_PRODUCED = if (Test-Path $V0_LOG) { (Select-String -Path $V0_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V1_PRODUCED = if (Test-Path $V1_LOG) { (Select-String -Path $V1_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V2_PRODUCED = if (Test-Path $V2_LOG) { (Select-String -Path $V2_LOG -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }

Write-Host "  V0 produced: $V0_PRODUCED blocks"
Write-Host "  V1 produced: $V1_PRODUCED blocks"
Write-Host "  V2 produced: $V2_PRODUCED blocks"
Write-Host ""

Write-Host "=== Block Reception ===" -ForegroundColor Yellow
Write-Host ""

$V0_RECEIVED = if (Test-Path $V0_LOG) { (Select-String -Path $V0_LOG -Pattern "Received NewBlock" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V1_RECEIVED = if (Test-Path $V1_LOG) { (Select-String -Path $V1_LOG -Pattern "Received NewBlock" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V2_RECEIVED = if (Test-Path $V2_LOG) { (Select-String -Path $V2_LOG -Pattern "Received NewBlock" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }

Write-Host "  V0 received: $V0_RECEIVED blocks"
Write-Host "  V1 received: $V1_RECEIVED blocks"
Write-Host "  V2 received: $V2_RECEIVED blocks"
Write-Host ""

Write-Host "=== Peer Connections ===" -ForegroundColor Yellow
Write-Host ""

$V0_PEERS = if (Test-Path $V0_LOG) { (Select-String -Path $V0_LOG -Pattern "Peer connected" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V1_PEERS = if (Test-Path $V1_LOG) { (Select-String -Path $V1_LOG -Pattern "Peer connected" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V2_PEERS = if (Test-Path $V2_LOG) { (Select-String -Path $V2_LOG -Pattern "Peer connected" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }

Write-Host "  V0 peers: $V0_PEERS"
Write-Host "  V1 peers: $V1_PEERS"
Write-Host "  V2 peers: $V2_PEERS"
Write-Host ""

Write-Host "=== Fork/Reorg Detection ===" -ForegroundColor Yellow
Write-Host ""

$V0_FORKS = if (Test-Path $V0_LOG) { (Select-String -Path $V0_LOG -Pattern "unknown parent" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V1_FORKS = if (Test-Path $V1_LOG) { (Select-String -Path $V1_LOG -Pattern "unknown parent" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V2_FORKS = if (Test-Path $V2_LOG) { (Select-String -Path $V2_LOG -Pattern "unknown parent" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }

Write-Host "  V0 fork indicators: $V0_FORKS"
Write-Host "  V1 fork indicators: $V1_FORKS"
Write-Host "  V2 fork indicators: $V2_FORKS"
Write-Host ""

$V0_ACCEPTED = if (Test-Path $V0_LOG) { (Select-String -Path $V0_LOG -Pattern "Accepted block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V1_ACCEPTED = if (Test-Path $V1_LOG) { (Select-String -Path $V1_LOG -Pattern "Accepted block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
$V2_ACCEPTED = if (Test-Path $V2_LOG) { (Select-String -Path $V2_LOG -Pattern "Accepted block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }

Write-Host "  V0 accepted from peers: $V0_ACCEPTED"
Write-Host "  V1 accepted from peers: $V1_ACCEPTED"
Write-Host "  V2 accepted from peers: $V2_ACCEPTED"
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Stopping Nodes" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Stop all nodes
if ($proc_V0 -and -not $proc_V0.HasExited) { Stop-Process -Id $proc_V0.Id -Force -ErrorAction SilentlyContinue }
if ($proc_V1 -and -not $proc_V1.HasExited) { Stop-Process -Id $proc_V1.Id -Force -ErrorAction SilentlyContinue }
if ($proc_V2 -and -not $proc_V2.HasExited) { Stop-Process -Id $proc_V2.Id -Force -ErrorAction SilentlyContinue }

Write-Host "All nodes stopped."
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Log files:"
Write-Host "  V0: $V0_LOG"
Write-Host "  V1: $V1_LOG"
Write-Host "  V2: $V2_LOG"
Write-Host ""
Write-Host "To view recent activity:"
Write-Host "  Get-Content $V0_LOG | Select-String 'Miner sealed|Received NewBlock|Peer connected'"
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
