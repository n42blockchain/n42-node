#
# Test script for POA sync node - downloads blocks from 3 validators (Windows PowerShell)
# Usage: .\test_sync_node.ps1
#

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ValidatorBinary = Join-Path $ScriptDir "target\release\poa_eth66.exe"
$SyncBinary = Join-Path $ScriptDir "target\release\poa_sync_node.exe"

# Configuration
$NumValidators = 3
$BasePort = 30303
$SyncPort = 30400
$BlockTime = 5
$ValidatorRunTime = 30    # How long validators run before sync node joins
$SyncRunTime = 30         # How long sync node runs

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "POA Sync Node Test"
Write-Host "Validators: $NumValidators"
Write-Host "Block time: ${BlockTime}s"
Write-Host "==========================================" -ForegroundColor Cyan

# Check if binaries exist
if (-not (Test-Path $ValidatorBinary)) {
    Write-Host "Validator binary not found. Building..." -ForegroundColor Yellow
    Push-Location $ScriptDir
    cargo build --release --bin poa_eth66
    Pop-Location
}

if (-not (Test-Path $ValidatorBinary)) {
    $ValidatorBinary = Join-Path $ScriptDir "target\debug\poa_eth66.exe"
}

if (-not (Test-Path $SyncBinary)) {
    Write-Host "Sync binary not found. Building..." -ForegroundColor Yellow
    Push-Location $ScriptDir
    cargo build --release --bin poa_sync_node
    Pop-Location
}

if (-not (Test-Path $SyncBinary)) {
    $SyncBinary = Join-Path $ScriptDir "target\debug\poa_sync_node.exe"
}

# Kill any existing instances
Get-Process -Name "poa_eth66" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "poa_sync_node" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Create temp log directory
$LogDir = Join-Path $env:TEMP "poa_sync_test_$PID"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-Host "Log directory: $LogDir"

# Array to store processes
$NodeProcesses = @()

# Start Validator 0 (bootstrap node)
Write-Host ""
Write-Host "=== Phase 1: Starting Validators ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "Starting Validator 0 on port $BasePort..." -ForegroundColor Cyan
$env:RUST_LOG = "info"
$Validator0Log = Join-Path $LogDir "validator0.log"
$Validator0Process = Start-Process -FilePath $ValidatorBinary -ArgumentList "--port", $BasePort, "--validator-index", "0", "--block-time", $BlockTime -RedirectStandardOutput $Validator0Log -RedirectStandardError (Join-Path $LogDir "validator0_err.log") -PassThru -WindowStyle Hidden
$NodeProcesses += $Validator0Process
Write-Host "Validator 0 PID: $($Validator0Process.Id)"

# Wait for validator 0 to start
Start-Sleep -Seconds 3

# Get enode from validator 0
$Enode = $null
$LogContent = Get-Content $Validator0Log -ErrorAction SilentlyContinue
foreach ($line in $LogContent) {
    if ($line -match 'enode://[^\s]+') {
        $Enode = $Matches[0]
        break
    }
}

if (-not $Enode) {
    Write-Host "Failed to get enode from Validator 0" -ForegroundColor Red
    Get-Content $Validator0Log -ErrorAction SilentlyContinue
    $Validator0Process | Stop-Process -Force -ErrorAction SilentlyContinue
    exit 1
}

# Replace 0.0.0.0 with 127.0.0.1 (0.0.0.0 is bind address, not routable)
$Enode = $Enode -replace '@0\.0\.0\.0:', '@127.0.0.1:'
Write-Host "Validator 0 enode: $Enode"

# Start remaining validators
for ($i = 1; $i -lt $NumValidators; $i++) {
    $Port = $BasePort + $i
    Write-Host ""
    Write-Host "Starting Validator $i on port $Port..." -ForegroundColor Cyan
    $ValidatorLog = Join-Path $LogDir "validator$i.log"
    $ValidatorProcess = Start-Process -FilePath $ValidatorBinary -ArgumentList "--port", $Port, "--validator-index", $i, "--block-time", $BlockTime, "--bootnode", $Enode -RedirectStandardOutput $ValidatorLog -RedirectStandardError (Join-Path $LogDir "validator${i}_err.log") -PassThru -WindowStyle Hidden
    $NodeProcesses += $ValidatorProcess
    Write-Host "Validator $i PID: $($ValidatorProcess.Id)"
    Start-Sleep -Seconds 1
}

# Wait for validators to produce some blocks
Write-Host ""
Write-Host "=== Phase 2: Waiting for Validators to Produce Blocks ===" -ForegroundColor Yellow
Write-Host "Waiting $ValidatorRunTime seconds for validators to produce blocks..."
Write-Host ""

for ($i = 1; $i -le $ValidatorRunTime; $i++) {
    if ($i % 5 -eq 0) {
        $TotalBlocks = 0
        for ($v = 0; $v -lt $NumValidators; $v++) {
            $ValidatorLog = Join-Path $LogDir "validator$v.log"
            $Blocks = (Select-String -Path $ValidatorLog -Pattern "Produced block" -ErrorAction SilentlyContinue | Measure-Object).Count
            $TotalBlocks += $Blocks
        }
        Write-Host "  [$i/$ValidatorRunTime] Total blocks produced: $TotalBlocks"
    }
    Start-Sleep -Seconds 1
}

# Count blocks before sync
Write-Host ""
Write-Host "Blocks produced by validators before sync:" -ForegroundColor Blue
for ($i = 0; $i -lt $NumValidators; $i++) {
    $ValidatorLog = Join-Path $LogDir "validator$i.log"
    $Blocks = (Select-String -Path $ValidatorLog -Pattern "Produced block" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  Validator $i : $Blocks blocks"
}

# Start sync node
Write-Host ""
Write-Host "=== Phase 3: Starting Sync Node ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "Starting sync node on port $SyncPort..." -ForegroundColor Green
$SyncLog = Join-Path $LogDir "sync_node.log"
$SyncProcess = Start-Process -FilePath $SyncBinary -ArgumentList "--port", $SyncPort, "--block-time", $BlockTime, "--bootnode", $Enode -RedirectStandardOutput $SyncLog -RedirectStandardError (Join-Path $LogDir "sync_node_err.log") -PassThru -WindowStyle Hidden
Write-Host "Sync node PID: $($SyncProcess.Id)"

# Wait for sync node to download blocks
Write-Host ""
Write-Host "Waiting $SyncRunTime seconds for sync node to download blocks..."
Write-Host ""

for ($i = 1; $i -le $SyncRunTime; $i++) {
    if ($i % 5 -eq 0) {
        $Synced = (Select-String -Path $SyncLog -Pattern "Synced new block" -ErrorAction SilentlyContinue | Measure-Object).Count
        $Peers = (Select-String -Path $SyncLog -Pattern "Connected to peer" -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  [$i/$SyncRunTime] Sync node: $Synced blocks synced, $Peers peers"
    }
    Start-Sleep -Seconds 1
}

# Analyze results
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Test Results" -ForegroundColor Blue
Write-Host "==========================================" -ForegroundColor Cyan

# Validator stats
Write-Host ""
Write-Host "=== Validator Statistics ===" -ForegroundColor Blue
$TotalProduced = 0
for ($i = 0; $i -lt $NumValidators; $i++) {
    $ValidatorLog = Join-Path $LogDir "validator$i.log"
    $Produced = (Select-String -Path $ValidatorLog -Pattern "Produced block" -ErrorAction SilentlyContinue | Measure-Object).Count
    $Received = (Select-String -Path $ValidatorLog -Pattern "Received NewBlock" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  Validator $i : produced=$Produced, received=$Received"
    $TotalProduced += $Produced
}

# Sync node stats
Write-Host ""
Write-Host "=== Sync Node Statistics ===" -ForegroundColor Blue
$Synced = (Select-String -Path $SyncLog -Pattern "Synced new block" -ErrorAction SilentlyContinue | Measure-Object).Count
$Connected = (Select-String -Path $SyncLog -Pattern "Connected to peer" -ErrorAction SilentlyContinue | Measure-Object).Count
$Rejected = (Select-String -Path $SyncLog -Pattern "validation failed" -ErrorAction SilentlyContinue | Measure-Object).Count

Write-Host "  Peers connected: $Connected"
Write-Host "  Blocks synced: $Synced"
Write-Host "  Blocks rejected: $Rejected"

# Show last sync status
Write-Host ""
Write-Host "=== Last Sync Status ===" -ForegroundColor Blue
$SyncStatus = Select-String -Path $SyncLog -Pattern "Sync status" -ErrorAction SilentlyContinue | Select-Object -Last 1
if ($SyncStatus) {
    Write-Host $SyncStatus.Line
} else {
    Write-Host "  No sync status available"
}

# Final verdict
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
if ($Synced -gt 0 -and $Rejected -eq 0) {
    Write-Host "TEST PASSED!" -ForegroundColor Green
    Write-Host "Sync node successfully downloaded $Synced blocks from validators."
    Write-Host "Total blocks produced by validators: $TotalProduced"
} elseif ($Synced -gt 0 -and $Rejected -gt 0) {
    Write-Host "TEST PARTIAL SUCCESS" -ForegroundColor Yellow
    Write-Host "Sync node downloaded $Synced blocks but rejected $Rejected."
} elseif ($Connected -gt 0 -and $Synced -eq 0) {
    Write-Host "TEST PARTIAL SUCCESS" -ForegroundColor Yellow
    Write-Host "Sync node connected to peers but didn't sync any new blocks."
    Write-Host "This might be because validators produced blocks before sync node connected."
} else {
    Write-Host "TEST FAILED!" -ForegroundColor Red
    if ($Connected -eq 0) {
        Write-Host "Sync node failed to connect to any validators."
    }
}
Write-Host "==========================================" -ForegroundColor Cyan

# Show recent sync node activity
Write-Host ""
Write-Host "Recent sync node activity:" -ForegroundColor Yellow
Select-String -Path $SyncLog -Pattern "Synced new block|Connected to peer|Sync status" -ErrorAction SilentlyContinue | Select-Object -Last 10 | ForEach-Object { Write-Host $_.Line }

# Cleanup
Write-Host ""
Write-Host "Stopping all nodes..."
foreach ($proc in $NodeProcesses) {
    $proc | Stop-Process -Force -ErrorAction SilentlyContinue
}
$SyncProcess | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Full logs available at: $LogDir"
Write-Host "  - Validators: $LogDir\validator{0,1,2}.log"
Write-Host "  - Sync node:  $LogDir\sync_node.log"
Write-Host ""
Write-Host "To view sync progress:"
Write-Host "  Select-String -Path '$LogDir\sync_node.log' -Pattern 'Synced new block'"
