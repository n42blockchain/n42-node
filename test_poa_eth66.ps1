#
# Test script for POA eth66 block propagation with 3 nodes (Windows PowerShell)
# Usage: .\test_poa_eth66.ps1
#

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Binary = Join-Path $ScriptDir "target\release\poa_eth66.exe"

# Configuration
$NumNodes = 3
$BasePort = 30303
$BlockTime = 5
$WaitTime = 30

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "POA eth66 Block Propagation Test"
Write-Host "Number of nodes: $NumNodes"
Write-Host "==========================================" -ForegroundColor Cyan

# Check if binary exists
if (-not (Test-Path $Binary)) {
    Write-Host "Binary not found. Building..." -ForegroundColor Yellow
    Push-Location $ScriptDir
    cargo build --release --bin poa_eth66
    Pop-Location
}

if (-not (Test-Path $Binary)) {
    # Try debug build
    $Binary = Join-Path $ScriptDir "target\debug\poa_eth66.exe"
}

# Kill any existing instances
Get-Process -Name "poa_eth66" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Create temp log directory
$LogDir = Join-Path $env:TEMP "poa_eth66_test_$PID"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-Host "Log directory: $LogDir"

# Array to store processes
$NodeProcesses = @()

# Start Node 0 (bootstrap node)
Write-Host ""
Write-Host "Starting Node 0 (Validator 0) on port $BasePort..." -ForegroundColor Yellow
$env:RUST_LOG = "info"
$Node0Log = Join-Path $LogDir "node0.log"
$Node0Process = Start-Process -FilePath $Binary -ArgumentList "--port", $BasePort, "--validator-index", "0", "--block-time", $BlockTime -RedirectStandardOutput $Node0Log -RedirectStandardError (Join-Path $LogDir "node0_err.log") -PassThru -WindowStyle Hidden
$NodeProcesses += $Node0Process
Write-Host "Node 0 PID: $($Node0Process.Id)"

# Wait for node 0 to start
Start-Sleep -Seconds 3

# Get enode from node 0
$Enode = $null
$LogContent = Get-Content $Node0Log -ErrorAction SilentlyContinue
foreach ($line in $LogContent) {
    if ($line -match 'enode://[^\s]+') {
        $Enode = $Matches[0]
        break
    }
}

if (-not $Enode) {
    Write-Host "Failed to get enode from Node 0" -ForegroundColor Red
    Get-Content $Node0Log -ErrorAction SilentlyContinue
    $Node0Process | Stop-Process -Force -ErrorAction SilentlyContinue
    exit 1
}

# Replace 0.0.0.0 with 127.0.0.1 (0.0.0.0 is bind address, not routable)
$Enode = $Enode -replace '@0\.0\.0\.0:', '@127.0.0.1:'
Write-Host "Node 0 enode: $Enode"

# Start remaining nodes
for ($i = 1; $i -lt $NumNodes; $i++) {
    $Port = $BasePort + $i
    Write-Host ""
    Write-Host "Starting Node $i (Validator $i) on port $Port..." -ForegroundColor Yellow
    $NodeLog = Join-Path $LogDir "node$i.log"
    $NodeProcess = Start-Process -FilePath $Binary -ArgumentList "--port", $Port, "--validator-index", $i, "--block-time", $BlockTime, "--bootnode", $Enode -RedirectStandardOutput $NodeLog -RedirectStandardError (Join-Path $LogDir "node${i}_err.log") -PassThru -WindowStyle Hidden
    $NodeProcesses += $NodeProcess
    Write-Host "Node $i PID: $($NodeProcess.Id)"
    Start-Sleep -Seconds 1
}

# Wait for connection and block exchange
Write-Host ""
Write-Host "Waiting $WaitTime seconds for nodes to connect and exchange blocks..." -ForegroundColor Yellow
for ($i = 1; $i -le $WaitTime; $i++) {
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 1
}
Write-Host ""

# Analyze results
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Test Results"
Write-Host "==========================================" -ForegroundColor Cyan

# Check peer connections
Write-Host ""
Write-Host "=== Peer Connections ===" -ForegroundColor Blue
$TotalPeers = 0
for ($i = 0; $i -lt $NumNodes; $i++) {
    $NodeLog = Join-Path $LogDir "node$i.log"
    $Peers = (Select-String -Path $NodeLog -Pattern "Peer connected" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  Node $i connected peers: $Peers"
    $TotalPeers += $Peers
}

# Check block broadcasts
Write-Host ""
Write-Host "=== Block Broadcasts ===" -ForegroundColor Blue
$TotalBroadcasts = 0
for ($i = 0; $i -lt $NumNodes; $i++) {
    $NodeLog = Join-Path $LogDir "node$i.log"
    $Broadcasts = (Select-String -Path $NodeLog -Pattern "Broadcasting block via eth66" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  Node $i broadcasts: $Broadcasts"
    $TotalBroadcasts += $Broadcasts
}

# Check block receives
Write-Host ""
Write-Host "=== Block Receives ===" -ForegroundColor Blue
$TotalReceives = 0
$NodesWithReceives = 0
for ($i = 0; $i -lt $NumNodes; $i++) {
    $NodeLog = Join-Path $LogDir "node$i.log"
    $Receives = (Select-String -Path $NodeLog -Pattern "Received NewBlock via eth66" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  Node $i received: $Receives blocks"
    $TotalReceives += $Receives
    if ($Receives -gt 0) {
        $NodesWithReceives++
    }
}

# Check for decode errors
Write-Host ""
Write-Host "=== Decode Errors ===" -ForegroundColor Blue
$DecodeErrors = 0
for ($i = 0; $i -lt $NumNodes; $i++) {
    $NodeLog = Join-Path $LogDir "node$i.log"
    $Errors = (Select-String -Path $NodeLog -Pattern "failed to decode" -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($Errors -gt 0) {
        Write-Host "  Node $i : $Errors errors" -ForegroundColor Red
        $DecodeErrors += $Errors
    }
}
if ($DecodeErrors -eq 0) {
    Write-Host "  No decode errors" -ForegroundColor Green
}

# Summary
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Blue
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Total peer connections: $TotalPeers"
Write-Host "  Total blocks broadcast: $TotalBroadcasts"
Write-Host "  Total blocks received: $TotalReceives"
Write-Host "  Nodes receiving blocks: $NodesWithReceives / $NumNodes"
Write-Host "  Decode errors: $DecodeErrors"

# Final verdict
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
if ($NodesWithReceives -ge ($NumNodes - 1) -and $DecodeErrors -eq 0) {
    Write-Host "TEST PASSED!" -ForegroundColor Green
    Write-Host "All nodes successfully exchanged blocks via eth66 protocol."
} elseif ($NodesWithReceives -gt 0 -and $DecodeErrors -eq 0) {
    Write-Host "TEST PARTIAL SUCCESS" -ForegroundColor Yellow
    Write-Host "$NodesWithReceives out of $NumNodes nodes received blocks."
} else {
    Write-Host "TEST FAILED!" -ForegroundColor Red
    if ($NodesWithReceives -eq 0) {
        Write-Host "No block propagation occurred."
    }
    if ($DecodeErrors -gt 0) {
        Write-Host "RLP decode errors occurred."
    }
}
Write-Host "==========================================" -ForegroundColor Cyan

# Show recent activity from each node
Write-Host ""
Write-Host "Recent activity from each node:" -ForegroundColor Yellow
for ($i = 0; $i -lt $NumNodes; $i++) {
    Write-Host ""
    Write-Host "--- Node $i ---" -ForegroundColor Blue
    $NodeLog = Join-Path $LogDir "node$i.log"
    Select-String -Path $NodeLog -Pattern "Broadcasting block|Received NewBlock|Peer connected" -ErrorAction SilentlyContinue | Select-Object -Last 5 | ForEach-Object { Write-Host $_.Line }
}

# Cleanup
Write-Host ""
Write-Host "Stopping nodes..."
foreach ($proc in $NodeProcesses) {
    $proc | Stop-Process -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Full logs available at: $LogDir"
for ($i = 0; $i -lt $NumNodes; $i++) {
    Write-Host "  - Node $i : $LogDir\node$i.log"
}
