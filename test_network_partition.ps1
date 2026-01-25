<#
.SYNOPSIS
    Network Partition Fork Test

.DESCRIPTION
    Phase 1: All 3 nodes connected, build common chain together
    Phase 2: Network partition - split into 2 groups, each builds independently
    Phase 3: Network heals - reconnect and observe reorg

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File test_network_partition.ps1
#>

param(
    [int]$CommonPrefixTime = 30,
    [int]$PartitionTime = 45,
    [int]$ReconnectTime = 30,
    [int]$BlockTime = 3
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       Network Partition Fork Test" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$BASE_PORT = 31303
$BINARY = "target\release\poa_eth66.exe"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LOG_DIR = Join-Path $env:TEMP "poa_partition_$timestamp"
New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Block time:      $BlockTime seconds"
Write-Host "  Common prefix:   $CommonPrefixTime seconds"
Write-Host "  Partition time:  $PartitionTime seconds"
Write-Host "  Reconnect time:  $ReconnectTime seconds"
Write-Host "  Log directory:   $LOG_DIR"
Write-Host ""

if (-not (Test-Path $BINARY)) {
    Write-Host "Building poa_eth66..." -ForegroundColor Yellow
    cargo build --release --bin poa_eth66
}

Write-Host "Cleaning up..." -ForegroundColor Gray
Get-Process -Name "poa_eth66" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$ENODE_V0 = "enode://fcca973818536e2990300a88ef560fdb887deb69000c7675bd40bfc063ad33271f12113fbeef6bc84a0067bfbb9665a313393fde09d4a09dc476a8e304d2ef4a@127.0.0.1:$BASE_PORT"

$PORT_V0 = $BASE_PORT
$PORT_V1 = $BASE_PORT + 1
$PORT_V2 = $BASE_PORT + 2

function Start-Node($Index, $Port, $Bootnode, $LogSuffix) {
    $logFile = Join-Path $LOG_DIR "node${Index}_${LogSuffix}.log"
    $errFile = Join-Path $LOG_DIR "node${Index}_${LogSuffix}_err.log"
    $args = "--port $Port --validator-index $Index --block-time $BlockTime"
    if ($Bootnode) { $args += " --bootnode `"$Bootnode`"" }
    $proc = Start-Process -FilePath $BINARY -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $logFile -RedirectStandardError $errFile
    return @{ Process = $proc; Log = $logFile; Index = $Index }
}

function Get-BlockCount($LogFile) {
    if (Test-Path $LogFile) { (Select-String -Path $LogFile -Pattern "Miner sealed block" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
}

function Get-ReceivedCount($LogFile) {
    if (Test-Path $LogFile) { (Select-String -Path $LogFile -Pattern "Received NewBlock" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
}

function Get-ForkCount($LogFile) {
    if (Test-Path $LogFile) { (Select-String -Path $LogFile -Pattern "unknown parent" -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 }
}

# ========== PHASE 1 ==========
Write-Host "========================================================" -ForegroundColor Green
Write-Host " PHASE 1: Building Common Prefix - $CommonPrefixTime sec" -ForegroundColor Green
Write-Host " All 3 validators connected" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Starting V0..." -ForegroundColor Yellow
$v0_p1 = Start-Node -Index 0 -Port $PORT_V0 -LogSuffix "phase1"
Write-Host "  PID: $($v0_p1.Process.Id)"
Start-Sleep -Seconds 3

Write-Host "Starting V1..." -ForegroundColor Yellow
$v1_p1 = Start-Node -Index 1 -Port $PORT_V1 -Bootnode $ENODE_V0 -LogSuffix "phase1"
Write-Host "  PID: $($v1_p1.Process.Id)"
Start-Sleep -Seconds 2

Write-Host "Starting V2..." -ForegroundColor Yellow
$v2_p1 = Start-Node -Index 2 -Port $PORT_V2 -Bootnode $ENODE_V0 -LogSuffix "phase1"
Write-Host "  PID: $($v2_p1.Process.Id)"
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Building common chain..." -ForegroundColor Cyan

for ($i = 1; $i -le $CommonPrefixTime; $i++) {
    if ($i % 5 -eq 0) {
        $b0 = Get-BlockCount $v0_p1.Log
        $b1 = Get-BlockCount $v1_p1.Log
        $b2 = Get-BlockCount $v2_p1.Log
        Write-Host "  [$i/$CommonPrefixTime] V0:$b0 V1:$b1 V2:$b2"
    }
    Start-Sleep -Seconds 1
}

$p1_v0 = Get-BlockCount $v0_p1.Log
$p1_v1 = Get-BlockCount $v1_p1.Log
$p1_v2 = Get-BlockCount $v2_p1.Log

Write-Host ""
Write-Host "Phase 1 Complete: V0=$p1_v0 V1=$p1_v1 V2=$p1_v2 blocks" -ForegroundColor Cyan
Write-Host ""

Write-Host "Stopping all nodes..." -ForegroundColor Yellow
$v0_p1.Process, $v1_p1.Process, $v2_p1.Process | ForEach-Object { if ($_ -and -not $_.HasExited) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } }
Start-Sleep -Seconds 3

# ========== PHASE 2 ==========
Write-Host "========================================================" -ForegroundColor Red
Write-Host " PHASE 2: Network Partition - $PartitionTime sec" -ForegroundColor Red
Write-Host " Partition A: V0 + V1" -ForegroundColor Red
Write-Host " Partition B: V2 isolated" -ForegroundColor Red
Write-Host "========================================================" -ForegroundColor Red
Write-Host ""

Write-Host "Starting Partition A..." -ForegroundColor Yellow
$v0_p2 = Start-Node -Index 0 -Port $PORT_V0 -LogSuffix "phase2_A"
Write-Host "  V0 PID: $($v0_p2.Process.Id)"
Start-Sleep -Seconds 3

$v1_p2 = Start-Node -Index 1 -Port $PORT_V1 -Bootnode $ENODE_V0 -LogSuffix "phase2_A"
Write-Host "  V1 PID: $($v1_p2.Process.Id)"
Start-Sleep -Seconds 2

Write-Host "Starting Partition B (V2 isolated)..." -ForegroundColor Yellow
$v2_p2 = Start-Node -Index 2 -Port $PORT_V2 -LogSuffix "phase2_B"
Write-Host "  V2 PID: $($v2_p2.Process.Id) - NO BOOTNODE"
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Both partitions running independently..." -ForegroundColor Cyan

for ($i = 1; $i -le $PartitionTime; $i++) {
    if ($i % 5 -eq 0) {
        $a0 = Get-BlockCount $v0_p2.Log
        $a1 = Get-BlockCount $v1_p2.Log
        $b2 = Get-BlockCount $v2_p2.Log
        Write-Host "  [$i/$PartitionTime] PartA: V0=$a0 V1=$a1 | PartB: V2=$b2"
    }
    Start-Sleep -Seconds 1
}

$p2_v0 = Get-BlockCount $v0_p2.Log
$p2_v1 = Get-BlockCount $v1_p2.Log
$p2_v2 = Get-BlockCount $v2_p2.Log

Write-Host ""
Write-Host "Phase 2 Complete:" -ForegroundColor Cyan
Write-Host "  Partition A: V0=$p2_v0 V1=$p2_v1"
Write-Host "  Partition B: V2=$p2_v2"
Write-Host ""

Write-Host "Stopping V2 for reconnection..." -ForegroundColor Yellow
if ($v2_p2.Process -and -not $v2_p2.Process.HasExited) { Stop-Process -Id $v2_p2.Process.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

# ========== PHASE 3 ==========
Write-Host "========================================================" -ForegroundColor Green
Write-Host " PHASE 3: Network Heals - $ReconnectTime sec" -ForegroundColor Green
Write-Host " V2 rejoins network" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Restarting V2 with bootnode..." -ForegroundColor Yellow
$v2_p3 = Start-Node -Index 2 -Port $PORT_V2 -Bootnode $ENODE_V0 -LogSuffix "phase3"
Write-Host "  V2 PID: $($v2_p3.Process.Id)"
Write-Host ""

Write-Host "Monitoring sync and reorg..." -ForegroundColor Cyan

for ($i = 1; $i -le $ReconnectTime; $i++) {
    if ($i % 5 -eq 0) {
        $v0_b = Get-BlockCount $v0_p2.Log
        $v1_b = Get-BlockCount $v1_p2.Log
        $v2_b = Get-BlockCount $v2_p3.Log
        $v2_r = Get-ReceivedCount $v2_p3.Log
        $v0_f = Get-ForkCount $v0_p2.Log
        $v2_f = Get-ForkCount $v2_p3.Log
        Write-Host "  [$i/$ReconnectTime] V0=$v0_b V1=$v1_b V2=$v2_b recv=$v2_r | Forks: V0=$v0_f V2=$v2_f"
    }
    Start-Sleep -Seconds 1
}

# ========== RESULTS ==========
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " FINAL RESULTS" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$f_v0 = Get-ForkCount $v0_p2.Log
$f_v1 = Get-ForkCount $v1_p2.Log
$f_v2 = Get-ForkCount $v2_p3.Log
$totalForks = $f_v0 + $f_v1 + $f_v2

Write-Host "Fork Detection (unknown parent):"
Write-Host "  V0: $f_v0"
Write-Host "  V1: $f_v1"
Write-Host "  V2: $f_v2"
Write-Host "  Total: $totalForks"
Write-Host ""

if ($totalForks -gt 0) {
    Write-Host "FORK DETECTED!" -ForegroundColor Green
    Write-Host "The partition created competing chains." -ForegroundColor Green
} else {
    Write-Host "No fork detected." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Stopping all nodes..." -ForegroundColor Gray
Get-Process -Name "poa_eth66" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host ""
Write-Host "Log files: $LOG_DIR" -ForegroundColor Cyan
Write-Host "  Phase 1: node*_phase1.log"
Write-Host "  Phase 2: node*_phase2_*.log"
Write-Host "  Phase 3: node2_phase3.log"
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
