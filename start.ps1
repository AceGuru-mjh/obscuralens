# ---------------------------------------------------------------------------
# ObscuraLens one-command launcher (Windows PowerShell).
#
#   .\start.ps1                    -> create .venv (first run), install deps,
#                                     start the web UI and open the browser
#   .\start.ps1 -NoBrowser         -> same, without opening a browser
#   .\start.ps1 -Port 9000         -> listen on another port
#   .\start.ps1 -Host 0.0.0.0      -> bind on all interfaces
#   .\start.ps1 -Cli ip 8.8.8.8    -> pass through to the CLI instead
#   .\start.ps1 -Reset             -> recreate the virtualenv from scratch
#
# First run needs internet access for pip; later runs start in seconds.
# Data (history, cases, watchlist, cache) lives under .\data and survives
# restarts.
# ---------------------------------------------------------------------------
param(
    [int]$Port = 8000,
    [string]$Host = "127.0.0.1",
    [switch]$NoBrowser,
    [switch]$Reset,
    [switch]$Cli,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

$venv = Join-Path $root ".venv"
$stamp = Join-Path $venv ".obscuralens-deps-v5"
$python = Join-Path $venv "Scripts\python.exe"

function Say($message) { Write-Host "[obscuralens] $message" -ForegroundColor Cyan }
function Die($message) {
    Write-Host "[obscuralens] error: $message" -ForegroundColor Red
    exit 1
}

if ($Reset -and (Test-Path $venv)) {
    Remove-Item -Recurse -Force $venv
    Say "removed .venv - it will be rebuilt"
}

# ---- create the virtualenv ------------------------------------------------
if (-not (Test-Path $python)) {
    Say "creating virtual environment in .venv (first run)..."
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
    if (-not $py) { Die "no Python found - install Python 3.9+ first (https://python.org)" }
    if ($py.Source -like "*py.exe") {
        & $py.Source -3 -m venv $venv
    } else {
        & $py.Source -m venv $venv
    }
    if (-not (Test-Path $python)) { Die "could not create .venv" }
    & $python -m pip install --quiet --upgrade pip 2>$null
}

# ---- dependencies -----------------------------------------------------------
if (-not (Test-Path $stamp)) {
    Say "installing dependencies (first run only - this can take a minute)..."
    & $python -m pip install --quiet --disable-pip-version-check `
        requests phonenumbers PyYAML tabulate jinja2 `
        fastapi uvicorn "python-multipart>=0.0.9"
    if ($LASTEXITCODE -ne 0) { Die "pip install failed - check your internet connection / proxy" }
    # Optional niceties: charts + PDF reports. Failures are non-fatal.
    & $python -m pip install --quiet --disable-pip-version-check `
        matplotlib numpy wordcloud reportlab 2>$null
    Say "optional chart/report packages installed (or skipped)"
    New-Item -ItemType File -Path $stamp | Out-Null
} else {
    Say "dependencies already installed - remove .venv\.obscuralens-deps-v5 to force a refresh"
}

if (-not $env:OBSCURALENS_CONFIG_DIR) { $env:OBSCURALENS_CONFIG_DIR = Join-Path $root "config" }
New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root "reports") | Out-Null
New-Item -ItemType Directory -Force -Path $env:OBSCURALENS_CONFIG_DIR | Out-Null

# ---- launch -----------------------------------------------------------------
if ($Cli) {
    if ($CliArgs) {
        & $python -m obscuralens @CliArgs
    } else {
        & $python -m obscuralens
    }
    exit $LASTEXITCODE
}

$url = "http://$($Host):$Port"
Say "starting ObscuraLens web UI on $url"
Say "press Ctrl+C to stop - data stays in .\data"

$openFlag = "--open"
if ($NoBrowser) { $openFlag = "--no-open" }
& $python -m obscuralens serve --host $Host --port $Port $openFlag
