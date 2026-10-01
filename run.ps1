param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ObscuraArgs
)

# One-command launcher: creates .venv on first use, installs dependencies,
# then runs ObscuraLens. Examples:
#   .\run.ps1                      # interactive console
#   .\run.ps1 ip 8.8.8.8 -f json
#   .\run.ps1 investigate example.com

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venv = Join-Path $root '.venv'
$python = Join-Path $venv 'Scripts\python.exe'

if (-not (Test-Path $python)) {
    Write-Host "Creating virtual environment in .venv ..." -ForegroundColor Cyan
    python -m venv $venv
}

& $python -m pip install --quiet --upgrade pip
& $python -m pip install --quiet -r requirements.txt

if ($ObscuraArgs.Count -eq 0) {
    & $python -m obscuralens
} else {
    & $python -m obscuralens @ObscuraArgs
}
exit $LASTEXITCODE
