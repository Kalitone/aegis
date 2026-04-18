#Requires -RunAsAdministrator
param([string]$ServiceName = "AEGIS")

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$NssmExe     = Join-Path $ProjectRoot "tools\nssm\nssm.exe"

if (-not (Test-Path $NssmExe)) {
    throw "NSSM not found at $NssmExe — was AEGIS installed via install-service.ps1?"
}

& $NssmExe stop   $ServiceName 2>$null | Out-Null
& $NssmExe remove $ServiceName confirm
Write-Host "Service '$ServiceName' removed."
