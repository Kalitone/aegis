#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs AEGIS as a Windows service via NSSM.

.DESCRIPTION
    Downloads NSSM (if missing), registers `python -m aegis` as a service named
    "AEGIS" running as LocalSystem so it starts at boot before any user logs on
    and can see/act on every process on the box.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1
#>

param(
    [string]$ServiceName = "AEGIS",
    [string]$DisplayName = "AEGIS Endpoint Guardian",
    [string]$ConfigPath  = "config\aegis.yaml"
)

$ErrorActionPreference = "Stop"

# --- Locate project root (parent of /scripts) ---
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
Write-Host "Project root: $ProjectRoot"

# --- Resolve python.exe (prefer venv if present) ---
$PythonExe = $null
foreach ($candidate in @(
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe"),
    (Join-Path $ProjectRoot "venv\Scripts\python.exe")
)) {
    if (Test-Path $candidate) { $PythonExe = $candidate; break }
}
if (-not $PythonExe) {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}
if (-not $PythonExe) {
    throw "python.exe not found. Install Python or create a venv in this directory."
}
Write-Host "Python:       $PythonExe"

# --- Ensure NSSM is available (downloads to .\tools\nssm\nssm.exe if missing) ---
$NssmDir = Join-Path $ProjectRoot "tools\nssm"
$NssmExe = Join-Path $NssmDir "nssm.exe"
if (-not (Test-Path $NssmExe)) {
    Write-Host "NSSM not found. Downloading..."
    New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
    $zip = Join-Path $env:TEMP "nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $env:TEMP -Force
    $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    Copy-Item (Join-Path $env:TEMP "nssm-2.24\$arch\nssm.exe") $NssmExe -Force
    Remove-Item $zip -Force
}
Write-Host "NSSM:         $NssmExe"

# --- Remove any previous install ---
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing service '$ServiceName'..."
    & $NssmExe stop   $ServiceName 2>$null | Out-Null
    & $NssmExe remove $ServiceName confirm | Out-Null
}

# --- Install ---
$LogDir = Join-Path $ProjectRoot "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

& $NssmExe install $ServiceName $PythonExe "-m aegis --config `"$ConfigPath`"" | Out-Null
& $NssmExe set $ServiceName AppDirectory       $ProjectRoot                           | Out-Null
& $NssmExe set $ServiceName DisplayName        $DisplayName                           | Out-Null
& $NssmExe set $ServiceName Description        "Adaptive Endpoint Guardian Intelligence System" | Out-Null
& $NssmExe set $ServiceName Start              SERVICE_AUTO_START                     | Out-Null
& $NssmExe set $ServiceName ObjectName         LocalSystem                            | Out-Null
& $NssmExe set $ServiceName AppStdout          (Join-Path $LogDir "service.out.log")  | Out-Null
& $NssmExe set $ServiceName AppStderr          (Join-Path $LogDir "service.err.log")  | Out-Null
& $NssmExe set $ServiceName AppRotateFiles     1                                      | Out-Null
& $NssmExe set $ServiceName AppRotateBytes     10485760                               | Out-Null
& $NssmExe set $ServiceName AppExit            Default Restart                        | Out-Null
& $NssmExe set $ServiceName AppRestartDelay    5000                                   | Out-Null

Write-Host ""
Write-Host "Service '$ServiceName' installed. Starting..."
& $NssmExe start $ServiceName
Start-Sleep -Seconds 2
Get-Service $ServiceName

Write-Host ""
Write-Host "Done. Useful commands:"
Write-Host "  Get-Service $ServiceName"
Write-Host "  $NssmExe edit $ServiceName        # open NSSM GUI"
Write-Host "  Restart-Service $ServiceName"
Write-Host "  Stop-Service $ServiceName"
Write-Host "  .\scripts\uninstall-service.ps1   # remove"
Write-Host ""
Write-Host "NOTE: Toast notifications shown by a SYSTEM service appear in the"
Write-Host "Action Center but not as transient pop-ups (Windows isolates session 0)."
Write-Host "For interactive toasts, run AEGIS via Task Scheduler at user logon"
Write-Host "instead of as a service. See docs\INSTALL_WINDOWS.md."
