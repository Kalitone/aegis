<#
.SYNOPSIS
    Registers AEGIS in Task Scheduler to run hidden at user logon.

.DESCRIPTION
    Use this INSTEAD of (or alongside) the NSSM service when you want
    interactive Windows toast notifications. A service running as SYSTEM
    cannot pop transient toasts — toasts require the user's session.

    The task runs as the current user, hidden, and restarts on failure.
#>

param(
    [string]$TaskName   = "AEGIS-UserAgent",
    [string]$ConfigPath = "config\aegis.yaml"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$PythonExe = $null
foreach ($candidate in @(
    (Join-Path $ProjectRoot ".venv\Scripts\pythonw.exe"),
    (Join-Path $ProjectRoot "venv\Scripts\pythonw.exe")
)) {
    if (Test-Path $candidate) { $PythonExe = $candidate; break }
}
if (-not $PythonExe) {
    $PythonExe = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
}
if (-not $PythonExe) { $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $PythonExe) { throw "python(w).exe not found." }

$Action    = New-ScheduledTaskAction `
                -Execute $PythonExe `
                -Argument "-m aegis --config `"$ConfigPath`"" `
                -WorkingDirectory $ProjectRoot

$Trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings  = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit (New-TimeSpan -Hours 0)
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName `
    -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal `
    -Description "AEGIS endpoint guardian (per-user, interactive, toast-capable)" | Out-Null

Write-Host "Task '$TaskName' registered. Starting now..."
Start-ScheduledTask -TaskName $TaskName
Get-ScheduledTask  -TaskName $TaskName | Format-List TaskName, State

Write-Host ""
Write-Host "To remove:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
