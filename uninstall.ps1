<#
.SYNOPSIS
    Removes RADAR for the current user.
.PARAMETER RemoveData
    Also delete %LOCALAPPDATA%\RADAR (config, alerts, sign-in history, logs, token cache, plugins).
#>
[CmdletBinding()]
param([switch]$RemoveData)

$ErrorActionPreference = 'Stop'
$AppName    = 'RADAR'
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$DataDir    = Join-Path $env:LOCALAPPDATA $AppName

Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='$AppName.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match [regex]::Escape($InstallDir) -or $_.ExecutablePath -like "$InstallDir*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $AppName -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('Programs')) 'RADAR.lnk') -ErrorAction SilentlyContinue

# The running script may live inside the install folder; delete everything else first.
Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $PSCommandPath } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
if ($PSCommandPath -notlike "$InstallDir*") { Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue }

if ($RemoveData) {
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    Write-Host "Removed app and data."
} else {
    Write-Host "Removed app. Data kept in $DataDir (use -RemoveData to delete it)."
}
