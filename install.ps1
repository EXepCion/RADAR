<#
.SYNOPSIS
    Installs RADAR for the current user (no admin rights needed).

.DESCRIPTION
    - Copies the app into %LOCALAPPDATA%\Programs\RADAR and creates a Python venv there
    - Installs the package and its dependencies (msal + WAM broker, pystray, pillow, requests)
    - Registers it to start at logon (HKCU\...\Run) and starts it
    Data (config, alerts, logs, plugins) lives in %LOCALAPPDATA%\RADAR and is kept on upgrade.

.PARAMETER NoStart
    Install but do not start the app now.
#>
[CmdletBinding()]
param([switch]$NoStart)

$ErrorActionPreference = 'Stop'
$AppName    = 'RADAR'
$Source     = $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$Venv       = Join-Path $InstallDir 'venv'
$DataDir    = Join-Path $env:LOCALAPPDATA $AppName

function Find-Python {
    $probe = 'import sys, tkinter; assert sys.version_info >= (3, 10); print(sys.executable)'
    $candidates = @(
        @{ Exe = 'py';     Args = @('-3', '-c', $probe) },
        @{ Exe = 'python'; Args = @('-c', $probe) }
    )
    foreach ($c in $candidates) {
        try {
            $exe = & $c.Exe @($c.Args) 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe) { return ($exe | Select-Object -Last 1).Trim() }
        } catch { }
    }
    throw 'Python 3.10+ with tkinter was not found. Install it (e.g. "winget install Python.Python.3.13") and retry.'
}

Write-Host "Installing $AppName to $InstallDir"

# 1. Stop a running instance so files can be replaced
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='$AppName.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match [regex]::Escape($InstallDir) -or $_.ExecutablePath -like "$InstallDir*" } |
    ForEach-Object {
        Write-Host "  stopping running instance (pid $($_.ProcessId))"
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Milliseconds 500

# 2. Python + venv
$python = Find-Python
Write-Host "  using Python: $python"
New-Item -ItemType Directory -Force $InstallDir | Out-Null
if (-not (Test-Path (Join-Path $Venv 'Scripts\python.exe'))) {
    & $python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw 'venv creation failed' }
}
$vpy = Join-Path $Venv 'Scripts\python.exe'

# 3. Package
Write-Host '  installing package and dependencies (this can take a minute)...'
& $vpy -m pip install --quiet --disable-pip-version-check --upgrade pip | Out-Null
& $vpy -m pip install --quiet --disable-pip-version-check --upgrade --force-reinstall --no-deps $Source
if ($LASTEXITCODE -ne 0) { throw 'pip install of the app failed' }
& $vpy -m pip install --quiet --disable-pip-version-check $Source
if ($LASTEXITCODE -ne 0) { throw 'pip install of dependencies failed' }

foreach ($f in 'README.md', 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'uninstall.ps1') {
    if (Test-Path (Join-Path $Source $f)) { Copy-Item -Force (Join-Path $Source $f) $InstallDir }
}
New-Item -ItemType Directory -Force (Join-Path $DataDir 'plugins') | Out-Null
$template = Join-Path $Source 'templates\example_plugin.py'
if (Test-Path $template) {
    # leading underscore = not loaded; rename to activate
    Copy-Item -Force $template (Join-Path $DataDir 'plugins\_example_plugin.py.txt')
}

# 4. Start at logon
$launcher = Join-Path $Venv "Scripts\$AppName.exe"
if (-not (Test-Path $launcher)) { throw "launcher $launcher missing" }
New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $AppName -Value "`"$launcher`""
Write-Host '  registered to start at logon (HKCU Run key)'

# 5. Start menu shortcut (re-launching shows the reminders of the running instance)
$lnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'RADAR.lnk'
$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($lnk)
$sc.TargetPath = $launcher
$sc.WorkingDirectory = $InstallDir
$sc.Description = 'RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID'
$sc.Save()

if (-not $NoStart) {
    Start-Process -FilePath $launcher -WorkingDirectory $InstallDir
    Write-Host '  started - look for the shield icon in the notification area'
}
Write-Host "Done. Data, config and logs: $DataDir"
