<#
.SYNOPSIS
    Builds RADAR.exe (folder build), a zip of it and - when Inno Setup is installed - the installer, with checksums.

.DESCRIPTION
    Needs Python 3.10+ with the project's dependencies and PyInstaller:
        py -m venv .venv; .\.venv\Scripts\pip install -e .[dev] pyinstaller
    Output in .\dist:  RADAR\ (the program folder), RADAR-<version>-portable.zip, RADAR-<version>-setup.exe,
    SHA256SUMS.txt
    The installer step needs Inno Setup 6 (https://jrsoftware.org/isinfo.php); without it only the zip is built.

.PARAMETER Python
    The Python to build with (default: .\.venv\Scripts\python.exe, else "python").
#>
[CmdletBinding()]
param([string]$Python)

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root
if (-not $Python) {
    $Python = Join-Path $Root '.venv\Scripts\python.exe'
    if (-not (Test-Path $Python)) { $Python = 'python' }
}

$version = (& $Python packaging\prepare.py | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or -not $version) { throw 'packaging/prepare.py failed' }
Write-Host "Building RADAR $version"

Remove-Item -Recurse -Force dist\RADAR, build\radar -ErrorAction SilentlyContinue
& $Python -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\radar.spec
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed' }
if (-not (Test-Path dist\RADAR\RADAR.exe)) { throw 'dist\RADAR\RADAR.exe was not built' }

$zip = "dist\RADAR-$version-portable.zip"
Remove-Item -Force $zip -ErrorAction SilentlyContinue
Compress-Archive -Path dist\RADAR -DestinationPath $zip
$outputs = @($zip)

$iscc = @(
    (Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($iscc) {
    & $iscc /Q "/DAppVersion=$version" packaging\radar.iss
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }
    $outputs += "dist\RADAR-$version-setup.exe"
} else {
    Write-Warning 'Inno Setup 6 not found: no installer built (only the portable zip).'
}

$sums = $outputs | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_ -Algorithm SHA256).Hash.ToLower(), (Split-Path $_ -Leaf) }
Set-Content -Path dist\SHA256SUMS.txt -Value $sums -Encoding ascii
Write-Host 'Built:'
$outputs + 'dist\SHA256SUMS.txt' | ForEach-Object { Write-Host "  $_" }
