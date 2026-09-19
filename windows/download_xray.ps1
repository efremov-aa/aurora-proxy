# Aurora Proxy - скачивание Xray (Windows) в bin\
# Запуск:  powershell -ExecutionPolicy Bypass -File download_xray.ps1
$ErrorActionPreference = 'Stop'
$XrayVer = 'v26.9.9'
$Root   = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $Root 'bin'
$Zip    = Join-Path $env:TEMP 'Xray-windows-64.zip'

if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir | Out-Null }

$Url = "https://github.com/XTLS/Xray-core/releases/download/$XrayVer/Xray-windows-64.zip"
Write-Host "Скачиваю $Url ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $Zip

Write-Host 'Распаковываю...'
$Extract = Join-Path $env:TEMP 'xray_win_extract'
if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
Expand-Archive -Path $Zip -DestinationPath $Extract

foreach ($f in @('xray.exe','geoip.dat','geosite.dat','wintun.dll')) {
    $src = Join-Path $Extract $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $BinDir $f) -Force }
}

Remove-Item -Recurse -Force $Extract | Out-Null
Write-Host "[OK] Xray $XrayVer в $BinDir"