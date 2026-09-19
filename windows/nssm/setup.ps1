$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host 'Проверяю Python 3...'
try {
    py -3 --version | Out-Null
} catch {
    Write-Host '[ОШИБКА] Python 3 не найден. Установите с python.org и отметьте "Add to PATH".'
    exit 1
}

py -3 -m pip install --upgrade pip
py -3 -m pip install -r (Join-Path $root 'requirements.txt')

& (Join-Path $root 'nssm\install_service.bat')