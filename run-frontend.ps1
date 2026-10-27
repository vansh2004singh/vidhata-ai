$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot\frontend"
Write-Host "Open http://127.0.0.1:8000" -ForegroundColor Cyan
py -3 -m http.server 8000 --bind 127.0.0.1
