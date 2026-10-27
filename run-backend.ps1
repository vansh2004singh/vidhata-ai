$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot\backend"
if (!(Test-Path ".venv")) { py -3 -m venv .venv }
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
if (!(Test-Path ".env")) { Copy-Item ".env.example" ".env" }
Write-Host "Starting Vidhata API on http://127.0.0.1:8001" -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload
