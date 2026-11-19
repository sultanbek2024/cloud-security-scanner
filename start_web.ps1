Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " SATBAYEV UNIVERSITY - CloudSec Auditor (Web Dashboard)" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Веб-интерфейс іске қосылуда: http://localhost:8000" -ForegroundColor Green
Write-Host ""

if (Test-Path ".\venv\Scripts\python.exe") {
    & ".\venv\Scripts\python.exe" scanner.py --web
} else {
    python scanner.py --web
}
