@echo off
chcp 65001 > nul
echo ========================================================
echo  SATBAYEV UNIVERSITY - CloudSec Auditor (Web Dashboard)
echo ========================================================
echo Веб-интерфейс іске қосылуда: http://localhost:8000
echo.
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe scanner.py --web
) else (
    python scanner.py --web
)
pause
