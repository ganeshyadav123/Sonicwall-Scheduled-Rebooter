@echo off
title SonicWall Firewall Reboot Scheduler (Production WSGI)
echo ================================================================
echo   SonicWall Firewall Reboot Scheduler — Production Mode
echo ================================================================
echo.

cd /d "%~dp0"

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Create virtual environment if missing
if not exist "backend\venv" (
    echo [1/3] Creating virtual environment...
    python -m venv backend\venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Install dependencies if needed
echo [2/3] Checking dependencies...
call backend\venv\Scripts\activate.bat
pip install -r backend\requirements.txt --quiet

echo [3/3] Launching Production WSGI Server on http://localhost:5000 ...
echo.
echo ================================================================
echo   Server is running at: http://localhost:5000
echo   Press Ctrl+C in this window to stop the server.
echo ================================================================
echo.

:: Delay browser launch by 2 seconds so server finishes binding to port 5000
start /b "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5000"

:: Start Python production server
"backend\venv\Scripts\python.exe" backend\app.py

pause
