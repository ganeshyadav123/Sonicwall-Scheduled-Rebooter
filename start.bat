@echo off
title SonicWall Firewall Reboot Scheduler (Development Mode)
echo ============================================
echo   SonicWall Firewall Reboot Scheduler
echo ============================================
echo.

cd /d "%~dp0"

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Create virtual environment if it doesn't exist
if not exist "backend\venv" (
    echo [1/3] Creating virtual environment...
    python -m venv backend\venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo       Done.
) else (
    echo [1/3] Virtual environment ready.
)

:: Install dependencies
echo [2/3] Checking dependencies...
call backend\venv\Scripts\activate.bat
pip install -r backend\requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo       Done.

:: Start the backend server
echo [3/3] Starting backend server on http://localhost:5000
echo.
echo ============================================
echo   Server URL: http://localhost:5000
echo   Press Ctrl+C to stop the server
echo ============================================
echo.

:: Open browser after 2 second delay
start /b "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5000"

:: Run Flask App
"backend\venv\Scripts\python.exe" backend\app.py --dev

pause
