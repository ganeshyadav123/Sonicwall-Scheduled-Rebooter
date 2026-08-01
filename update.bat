@echo off
title Upgrade Scheduler Dependencies
echo ============================================
echo   Upgrading Dependencies for Scheduler
echo ============================================
echo.

cd /d "%~dp0"

if not exist "backend\venv" (
    echo [ERROR] Virtual environment not found. Run start.bat first to create it.
    pause
    exit /b 1
)

echo [1/2] Activating virtual environment...
call backend\venv\Scripts\activate.bat

echo [2/2] Upgrading packages to latest secure versions...
echo Upgrading pip...
python -m pip install --upgrade pip --quiet

echo Upgrading Flask, Flask-CORS, and Paramiko...
pip install --upgrade flask flask-cors paramiko

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Upgrade failed. Please check internet connection or console output.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Upgrade Complete!
echo   All packages have been updated to latest versions.
echo ============================================
echo.
pause
