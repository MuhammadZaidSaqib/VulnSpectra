@echo off
REM VulnSpectra Quick Start Script for Windows

echo ========================================
echo VulnSpectra - Quick Start
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

echo [OK] Python found
echo.

REM Check if dependencies are installed
echo Checking dependencies...
python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
) else (
    echo [OK] Dependencies installed
)

echo.
echo ========================================
echo Starting VulnSpectra Dashboard
echo ========================================
echo.
echo Dashboard will open in your browser
echo API Server: http://localhost:8000
echo.
echo Press Ctrl+C to stop
echo.

python main.py --dashboard

pause

