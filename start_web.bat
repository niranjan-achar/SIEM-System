@echo off
echo ================================================================
echo        🛡️  Avighna2 SIEM Web Interface Launcher  🛡️
echo ================================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

:: Check if virtual environment exists
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

:: Install/upgrade requirements
echo 📋 Installing/updating requirements...
pip install -r requirements.txt --quiet --disable-pip-version-check

:: Check if .env file exists
if not exist ".env" (
    echo 📝 Creating .env file from template...
    copy .env.example .env >nul
    echo ⚠️  Please edit .env file to configure your settings
)

:: Start the web application
echo.
echo 🚀 Starting Avighna2 SIEM Web Interface...
echo.
python run_web.py

:: Deactivate virtual environment
deactivate

echo.
echo 👋 Avighna2 SIEM has stopped. Press any key to exit.
pause >nul