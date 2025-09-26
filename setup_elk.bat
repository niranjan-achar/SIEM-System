@echo off
REM Avighna2 SIEM - ELK Edition Setup Script
REM This script sets up the complete ELK environment

echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                🔍 Avighna2 SIEM - ELK Setup                          ║
echo ║           Setting up Elasticsearch-Powered SIEM System               ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

echo ✅ Python is available

REM Check if virtual environment exists
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)

REM Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo 📦 Upgrading pip...
python -m pip install --upgrade pip

REM Install ELK dependencies
echo 📦 Installing ELK SIEM dependencies...
pip install -r requirements.txt

REM Create environment file if it doesn't exist
if not exist ".env" (
    echo 📝 Creating environment configuration...
    copy .env.example .env >nul 2>&1
    echo ✅ Environment file created
)

REM Check if Elasticsearch is available
echo 🔍 Checking Elasticsearch connection...
python -c "import requests; print('✅ Elasticsearch is running') if requests.get('http://localhost:9200', timeout=2).status_code == 200 else print('❌ Elasticsearch not found')" 2>nul
if errorlevel 1 (
    echo.
    echo ⚠️  Elasticsearch is not running on localhost:9200
    echo.
    echo 🚀 Quick Elasticsearch Setup Options:
    echo.
    echo 1. Docker (Recommended):
    echo    docker run -d --name elasticsearch -p 9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    echo.
    echo 2. Download and Install:
    echo    Visit: https://www.elastic.co/downloads/elasticsearch
    echo    Extract and run: bin\elasticsearch.bat
    echo.
    echo 3. Continue without Elasticsearch (Fallback mode):
    echo    The SIEM will work with reduced functionality
    echo.
    set /p "choice=Do you want to continue anyway? (y/n): "
    if /i "%choice%" neq "y" (
        echo Setup cancelled. Please install Elasticsearch and try again.
        pause
        exit /b 1
    )
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                    🎉 ELK SIEM Setup Complete!                       ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.
echo 🚀 To start your ELK-powered SIEM:
echo.
echo    1. Make sure Elasticsearch is running on localhost:9200
echo    2. Run: python run_elk_siem.py
echo    3. Open browser: http://localhost:5000
echo    4. Login with password: Avighna123!
echo.
echo 🔍 ELK Features Available:
echo    • Advanced Elasticsearch Storage
echo    • Real-time Threat Analytics
echo    • Geographic Threat Mapping  
echo    • Complex Security Queries
echo    • WebSocket Live Updates
echo    • AI-Enhanced Threat Detection
echo.
echo 📚 Read README_ELK.md for detailed documentation
echo.

set /p "start=Start ELK SIEM now? (y/n): "
if /i "%start%"=="y" (
    echo 🚀 Starting ELK SIEM...
    python run_elk_siem.py
) else (
    echo 👋 Setup complete! Run 'python run_elk_siem.py' when ready.
)

pause