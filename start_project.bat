@echo off

cd /d "%~dp0"

echo ========================================
echo       CYBERGUARD SECURITY SYSTEM
echo ========================================
echo.

if not defined FLASK_SECRET_KEY (
    echo Error: FLASK_SECRET_KEY is not set.
    echo Follow the setup instructions in README.md before starting the app.
    pause
    exit /b 1
)

echo Starting CyberGuard...

start "" http://127.0.0.1:5000/login

python app.py

pause