@echo off
title Cyber Infrastructure Monitor
set "PYTHONPATH=%~dp0src"

echo Starting Cyber Monitor dashboard and collector...
echo Dashboard: http://127.0.0.1:8000
echo Collector: 0.0.0.0:5000 or the next free port shown in the dashboard
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    py -m cyber_monitor.app
    pause
    exit /b
)

where python >nul 2>nul
if %errorlevel%==0 (
    python -m cyber_monitor.app
    pause
    exit /b
)

echo Python was not found on PATH.
echo Install Python from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
echo Then run:
echo   pip install -r requirements.txt
echo   run_monitor.bat
pause
