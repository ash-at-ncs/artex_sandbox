@echo off
setlocal
title ARTEX Sandbox Launcher

echo ================================================================
echo   ARTEX ^| Autonomous Attack ^& Agentic Defense Sandbox
echo   Wire Diagram Simulation v2.4.0
echo ================================================================

cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% equ 0 (
    python start.py
    goto :eof
)

where py >nul 2>nul
if %errorlevel% equ 0 (
    py start.py
    goto :eof
)

echo [!] Python was not found in your PATH.
echo [!] Attempting direct browser launch against active port 8080...
start http://localhost:8080/wire.html
pause
