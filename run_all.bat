@echo off
title Cyber Shield - Master Launcher
echo ========================================================
echo Launching Cyber Shield Full-Stack Platform...
echo ========================================================

start "Cyber Shield Backend" cmd /k "%~dp0run_backend.bat"
timeout /t 2 /nobreak >nul
start "Cyber Shield Frontend" cmd /k "%~dp0run_frontend.bat"

echo.
echo Both servers are launching!
echo  - Frontend: http://127.0.0.1:5173/
echo  - Backend:  http://127.0.0.1:8000/
echo.
timeout /t 3
start http://127.0.0.1:5173/

