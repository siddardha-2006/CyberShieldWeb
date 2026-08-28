@echo off
title Cyber Shield - Frontend Web App
echo ========================================================
echo Starting Cyber Shield Frontend (Vite on Port 5173)...
echo ========================================================
cd /d "%~dp0frontend"
call npm.cmd run dev -- --host 127.0.0.1 --port 5173
pause

