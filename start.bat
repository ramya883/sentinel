@echo off
title Sentinel Launcher
echo ========================================================
echo    Starting Sentinel AI Privacy & Security Dashboard
echo ========================================================

echo [1/2] Starting Sentinel API Server on port 5000...
start "Sentinel API Server (Port 5000)" cmd /k "cd /d %~dp0artifacts\api-server && node --enable-source-maps ./dist/index.mjs"

echo [2/2] Starting Sentinel Web Dashboard on port 5173...
start "Sentinel Web Dashboard (Port 5173)" cmd /k "cd /d %~dp0artifacts\privacy-security-dashboard && set PORT=5173 && set BASE_PATH=/ && npx vite --config vite.config.ts --host 0.0.0.0 --port 5173"

echo.
echo Waiting 4 seconds for services to initialize...
timeout /t 4 /nobreak >nul

echo Opening Sentinel Dashboard in default browser...
start http://localhost:5173/

echo.
echo Sentinel is running!
echo Both services are running in their respective command windows.
echo Web Dashboard: http://localhost:5173/
echo API Server:    http://localhost:5000/api
echo ========================================================
