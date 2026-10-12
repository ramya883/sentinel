Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   Starting Sentinel AI Privacy & Security Dashboard" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n[1/2] Launching Sentinel API Server on port 5000..." -ForegroundColor Yellow
$apiProcess = Start-Process -FilePath "node" `
  -ArgumentList "--enable-source-maps", "./dist/index.mjs" `
  -WorkingDirectory "$scriptDir\artifacts\api-server" `
  -WindowStyle Hidden `
  -PassThru

Write-Host "[2/2] Launching Sentinel Web Dashboard on port 5173..." -ForegroundColor Yellow
$viteProcess = Start-Process -FilePath "cmd.exe" `
  -ArgumentList "/c set PORT=5173 && set BASE_PATH=/ && npx vite --config vite.config.ts --host 0.0.0.0 --port 5173" `
  -WorkingDirectory "$scriptDir\artifacts\privacy-security-dashboard" `
  -WindowStyle Hidden `
  -PassThru

Start-Sleep -Seconds 3

Write-Host "`nSentinel is running!" -ForegroundColor Green
Write-Host "  Web Dashboard: http://localhost:5173/" -ForegroundColor Green
Write-Host "  API Server:    http://localhost:5000/api" -ForegroundColor Green
Write-Host "========================================================`n" -ForegroundColor Cyan
