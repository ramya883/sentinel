param(
    [string]$ApiUrl = "http://localhost:5000/api"
)

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Write-Host "Connecting to Sentinel API at $ApiUrl..." -ForegroundColor Yellow

$email = "admin@sentinel.local"
$username = "admin"
$password = "password123"

$loginBody = @{ email = $email; password = $password } | ConvertTo-Json
try {
    Invoke-RestMethod -Uri "$ApiUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -WebSession $session | Out-Null
    Write-Host "Successfully authenticated with Sentinel Dashboard!" -ForegroundColor Green
} catch {
    Write-Host "Initial login failed. Registering admin account..." -ForegroundColor Yellow
    $regBody = @{ username = $username; email = $email; password = $password } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri "$ApiUrl/auth/register" -Method Post -Body $regBody -ContentType "application/json" -WebSession $session | Out-Null
        Write-Host "Admin account registered & authenticated!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to register: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n[LIVE STREAM ACTIVE] Sampling Windows network adapter stats every 2s..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop.`n"

$prev = Get-NetAdapterStatistics | Measure-Object -Property ReceivedBytes, SentBytes -Sum

while ($true) {
    Start-Sleep -Seconds 2
    $curr = Get-NetAdapterStatistics | Measure-Object -Property ReceivedBytes, SentBytes -Sum
    
    $rxPrev = ($prev | Where-Object {$_.Property -eq "ReceivedBytes"}).Sum
    $txPrev = ($prev | Where-Object {$_.Property -eq "SentBytes"}).Sum
    $rxCurr = ($curr | Where-Object {$_.Property -eq "ReceivedBytes"}).Sum
    $txCurr = ($curr | Where-Object {$_.Property -eq "SentBytes"}).Sum

    $rx = [math]::Max(0, $rxCurr - $rxPrev)
    $tx = [math]::Max(0, $txCurr - $txPrev)
    
    $payload = @{
        duration = 2.0
        srcBytes = $tx
        dstBytes = $rx
        failedLogins = 0
        packetCount = [math]::AsInt32(($tx + $rx) / 500)
        connectionRate = 4.5
    } | ConvertTo-Json

    try {
        $res = Invoke-RestMethod -Uri "$ApiUrl/intrusion/analyze" -Method Post -Body $payload -ContentType "application/json" -WebSession $session
        $status = "[$($res.classification.ToUpper())]"
        $score = [math]::AsInt32($res.anomalyScore * 100)
        Write-Host "$status Score: $score% | Risk: $($res.riskLevel) | TX: $([math]::Round($tx/1024, 1)) KB  RX: $([math]::Round($rx/1024, 1)) KB" -ForegroundColor Green
    } catch {
        Write-Host "Error sending metric: $_" -ForegroundColor Red
    }

    $prev = $curr
}
