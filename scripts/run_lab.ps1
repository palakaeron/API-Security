param(
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
$labRoot = Join-Path $PSScriptRoot '..\lab'
$services = @(
    @{ Name = 'auth'; Port = 8101 },
    @{ Name = 'users'; Port = 8102 },
    @{ Name = 'admin'; Port = 8103 },
    @{ Name = 'payments'; Port = 8104 },
    @{ Name = 'orders'; Port = 8105 },
    @{ Name = 'inventory'; Port = 8106 },
    @{ Name = 'graphql'; Port = 8107 }
)

if (-not $env:LAB_SECURE_JWT_SECRET) {
    throw 'Set LAB_SECURE_JWT_SECRET in .env or the current environment before starting the lab.'
}

$processes = @()
try {
    foreach ($service in $services) {
        $env:LAB_SERVICE = $service.Name
        $processes += Start-Process -FilePath python -WorkingDirectory $labRoot -WindowStyle Hidden -PassThru `
            -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', $service.Port)
        Write-Output ("Started {0} API at http://127.0.0.1:{1}" -f $service.Name, $service.Port)
    }
    Remove-Item Env:LAB_SERVICE -ErrorAction SilentlyContinue
    if ($KeepRunning) {
        Write-Output 'Press Ctrl+C to stop all lab processes.'
        while ($true) { Start-Sleep -Seconds 1 }
    }
}
finally {
    if ($KeepRunning) {
        $processes | Where-Object { -not $_.HasExited } | Stop-Process -Force
    }
}
