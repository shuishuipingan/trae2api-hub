param(
  [string]$TraeExe = "D:\work app\Trae CN\Trae CN.exe",
  [int]$Port = 9335
)
if (-not (Test-Path $TraeExe)) { throw "Trae CN not found: $TraeExe" }
Start-Process -FilePath $TraeExe -ArgumentList "--remote-debugging-port=$Port","--remote-allow-origins=*"
Write-Host "Trae CN launched with CDP on $Port"
