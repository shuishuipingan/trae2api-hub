@echo off
setlocal
rem ===========================================================
rem  Allow Trae2API-Hub through Windows Firewall (LAN mode).
rem
rem  Run this ONCE as administrator if other devices cannot
rem  connect. It asks for elevation itself.
rem
rem  Usage:  allow-firewall.bat [port]     (default port: 8791)
rem ===========================================================

set "PORT=%~1"
if "%PORT%"=="" set "PORT=8791"

echo Requesting administrator rights to add a firewall rule
echo for TCP port %PORT% (Trae2API-Hub) ...
echo.
echo (A User Account Control prompt will appear - choose Yes)
echo.

powershell -NoProfile -Command ^
  "Start-Process -Verb RunAs -Wait -FilePath 'netsh' -ArgumentList 'advfirewall','firewall','add','rule',^
  'name=Trae2API-Hub (TCP %PORT%)','dir=in','action=allow','protocol=TCP','localport=%PORT%'"

echo.
echo Done. If the rule was added, other devices should now reach
echo http://<this-pc-ip>:%PORT%/
echo.
echo To remove it later:
echo   netsh advfirewall firewall delete rule name="Trae2API-Hub (TCP %PORT%)"
echo.
pause
