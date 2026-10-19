@echo off
setlocal EnableExtensions
rem ===========================================================
rem  Trae2API-Hub - LAN mode (CN + INTL)
rem
rem  Listens on every network interface so phones, laptops and
rem  other PCs on the same network can use it.
rem
rem  An API key is REQUIRED in this mode.
rem
rem  ASCII-only on purpose: .bat files are parsed using the
rem  console code page, so non-ASCII text breaks the parser.
rem
rem  NOTE: this script puts no %VAR% inside an if( ... ) block,
rem  because a path containing ( or ) breaks the cmd.exe parser.
rem  All checks use if/errorlevel/goto instead.
rem ===========================================================

set "PORT=%~1"
rem 8791 is the Trae2API-Hub default (8788/8789/8790 belong to other proxies).
if "%PORT%"=="" set "PORT=8791"
set "KEY=%~2"
set "HERE=%~dp0"
set "SCRIPT=%HERE%trae_proxy.py"

if not exist "%SCRIPT%" goto no_script

set "PYEXE="

rem ---- 1) bundled runtime (ships with the zip) ----
if not exist "%HERE%python\python.exe" goto try_path
"%HERE%python\python.exe" --version >nul 2>nul
if errorlevel 1 goto try_path
set "PYEXE=%HERE%python\python.exe"
goto run

:try_path
rem ---- 2) python on PATH ----
python --version >nul 2>nul
if errorlevel 1 goto try_py
set "PYEXE=python"
goto run

:try_py
rem ---- 3) py launcher ----
py --version >nul 2>nul
if errorlevel 1 goto try_codex
set "PYEXE=py"
goto run

:try_codex
rem ---- 4) Codex bundled runtimes ----
call :find_codex
if defined PYEXE goto run

echo [ERROR] No usable Python found.
echo.
echo Options:
echo   1. Use the packaged zip, which already contains python\
echo   2. Install Python 3.9+ from https://www.python.org/downloads/
echo.
pause
exit /b 1

:no_script
echo [ERROR] trae_proxy.py not found next to this script.
echo         expected: %SCRIPT%
echo.
pause
exit /b 1

:find_codex
if not exist "%USERPROFILE%\.cache\codex-runtimes" goto :eof
for /d %%D in ("%USERPROFILE%\.cache\codex-runtimes\*") do call :probe "%%~D"
goto :eof

:probe
if defined PYEXE goto :eof
for /f "delims=" %%P in ('dir /b /s "%~1\python.exe" 2^>nul') do call :probe_one "%%~P"
goto :eof

:probe_one
if defined PYEXE goto :eof
"%~1" --version >nul 2>nul
if errorlevel 1 goto :eof
set "PYEXE=%~1"
goto :eof

:run
echo ===========================================================
echo   Trae2API-Hub - LAN MODE
echo.
echo   Port %PORT% - your API address, dashboard link and API
echo   key are printed below once the server is up.
echo.
echo   If other devices cannot connect, run allow-firewall.bat
echo   once as administrator.
echo.
echo   Keep this window open. Closing it stops the server.
echo ===========================================================
echo.

rem Pass --api-key only when the user supplied one; otherwise the gateway
rem mints a random key on first run and prints it below.
if "%KEY%"=="" goto run_nokey
"%PYEXE%" "%SCRIPT%" --port %PORT% --lan --api-key %KEY%
goto after_run

:run_nokey
"%PYEXE%" "%SCRIPT%" --port %PORT% --lan

:after_run
echo.
echo [server exited]
pause
