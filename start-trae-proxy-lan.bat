@echo off
rem Compatibility shim: the launcher was renamed to start-trae2api-hub-lan.bat.
rem Keeps old shortcuts / docs working; forwards every argument.
call "%~dp0start-trae2api-hub-lan.bat" %*
exit /b %ERRORLEVEL%
