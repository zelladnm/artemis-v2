@echo off
setlocal
call "%~dp0start.cmd" --doctor %*
set "artemis_exit=%errorlevel%"
if "%ARTEMIS_NO_PAUSE%"=="1" goto exit
if not "%~1"=="" goto exit
pause
:exit
exit /b %artemis_exit%
