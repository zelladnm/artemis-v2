@echo off
setlocal
set "PYTHON_MANAGER_AUTOMATIC_INSTALL=false"
set "PYLAUNCHER_ALLOW_INSTALL="
if defined ARTEMIS_PYTHON goto pinned
where python.exe >nul 2>nul
if not errorlevel 1 goto python
where py.exe >nul 2>nul
if not errorlevel 1 goto launcher
echo Python 3.11 or newer was not found. See FIRST_TEST.md for installation.
set "artemis_exit=2"
goto done
:pinned
"%ARTEMIS_PYTHON%" -X utf8 "%~dp0launch.py" %*
set "artemis_exit=%errorlevel%"
goto done
:python
python.exe -X utf8 "%~dp0launch.py" %*
set "artemis_exit=%errorlevel%"
goto done
:launcher
py.exe -3 -X utf8 "%~dp0launch.py" %*
set "artemis_exit=%errorlevel%"
:done
if "%ARTEMIS_NO_PAUSE%"=="1" goto exit
if not "%~1"=="" goto exit
if not "%artemis_exit%"=="0" pause
:exit
exit /b %artemis_exit%
