@echo off
rem fastime autostart disabler: remove the logon scheduled task and the VBS launcher
setlocal
cd /d "%~dp0"

schtasks /delete /tn "Fastime" /f >nul 2>&1
if errorlevel 1 (
  echo [SKIP] No autostart task named "Fastime" found.
) else (
  echo [OK] Autostart task "Fastime" removed.
)

if exist "%~dp0run-hidden.vbs" (
  del /f "%~dp0run-hidden.vbs" >nul 2>&1
  echo [OK] run-hidden.vbs deleted.
)
pause
