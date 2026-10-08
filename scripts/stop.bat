@echo off
rem fastime stopper: kill all fastime-*.exe processes
setlocal
cd /d "%~dp0"

set "NAME="
for %%f in ("%~dp0fastime*.exe") do set "NAME=%%~nxf"
if not defined NAME (
  echo [FAIL] fastime exe not found in %~dp0, cannot determine process name
  pause
  exit /b 1
)

taskkill /F /IM "%NAME%" >nul 2>&1
if errorlevel 1 (
  echo [SKIP] %NAME% is not running.
) else (
  echo [OK] Stopped %NAME%
)
pause
