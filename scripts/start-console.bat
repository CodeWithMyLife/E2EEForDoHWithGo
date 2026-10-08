@echo off
rem fastime console starter: run in THIS window with -log debug
setlocal
cd /d "%~dp0"

set "EXE="
for %%f in ("%~dp0fastime*.exe") do set "EXE=%%~ff"
if not defined EXE (
  echo [FAIL] fastime exe not found in %~dp0
  pause
  exit /b 1
)

echo [OK] Starting: %EXE% -log debug
echo      Close this window or press Ctrl+C to stop.
echo.
"%EXE%" -log debug

echo.
echo [INFO] fastime exited with code %errorlevel%
echo        See fastime.log next to the exe for details.
pause
