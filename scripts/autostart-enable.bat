@echo off
rem fastime autostart enabler: hidden start at user logon, with -log error
setlocal
cd /d "%~dp0"

set "EXE="
for %%f in ("%~dp0fastime*.exe") do set "EXE=%%~ff"
if not defined EXE (
  echo [FAIL] fastime exe not found in %~dp0
  pause
  exit /b 1
)

rem Write hidden launcher VBS: 0 = hidden window, False = do not wait
> "%~dp0run-hidden.vbs" echo CreateObject("Wscript.Shell").Run """%EXE%"" -log error", 0, False

schtasks /create /tn "Fastime" /tr "wscript.exe \"%~dp0run-hidden.vbs\"" /sc onlogon /f >nul 2>&1
if errorlevel 1 (
  echo [FAIL] Failed to create scheduled task. Try "Run as administrator".
  pause
  exit /b 1
)

echo [OK] Autostart enabled.
echo      Exe     : %EXE%
echo      Args    : -log error
echo      Mode    : hidden, no console window
echo      Task    : Fastime ^(runs at user logon^)
echo.
echo To disable later, run autostart-disable.bat
pause
