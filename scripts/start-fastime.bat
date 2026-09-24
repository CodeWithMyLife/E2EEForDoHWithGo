@echo off
rem fastime 启动器：与 fastime-windows-*.exe 放在同一目录，双击运行
cd /d "%~dp0"
set BIN=
for %%f in (fastime-*.exe) do set BIN=%%f
if "%BIN%"=="" (
  echo [FAIL] fastime-*.exe not found in this folder.
  pause
  exit /b 1
)
echo [OK] Starting %BIN% ...
echo [OK] Log file: %~dp0fastime.log
echo ----------------------------------------
"%BIN%"
echo ----------------------------------------
echo [EXIT] Process exited, code %ERRORLEVEL%. See fastime.log for details.
pause
