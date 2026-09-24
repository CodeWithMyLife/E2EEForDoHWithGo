@echo off
rem fastime 停止器：结束所有 fastime-*.exe 进程
cd /d "%~dp0"
set FOUND=0
for %%f in (fastime-*.exe) do (
  set FOUND=1
  taskkill /F /IM "%%f" >nul 2>&1
  if errorlevel 1 (echo [SKIP] %%f not running) else (echo [OK] Stopped %%f)
)
if %FOUND%==0 echo [SKIP] No fastime-*.exe found in this folder.
pause
