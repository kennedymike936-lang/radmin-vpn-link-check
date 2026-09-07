@echo off
chcp 65001 >nul
title NetCheck - Network & NAT health check
where pwsh >nul 2>nul
if errorlevel 1 goto :usepowershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0NetCheck.ps1"
goto :end
:usepowershell
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0NetCheck.ps1"
:end
pause
