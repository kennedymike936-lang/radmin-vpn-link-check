@echo off
chcp 65001 >nul
title Radmin (Blue Shield) Link Check
where pwsh >nul 2>nul
if errorlevel 1 goto :usepowershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0RadminCheck.ps1"
goto :end
:usepowershell
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0RadminCheck.ps1"
:end
pause
