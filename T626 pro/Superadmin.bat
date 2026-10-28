@echo off
title True T626 Pro Superadmin Password Extractor
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0decode_t626pro.ps1" %*
pause
exit /b
