@echo off
title True T625 Pro Superadmin Password Decoder and Enabler
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0decode_t625pro.ps1" %*
pause
exit /b
