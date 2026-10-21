@echo off
chcp 65001 >nul
rem Edit the address below to your web app address, then double-click this file.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ETA-Signer.ps1" -AllowedOrigin "https://YOUR-APP-ADDRESS"
pause
