@echo off
chcp 65001 >nul
rem Run this ONCE per environment to save the ETA Client ID/Secret (encrypted, only on this PC).
set /p ENVN=Environment (pre = test, prod = real): 
set /p RINN=Company tax number (leave empty to use for all companies): 
set /p INTR=Logging in as intermediary / accounting office? (y/n): 
if /i "%INTR%"=="y" (
 powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ETA-Signer.ps1" -SetCredentials %ENVN% -Rin "%RINN%" -Intermediary
) else (
 powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ETA-Signer.ps1" -SetCredentials %ENVN% -Rin "%RINN%"
)
pause
