@echo off
title Start AD Detection Lab
echo Starting the AD Detection lab (local + cloud)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Lab.ps1" %*
echo.
echo (You can close this window.)
pause
