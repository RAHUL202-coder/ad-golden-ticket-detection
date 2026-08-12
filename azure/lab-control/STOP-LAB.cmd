@echo off
title Stop AD Detection Lab
echo Stopping the AD Detection lab (saves credits)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stop-Lab.ps1" %*
echo.
echo Safe to power off the DC VM now.
pause
