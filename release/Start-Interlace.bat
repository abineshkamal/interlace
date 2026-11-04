@echo off
REM Launch Interlace. The console window must remain open while in use.
title Interlace
cd /d "%~dp0"
echo Starting Interlace... your browser will open at http://127.0.0.1:8081
echo Close this window to stop Interlace.
interlace.exe -data "%~dp0interlace-data"
