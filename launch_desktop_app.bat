@echo off
title Internet Police Launcher
wscript.exe "%~dp0start_silent.vbs"
timeout /t 1 >nul
if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app="http://localhost:8080"
) else (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --app="http://localhost:8080"
)
