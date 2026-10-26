@echo off
title Internet Police - Restore Default DNS
echo =========================================================================
echo    Restoring Automatic DHCP DNS on Wi-Fi...
echo =========================================================================
netsh interface ip set dns name="Wi-Fi" dhcp
ipconfig /flushdns
echo.
echo [SUCCESS] Default Wi-Fi DNS settings restored.
echo.
pause
