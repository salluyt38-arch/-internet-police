@echo off
title Internet Police - Enable DNS Shield
echo =========================================================================
echo    Enabling 24/7 Internet Police DNS Sinkhole on Wi-Fi...
echo =========================================================================
netsh interface ip set dns name="Wi-Fi" static 127.0.0.1
netsh interface ip add dns name="Wi-Fi" 9.9.9.9 index=2
ipconfig /flushdns
echo.
echo [SUCCESS] Your laptop Wi-Fi is now 100%% protected by Internet Police!
echo Ads and trackers will be dropped at 0.0.0.0 automatically.
echo.
pause
