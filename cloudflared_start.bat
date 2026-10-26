@echo off
title Internet Police - Cloudflare Public Tunnel
echo =========================================================================
echo    Starting Cloudflare Secure Tunnel for Internet Police...
echo    This generates a free, secure public HTTPS URL for phones and laptops!
echo =========================================================================
"C:\Users\pc\.gemini\antigravity\scratch\cloudflared.exe" tunnel --url http://localhost:8080
pause
