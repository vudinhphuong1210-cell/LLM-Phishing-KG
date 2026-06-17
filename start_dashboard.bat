@echo off
title Phishing Intelligence Dashboard
cd /d "E:\Shinny\LLM-Phishing-KG"
echo ========================================
echo   Khoi dong Dashboard tai localhost:8080
echo ========================================
echo.
echo Dang khoi dong server...
start "" /b cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:8080/"
python crawl_python\dashboard.py
pause
