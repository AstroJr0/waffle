@echo off
:: ─────────────────────────────────────────────────────────────
::  WAFFLE — setup script (Windows)
::  Run once after cloning the repo.
::  Right-click -> "Run as administrator" is recommended.
:: ─────────────────────────────────────────────────────────────
setlocal EnableDelayedExpansion
title WAFFLE Setup

echo.
echo   WAFFLE - Web Access Filter ^& Firewall
echo   Setup script for Windows
echo   ════════════════════════════════════════
echo.

:: ── 1. Python check ──────────────────────────────────────────
echo   [1/6] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Python not found.
    echo   Download from: https://www.python.org/downloads/
    echo   Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo   [OK] Found %%i

:: ── 2. cryptography package ──────────────────────────────────
echo.
echo   [2/6] Installing Python dependencies...
python -m pip install cryptography --quiet
if errorlevel 1 (
    echo   [WARN] Could not install cryptography. openssl fallback may be used.
) else (
    echo   [OK] cryptography installed
)

:: ── 3. Generate CA cert ──────────────────────────────────────
echo.
echo   [3/6] Generating local CA certificate...
python waffle.py --generate-ca
if errorlevel 1 (
    echo   [ERROR] CA generation failed. See output above.
    pause
    exit /b 1
)
echo   [OK] CA certificate created

:: ── 4. Install CA into Windows certificate store ─────────────
echo.
echo   [4/6] Installing CA into Windows certificate store...
echo   This allows Chrome and Edge to trust the WAFFLE block page.
echo.

:: certutil is built into Windows — no install needed
set CA_PATH=%USERPROFILE%\.config\waffle\ca.crt
certutil -addstore -user "Root" "%CA_PATH%" >nul 2>&1
if errorlevel 1 (
    echo   [WARN] Could not auto-install CA. Trying elevated certutil...
    certutil -addstore "Root" "%CA_PATH%"
    if errorlevel 1 (
        echo.
        echo   [MANUAL INSTALL NEEDED]
        echo   1. Open: certmgr.msc
        echo   2. Trusted Root Certification Authorities ^> Certificates
        echo   3. Right-click ^> All Tasks ^> Import
        echo   4. Select: %CA_PATH%
        echo   5. Click Next through the wizard, then Finish
        echo.
    )
) else (
    echo   [OK] CA installed into Windows certificate store
)

:: ── 5. Chrome-specific NSS install ───────────────────────────
echo.
echo   [5/6] Checking Chrome NSS store...
echo   Close Chrome completely before continuing.
pause

:: Chrome on Windows uses the Windows cert store directly —
:: no separate NSS step needed for modern Chrome on Windows.
echo   [OK] Chrome uses the Windows certificate store — no extra step needed.

:: ── 6. Set system proxy (optional) ───────────────────────────
echo.
echo   [6/6] Optional: configure Windows system proxy automatically?
echo   (This points all apps to WAFFLE at 127.0.0.1:8080)
set /p SETPROXY="   Set system proxy? [Y/n]: "
if /i "%SETPROXY%"=="" set SETPROXY=Y
if /i "%SETPROXY%"=="Y" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
        /v ProxyEnable /t REG_DWORD /d 1 /f >nul
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
        /v ProxyServer /t REG_SZ /d "127.0.0.1:8080" /f >nul
    echo   [OK] System proxy set to 127.0.0.1:8080
    echo   [!]  Run 'waffle --deactivate' to clear it when done.
) else (
    echo   [SKIP] Set your browser proxy manually to 127.0.0.1:8080
)

:: ── Done ─────────────────────────────────────────────────────
echo.
echo   ════════════════════════════════════════
echo   Setup complete!
echo   ════════════════════════════════════════
echo.
echo   Start WAFFLE:       python waffle.py --activate
echo   Add a site:         python waffle.py -a https://example.com
echo   Check status:       python waffle.py --status
echo.
echo   If you downloaded the .exe binary, replace "python waffle.py"
echo   with just "waffle" in the commands above.
echo.
pause