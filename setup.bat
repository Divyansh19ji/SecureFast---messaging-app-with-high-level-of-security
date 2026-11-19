@echo off
setlocal
echo ============================================================
echo   SecureFast v2.0 - First-Time Setup (Python + C11 Engine)
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python 3.11+ was not found on PATH.
    echo Download Python from https://www.python.org/downloads/ and check "Add Python to PATH".
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Creating isolated Python virtual environment (.venv)...
    python -m venv .venv
    if errorlevel 1 exit /b 1
)

echo [2/4] Installing SecureFast Python dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

echo [3/4] Installing SecureFast CLI package...
".venv\Scripts\python.exe" -m pip install -e . --no-build-isolation --no-deps
if errorlevel 1 exit /b 1

echo [4/4] Compiling C11 Native Anti-OCR & Crypto Engine...
".venv\Scripts\python.exe" build_native.py --bench
if errorlevel 1 (
    echo [WARN] Could not recompile native engine; checking prebuilt DLL...
    if not exist "securefast\native_bin\securefast_core.dll" (
        echo [ERROR] Native DLL missing!
        pause
        exit /b 1
    )
)

echo.
echo ============================================================
echo   Setup Complete!
echo   - Double-click start.bat        (Host Relay + Your App)
echo   - Double-click start-friend.bat (Join a Friend's Relay)
echo   - Double-click start-demo.bat   (Alice + Bob 2-User Demo)
echo ============================================================
pause
