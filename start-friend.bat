@echo off
setlocal
set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
echo Starting your local SecureFast Friend Client...
echo Once the browser opens, enter your name, pick your Role, and paste your friend's Invite Code (sf://...)!
echo.
"%PY%" -m securefast client --role MEMBER %*
pause
