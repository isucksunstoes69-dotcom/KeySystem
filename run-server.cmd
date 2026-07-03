@echo off
REM ============================================================
REM  Start the MC License server + dashboard (local, SQLite).
REM  Double-click this file, or run  .\run-server.cmd  in a terminal.
REM ============================================================
cd /d "%~dp0"

REM --- change this token before using in production ---
set LICENSE_ADMIN_TOKEN=mytoken

set LICENSE_PORT=8080
set LICENSE_PRIVATE_KEY_FILE=server\privatekey.txt
set LICENSE_PUBLIC_KEY_FILE=server\publickey.txt
set LICENSE_DB=data\license.db
set LICENSE_DOWNLOADS_DIR=data\downloads
set LICENSE_WEB_DIR=web
set LICENSE_CLIENT_SRC=src\dev\license

echo Starting license server...
echo Dashboard: http://localhost:%LICENSE_PORT%/
echo Admin token: %LICENSE_ADMIN_TOKEN%
echo (press Ctrl+C to stop)
echo.

java -cp "out;lib/*" dev.license.LicenseServer

echo.
echo Server stopped.
pause
