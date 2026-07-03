@echo off
REM Compile the server (with the SQLite driver on the classpath).
cd /d "%~dp0"
if not exist out mkdir out
javac -cp "lib/*" -d out src\dev\license\*.java
if errorlevel 1 ( echo BUILD FAILED & pause & exit /b 1 )
echo Build OK.  Run with run-server.cmd
pause
