@echo off
cd /d "%~dp0"
echo Starting backend server...
go run main.go
pause